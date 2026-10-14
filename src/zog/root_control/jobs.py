"""Bounded systemd jobs on one connection owned by the serial root daemon.

The connection retains AddRef units until explicit release. A private event-loop
thread drains manager signals even while the serial root daemon waits for clients.
"""
from __future__ import annotations

import asyncio
import threading
from concurrent.futures import TimeoutError as FutureTimeout

from dbus_next import BusType, Message, MessageType
from dbus_next.aio import MessageBus

DESTINATION = "org.freedesktop.systemd1"
MANAGER_PATH = "/org/freedesktop/systemd1"
MANAGER_INTERFACE = "org.freedesktop.systemd1.Manager"


class JobError(RuntimeError):
    pass


class SystemdJobConnection:
    def __init__(self, *, timeout_seconds=30.0, bus_factory=None):
        self.timeout_seconds = timeout_seconds
        self.bus_factory = bus_factory or (lambda: MessageBus(bus_type=BusType.SYSTEM))
        self.loop = asyncio.new_event_loop()
        self.bus = None
        self.owner = None
        self.retained = set()
        self.thread = threading.Thread(target=self._serve_loop, daemon=True,
                                       name="zog-systemd-bus")
        self.thread.start()

    def _serve_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    async def _call(self, member, signature="", body=None, *, destination=DESTINATION,
                    path=MANAGER_PATH, interface=MANAGER_INTERFACE):
        reply = await self.bus.call(Message(
            destination=destination, path=path, interface=interface,
            member=member, signature=signature, body=body or [],
        ))
        if reply.message_type == MessageType.ERROR:
            raise JobError(f"{reply.error_name}: {reply.body}")
        return reply.body

    async def _connect(self):
        if self.bus is not None and self.bus.connected:
            return
        self.retained.clear()  # references belong to the lost connection
        self.bus = await self.bus_factory().connect()
        try:
            result = await self._call(
                "GetNameOwner", "s", [DESTINATION], destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus", interface="org.freedesktop.DBus",
            )
            self.owner = result[0]
            await self._call(
                "AddMatch", "s", [f"type='signal',sender='{DESTINATION}',"
                                     f"path='{MANAGER_PATH}',interface='{MANAGER_INTERFACE}',"
                                     "member='JobRemoved'"],
                destination="org.freedesktop.DBus", path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
            )
            await self._call("Subscribe")
        except BaseException:
            self.bus.disconnect()
            self.bus = None
            raise

    async def _execute(self, member, signature, body, *, job):
        await self._connect()
        if not job:
            return await self._call(member, signature, body)
        unit = body[0]
        completed = {}
        changed = asyncio.Event()

        def removed(message):
            if (message.message_type == MessageType.SIGNAL
                    and message.sender == self.owner
                    and message.path == MANAGER_PATH
                    and message.interface == MANAGER_INTERFACE
                    and message.member == "JobRemoved"
                    and len(message.body) == 4 and message.body[2] == unit):
                completed[message.body[1]] = message.body[3]
                changed.set()

        self.bus.add_message_handler(removed)
        try:
            # AddRef is part of the start transaction, so even /bin/true cannot
            # be collected between exec completion and subsequent observation.
            # Remember possible ownership BEFORE the call: its reply may be lost.
            if member == "StartTransientUnit":
                self.retained.add(unit)
            response = await self._call(member, signature, body)
            if len(response) != 1 or not isinstance(response[0], str):
                raise JobError(f"{member}: invalid job reply {response!r}")
            job_path = response[0]
            while job_path not in completed:
                changed.clear()
                if not self.bus.connected:
                    raise JobError(f"{unit}: bus disconnected; job outcome unknown")
                try:
                    await asyncio.wait_for(changed.wait(), 0.1)
                except TimeoutError:
                    pass
            result = completed[job_path]
            if result != "done":
                raise JobError(f"{unit}: {member} job {job_path} completed with {result}")
            return job_path
        finally:
            self.bus.remove_message_handler(removed)

    def call(self, member, signature, body, *, job=False):
        try:
            future = asyncio.run_coroutine_threadsafe(asyncio.wait_for(
                self._execute(member, signature, body, job=job), self.timeout_seconds
            ), self.loop)
            try:
                return future.result(timeout=self.timeout_seconds + 1.0)
            except FutureTimeout:
                future.cancel()
                raise
        except TimeoutError as exc:
            # A local deadline does not prove that the manager canceled the job.
            raise JobError(f"{member}: deadline exceeded; operation outcome unknown") from exc
        except JobError:
            raise
        except Exception as exc:
            raise JobError(f"{member}: {exc}; operation outcome unknown") from exc

    def release(self, unit):
        if self.bus is None or not self.bus.connected:
            self.retained.clear()
            return
        if unit in self.retained:
            try:
                self.call("UnrefUnit", "s", [unit])
            except JobError as exc:
                # A lost start reply may have represented a rejected start.
                if not any(name in str(exc) for name in ("NoSuchUnit", "NotReferenced")):
                    raise
            self.retained.discard(unit)

    def close(self):
        async def disconnect():
            if self.bus is not None:
                self.bus.disconnect()
                await asyncio.sleep(0)
        asyncio.run_coroutine_threadsafe(disconnect(), self.loop).result(timeout=2)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise JobError("D-Bus event loop did not stop")
        self.loop.close()
