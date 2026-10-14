import asyncio
from types import SimpleNamespace

import pytest
from dbus_next import MessageType

from zog.root_control.jobs import (
    SystemdJobConnection, JobError, MANAGER_INTERFACE, MANAGER_PATH,
)


class FakeBus:
    def __init__(self, *, result="done", early=True, silent=False, rejected=False,
                 disconnected=False, unrelated=False, lost_reply=False):
        self.result = result
        self.early = early
        self.silent = silent
        self.rejected = rejected
        self.disconnected = disconnected
        self.unrelated = unrelated
        self.lost_reply = lost_reply
        self.connected = False
        self.handlers = []
        self.calls = []

    async def connect(self):
        self.connected = True
        return self

    def add_message_handler(self, handler):
        self.handlers.append(handler)

    def remove_message_handler(self, handler):
        self.handlers.remove(handler)

    def disconnect(self):
        self.connected = False

    def emit(self, unit, *, path="/org/freedesktop/systemd1/job/42", sender=":1.0"):
        message = SimpleNamespace(
            message_type=MessageType.SIGNAL, sender=sender,
            interface=MANAGER_INTERFACE, path=MANAGER_PATH, member="JobRemoved",
            body=[42, path, unit, self.result],
        )
        for handler in self.handlers:
            handler(message)

    async def call(self, message):
        self.calls.append(message.member)
        body = []
        if message.member == "GetNameOwner":
            body = [":1.0"]
        if message.member in ("StartTransientUnit", "StopUnit"):
            assert self.calls.index("Subscribe") < len(self.calls) - 1
            assert self.handlers
            if self.rejected:
                return SimpleNamespace(message_type=MessageType.ERROR,
                    error_name="org.freedesktop.systemd1.UnitExists", body=["exists"])
            if self.unrelated:
                self.emit(message.body[0], path="/org/freedesktop/systemd1/job/999")
                self.emit("other.service")
                self.emit(message.body[0], sender=":9.9")
            if not self.silent:
                if self.early:
                    self.emit(message.body[0])
                else:
                    asyncio.get_running_loop().call_later(.001, self.emit, message.body[0])
            if self.disconnected:
                self.connected = False
            if self.lost_reply:
                await asyncio.sleep(1)
            body = ["/org/freedesktop/systemd1/job/42"]
        return SimpleNamespace(message_type=MessageType.METHOD_RETURN, body=body)


def start(connection):
    return connection.call("StartTransientUnit", "ssa(sv)a(sa(sv))",
                           ["test.service", "fail", [], []], job=True)


@pytest.mark.parametrize("early", [True, False])
def test_completion_before_or_after_method_reply(early):
    bus = FakeBus(early=early, unrelated=True)
    connection = SystemdJobConnection(bus_factory=lambda: bus, timeout_seconds=.1)
    try:
        assert start(connection).endswith("/42")
        assert "test.service" in connection.retained
        assert not bus.handlers
        connection.call("StopUnit", "ss", ["test.service", "replace"], job=True)
        connection.release("test.service")
        connection.release("test.service")
        assert bus.calls.count("Subscribe") == 1
        assert bus.calls.count("UnrefUnit") == 1
    finally:
        connection.close()


@pytest.mark.parametrize("result", ["failed", "timeout", "canceled", "dependency", "skipped"])
def test_unsuccessful_job_is_not_acceptance(result):
    connection = SystemdJobConnection(bus_factory=lambda: FakeBus(result=result))
    try:
        with pytest.raises(JobError, match=result):
            start(connection)
    finally:
        connection.close()


@pytest.mark.parametrize("options,match", [
    ({"silent": True, "unrelated": True}, "deadline exceeded"),
    ({"lost_reply": True}, "outcome unknown"),
    ({"silent": True, "disconnected": True}, "disconnected"),
    ({"rejected": True}, "UnitExists"),
])
def test_unknown_and_rejected_jobs_fail_without_replaying(options, match):
    bus = FakeBus(**options)
    connection = SystemdJobConnection(bus_factory=lambda: bus, timeout_seconds=.02)
    try:
        with pytest.raises(JobError, match=match):
            start(connection)
        assert bus.calls.count("StartTransientUnit") == 1
        assert not bus.handlers
    finally:
        connection.close()


def test_job_protocol_over_real_private_dbus():
    """Real wire/signature test with a simulated manager; no systemd claim."""
    import select
    import shutil
    import subprocess
    from dbus_next import Message
    from dbus_next.aio import MessageBus

    executable = shutil.which("dbus-daemon")
    if not executable:
        pytest.skip("dbus-daemon is not installed")
    daemon = subprocess.Popen([executable, "--session", "--nofork", "--print-address=1"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    connection = None
    server = None
    try:
        assert select.select([daemon.stdout], [], [], 3)[0], "private bus did not start"
        address = daemon.stdout.readline().strip()
        if not address:
            error = daemon.stderr.read()
            if "Operation not permitted" in error:
                pytest.skip("environment prohibits private D-Bus sockets")
            pytest.fail(f"private D-Bus failed: {error}")
        connection = SystemdJobConnection(
            bus_factory=lambda: MessageBus(bus_address=address), timeout_seconds=2)
        async def make_server():
            server = await MessageBus(bus_address=address).connect()
            await server.request_name("org.freedesktop.systemd1")
            return server
        server = asyncio.run_coroutine_threadsafe(make_server(), connection.loop).result(timeout=2)
        seen = []

        def handle(message):
            if message.message_type != MessageType.METHOD_CALL or message.interface != MANAGER_INTERFACE:
                return
            seen.append(message.member)
            if message.member in ("StartTransientUnit", "StopUnit"):
                path = "/org/freedesktop/systemd1/job/42"
                server.send(Message.new_signal(MANAGER_PATH, MANAGER_INTERFACE,
                    "JobRemoved", "uoss", [42, path, message.body[0], "done"]))
                return Message.new_method_return(message, "o", [path])
            return Message.new_method_return(message)

        connection.loop.call_soon_threadsafe(server.add_message_handler, handle)
        assert start(connection).endswith("/42")
        connection.call("StopUnit", "ss", ["test.service", "replace"], job=True)
        connection.release("test.service")
        assert seen == ["Subscribe", "StartTransientUnit", "StopUnit", "UnrefUnit"]
    finally:
        if server:
            connection.loop.call_soon_threadsafe(server.disconnect)
        if connection:
            connection.close()
        daemon.terminate()
        daemon.communicate(timeout=3)
