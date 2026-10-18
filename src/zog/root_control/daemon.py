import os
import re
import socket
import stat
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore
from pathlib import Path

from .protocol import decode, encode
from .systemd import BusctlSystemdBackend
from .build import BuildBackend
from .events import emit
from zog.box_control.errors import PersistenceError

DEFAULT_SOCKET = Path("/run/zog/root-control.sock")
_INGRESS_WORKERS = 4
_INGRESS_DEADLINE_SECONDS = 10.0
_OPERATION = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class RootControlDaemon:
    def __init__(self, socket_path, *, systemd_backend=None, journal_barrier=None,
                 socket_group_gid=None, controller_uid=None):
        self.socket_path = Path(socket_path)
        if (not self.socket_path.is_absolute() or self.socket_path == Path("/")
                or ".." in self.socket_path.parts):
            raise ValueError("privileged socket path must be an absolute, fixed path")
        if (socket_group_gid is not None and
                (type(socket_group_gid) is not int or socket_group_gid < 1 or socket_group_gid >= 2**31)):
            raise ValueError("root-control socket group must be an explicit positive numeric GID")
        if (controller_uid is not None and
                (type(controller_uid) is not int or controller_uid < 1000 or controller_uid >= 2**31)):
            raise ValueError("root-control controller UID must be an explicit unprivileged numeric UID")
        if socket_group_gid is not None and controller_uid is None:
            raise ValueError("socket group requires the exact authorized controller UID")
        self.socket_group_gid = socket_group_gid
        self.controller_uid = controller_uid
        self.systemd = systemd_backend or BusctlSystemdBackend()
        self.build = BuildBackend(self.systemd, journal_barrier=journal_barrier)

    def _prepare_socket_parent(self):
        # No group-/world-writable ancestor or redirected directory can
        # substitute a privileged listener. The installer owns this hierarchy.
        parent = self.socket_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        current = Path("/")
        for part in parent.parts[1:]:
            current /= part
            info = current.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022):
                raise PermissionError("untrusted privileged socket ancestry")
        try:
            info = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
            raise PermissionError("untrusted existing privileged socket")
        self.socket_path.unlink()

    def _protect_socket(self):
        # The exact controller *UID*, not membership in a shared group,
        # is authorized for the complete privileged mechanism interface.
        if self.controller_uid is not None or self.socket_group_gid is not None:
            os.chown(self.socket_path,
                     self.controller_uid if self.controller_uid is not None else -1,
                     self.socket_group_gid if self.socket_group_gid is not None else -1)
        os.chmod(self.socket_path, 0o660 if self.socket_group_gid is not None else 0o600)

    def _authorize_peer(self, conn):
        if not hasattr(socket, "SO_PEERCRED"):
            raise PermissionError("kernel peer credentials unavailable")
        data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        if len(data) != 12:
            raise PermissionError("invalid peer credentials")
        _pid, uid, _gid = struct.unpack("3i", data)
        expected = self.controller_uid if self.controller_uid is not None else 0
        if uid != expected:
            raise PermissionError("unauthorized controller identity")

    @staticmethod
    def _request_operation(request):
        if (type(request) is not dict or
                type(request.get("operation")) is not str or
                _OPERATION.fullmatch(request["operation"]) is None):
            raise ValueError("invalid root-control operation")
        return request["operation"]

    def _admit(self, conn, workers, slots, admission, accepted_at):
        try:
            self._authorize_peer(conn)  # Authenticate before reading any frame.
            request = decode(conn, deadline=accepted_at + _INGRESS_DEADLINE_SECONDS)
            self._request_operation(request)
            # After parsing, submit to the original serialized mutation or
            # separate bounded observation lane. Ownership passes to _dispatch.
            self._dispatch(conn, request, workers, slots)
        except Exception:
            with conn:
                self._respond(conn, {"ok": False, "error": "root-control request rejected"})
        finally:
            admission.release()

    def _enqueue(self, conn, ingress, workers, slots, admission):
        if not admission.acquire(blocking=False):
            with conn:
                self._respond(conn, {"ok": False, "error": "root-control admission busy"})
            return False
        try:
            ingress.submit(self._admit, conn, workers, slots,
                           admission, time.monotonic())
        except BaseException:
            admission.release()
            conn.close()
            raise
        return True

    def serve(self):
        self._prepare_socket_parent()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(self.socket_path))
            self._protect_socket()
            server.listen(16)
            # A finite pre-dispatch pool prevents one stalled header from
            # blocking every other controller request. No unbounded ingress
            # queue, and no parallel mutation/backend systemd job connection.
            with (ThreadPoolExecutor(max_workers=_INGRESS_WORKERS) as ingress,
                  ThreadPoolExecutor(max_workers=1) as mutations,
                  ThreadPoolExecutor(max_workers=2) as logs):
                workers = (mutations, logs)
                slots = (BoundedSemaphore(8), BoundedSemaphore(2))
                admission = BoundedSemaphore(_INGRESS_WORKERS)
                while True:
                    conn, _ = server.accept()
                    self._enqueue(conn, ingress, workers, slots, admission)

    @staticmethod
    def _respond(conn, response, *, operation=None, resource_id=None):
        try:
            conn.settimeout(5.0)
            conn.sendall(encode(response))
        except OSError:
            emit("root-control-response-undelivered", operation=operation, resource_id=resource_id)

    def _dispatch(self, conn, request, workers, slots):
        operation = self._request_operation(request)
        lane = 1 if operation in {'ping', 'application_logs', 'build_job_logs', 'application_processes', 'application_runtime_mounts', 'application_runtime_credentials', 'build_job_processes', 'workspace_verify', 'build_registration_status', 'issuer_observe', 'issuer_inspect_result'} else 0
        if not slots[lane].acquire(blocking=False):
            with conn:
                self._respond(conn, {"ok": False, "error": "root-control lane busy; retry later"})
            return
        try:
            workers[lane].submit(self._serve_request, conn, request, slots[lane], time.monotonic())
        except BaseException:
            slots[lane].release()
            conn.close()
            raise

    def _serve_request(self, conn, request, slot, queued_at=None):
        started = time.monotonic()
        registration = request.get('operation') == 'build_register'
        rid = request.get('resource_id')
        # Do not echo arbitrary client strings into diagnostics.
        rid = rid if isinstance(rid, str) and len(rid) == 32 and all(c in '0123456789abcdef' for c in rid) else None
        if registration:
            emit('build-registration-start', resource_id=rid,
                 queued_seconds=started-(queued_at if queued_at is not None else started))
        try:
            with conn:
                try:
                    response = self.handle(request)
                except Exception as exc:
                    # A privileged error may contain raw host paths or client
                    # values; do not return them to the socket peer.
                    code = getattr(exc, "code", None)
                    if type(code) is not str or not re.fullmatch(r"[a-z0-9-]{1,64}", code):
                        code = None
                    response = {"ok": False, "error": "root-control operation rejected",
                                "storage_failure": isinstance(exc, PersistenceError), "code": code}
                if registration:
                    emit('build-registration-finish', resource_id=rid, ok=response.get('ok') is True,
                         elapsed_seconds=time.monotonic()-started)
                self._respond(conn, response, operation='build_register' if registration else None, resource_id=rid)
        finally:
            slot.release()

    def handle(self, request):
        operation = request.get("operation")
        if operation in {"build_register", "build_prepare", "build_start", "build_observe", "build_cleanup", "build_cancel", "build_release", "build_forget"}:
            arguments = {k:v for k,v in request.items() if k != "operation"}
            return {"ok": True, "result": getattr(self.build, operation[6:])(**arguments)}
        if operation in {"application_processes", "build_job_processes"}:
            from .processes import inspect
            allowed = ({"project_root", "runtime_id", "program", "limit"} if operation == "application_processes"
                       else {"project_root", "job_id", "limit"})
            arguments = {k:v for k,v in request.items() if k != "operation"}
            if not set(arguments) <= allowed:
                raise ValueError("unsupported process inspection arguments")
            return {"ok": True, "result": inspect(**arguments)}
        if operation == "execution_identity_resolve":
            from .identities import resolve
            if set(request) != {"operation", "project_root", "application"}:
                raise ValueError("invalid execution identity resolution request")
            return {"ok": True, "result": resolve(request["project_root"], request["application"])}
        if operation == "application_runtime_credentials":
            from .credentials import inspect_runtime_credentials
            arguments = {k: v for k, v in request.items() if k != "operation"}
            if (not {"project_root", "runtime_id"} <= set(arguments)
                    or not set(arguments) <= {"project_root", "runtime_id", "limit"}):
                raise ValueError("unsupported runtime credential inspection arguments")
            return {"ok": True, "result": inspect_runtime_credentials(**arguments)}
        if operation == "issuer_inspect_result":
            if set(request) != {"operation", "project_root", "request_id"}:
                raise ValueError("invalid selected issuer inspection arguments")
            from .issuer_inspection_result import read_selected_inspection
            return {"ok": True, "result": read_selected_inspection(
                project_root=request["project_root"], request_id=request["request_id"],
            )}
        if operation == "issuer_observe":
            from .issuer_observation import observe_issuer_request
            if set(request) != {"operation", "project_root", "request_id"}:
                raise ValueError("invalid privileged issuer inspection arguments")
            return {"ok": True, "result": observe_issuer_request(
                project_root=request["project_root"], request_id=request["request_id"],
            )}
        if operation == "application_runtime_mounts":
            from .mounts import inspect_runtime_mounts
            arguments = {k:v for k,v in request.items() if k != "operation"}
            if set(arguments) != {"project_root", "runtime_id"}:
                raise ValueError("unsupported runtime mount inspection arguments")
            return {"ok": True, "result": inspect_runtime_mounts(**arguments)}
        if operation == 'build_registration_status':
            return {'ok': True, 'result': self.build.registration_status(
                project_root=request['project_root'], resource_id=request['resource_id'])}
        if operation == "build_job_logs":
            from .journal import read_build_logs
            return {"ok": True, "result": read_build_logs(**{k:v for k,v in request.items() if k != "operation"})}
        if operation == "application_logs":
            from .journal import read_logs
            return {"ok": True, "result": read_logs(**{k:v for k,v in request.items() if k != "operation"})}
        if operation == "ping":
            return {"ok": True}
        if operation in {"mount", "unmount"}:
            # Legacy unscoped root-equivalent mechanism, not used by the
            # current controller transport. Never accept arbitrary host paths.
            raise ValueError("raw mount RPC is disabled")
        if operation == "application_storage_sync":
            self.systemd.sync_application_storage(project_root=request['project_root'],
                application=request['application'], storage_id=request['storage_id'])
            return {"ok": True, "result": None}
        if operation == "application_storage_delete":
            self.systemd.delete_application_storage(project_root=request['project_root'],
                application=request['application'], storage_id=request['storage_id'])
            return {"ok": True, "result": None}
        if operation in {'workspace_prepare', 'workspace_verify'}:
            from .workspace import WorkspaceBackend
            backend = WorkspaceBackend(BusctlSystemdBackend() if operation == 'workspace_verify' else self.systemd)
            return {"ok": True, "result": getattr(backend, operation[10:])(**{k:v for k,v in request.items() if k != 'operation'})}
        if operation == "systemd_version":
            return {"ok": True, "result": self.systemd.version()}
        if operation == "systemd_start_slice":
            self.systemd.start_slice(
                project_root=request["project_root"],
                slice_name=request["slice_name"],
                description=request["description"],
            )
            return {"ok": True}
        if operation == "systemd_start_service":
            self.systemd.start_service(
                project_root=request["project_root"],
                generation=request["generation"],
                definition=request["definition"],
            )
            return {"ok": True}
        if operation == "systemd_observe":
            result = self.systemd.observe(
                project_root=request["project_root"], unit_name=request["unit_name"]
            )
            return {"ok": True, "result": result}
        if operation == "systemd_kill":
            self.systemd.kill(
                project_root=request["project_root"],
                unit_name=request["unit_name"],
                signal_number=int(request["signal_number"]),
            )
            return {"ok": True}
        if operation == "systemd_stop":
            self.systemd.stop(
                project_root=request["project_root"], unit_name=request["unit_name"]
            )
            return {"ok": True}
        if operation == "systemd_release":
            self.systemd.release(project_root=request["project_root"], unit_name=request["unit_name"])
            return {"ok": True}
        if operation == "systemd_release_runtime_root":
            self.systemd.release_runtime_root(
                project_root=request["project_root"],
                runtime_id=request["runtime_id"],
            )
            return {"ok": True}
        if operation == "systemd_reset_failed":
            self.systemd.reset_failed(
                project_root=request["project_root"], unit_name=request["unit_name"]
            )
            return {"ok": True}
        raise ValueError(f"unsupported operation: {operation!r}")


def main():
    # Environment override is for root-control deployment/testing only. The
    # box-control public API itself has no environment-variable configuration.
    socket_path = os.environ.get("ROOT_CONTROL_SOCKET", str(DEFAULT_SOCKET))
    barrier = None
    if os.environ.get('ROOT_CONTROL_JOURNAL_BARRIER') == '1':
        from .journal_barrier import JournalBarrier
        barrier = JournalBarrier()
        barrier.start()
    gid_setting = os.environ.get("ROOT_CONTROL_SOCKET_GID")
    if gid_setting is not None and (not gid_setting.isascii() or not gid_setting.isdecimal()):
        raise ValueError("ROOT_CONTROL_SOCKET_GID must be a numeric GID")
    socket_group_gid = int(gid_setting) if gid_setting is not None else None
    uid_setting = os.environ.get("ROOT_CONTROL_CONTROLLER_UID")
    if uid_setting is not None and (not uid_setting.isascii() or not uid_setting.isdecimal()):
        raise ValueError("ROOT_CONTROL_CONTROLLER_UID must be a numeric UID")
    controller_uid = int(uid_setting) if uid_setting is not None else None
    RootControlDaemon(socket_path, journal_barrier=barrier,
                      socket_group_gid=socket_group_gid,
                      controller_uid=controller_uid).serve()


if __name__ == "__main__":
    main()
