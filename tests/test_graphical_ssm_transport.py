"""Real botocore HTTP transport; loopback only, no cloud credentials."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import threading

import boto3
import pytest
from botocore.exceptions import BotoCoreError, ClientError

from zog.root_control import graphical_owner_service as native


@pytest.mark.parametrize("failure", ["service-error", "lost-reply"])
def test_fixed_sender_never_retries_ambiguous_transport(monkeypatch, failure):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            if failure == "lost-reply":
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            body = b'{"__type":"InternalServerError","message":"test"}'
            self.send_response(500)
            self.send_header("Content-Type", "application/x-amz-json-1.1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = boto3.Session(aws_access_key_id="fixture-access",
                            aws_secret_access_key="fixture-secret",
                            region_name="us-east-1")

    class LocalSession:
        def client(self, name, *, config=None):
            # Environment retries must not override the explicit send fence.
            return session.client(name, config=config,
                                  endpoint_url="http://127.0.0.1:%d" % server.server_port)

    monkeypatch.setenv("AWS_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("AWS_RETRY_MODE", "standard")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    script = b"printf fixture"
    monkeypatch.setattr(native, "_read_root", lambda *a, **k: script)
    sender = native.FixedSSMSender({"instance_id": "i-0123456789abcdef0"})
    monkeypatch.setattr(sender, "_session", lambda: LocalSession())
    try:
        with pytest.raises((BotoCoreError, ClientError)):
            sender.send_fixed("a" * 32, {
                "script_sha256": "sha256:" + hashlib.sha256(script).hexdigest(),
                "timeout_seconds": 30})
        assert len(received) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
