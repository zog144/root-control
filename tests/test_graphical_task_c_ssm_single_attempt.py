"""Regression: one SSM HTTP request per independently protected owner claim.

Real botocore protocol over loopback only: never use AWS, production creds,
systemd, canonical STATE, or any actual remote command.
"""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import threading

import boto3
import pytest
from botocore.exceptions import BotoCoreError, ClientError

from zog.root_control import graphical_owner_service as native


@pytest.mark.parametrize("failure", ["http-500", "lost-ack"])
def test_one_sdk_attempt_even_with_environment_retry_override(monkeypatch, failure):
    received = []

    class Endpoint(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            if failure == "lost-ack":
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            body = b'{"__type":"InternalServerError","message":"fixture"}'
            self.send_response(500)
            self.send_header("Content-Type", "application/x-amz-json-1.1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Endpoint)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = boto3.Session(aws_access_key_id="fixture-access",
                            aws_secret_access_key="fixture-secret",
                            region_name="us-east-1")

    class LoopbackSession:
        def client(self, name, *, config=None):
            assert name == "ssm"
            assert config.retries["total_max_attempts"] == 1
            return session.client(name, config=config,
                                  endpoint_url="http://127.0.0.1:%d" % server.server_port)

    monkeypatch.setenv("AWS_MAX_ATTEMPTS", "5")
    monkeypatch.setenv("AWS_RETRY_MODE", "adaptive")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    script = b"printf fixture"
    monkeypatch.setattr(native, "_read_root", lambda *a, **k: script)
    sender = native.FixedSSMSender({"instance_id": "i-0123456789abcdef0"})
    monkeypatch.setattr(sender, "_session", lambda: LoopbackSession())
    try:
        with pytest.raises((BotoCoreError, ClientError)):
            sender.send_fixed("a" * 32, {
                "script_sha256": "sha256:" + hashlib.sha256(script).hexdigest(),
                "timeout_seconds": 30,
            })
        assert len(received) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
