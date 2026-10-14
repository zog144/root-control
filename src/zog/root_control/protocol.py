import json
import struct
import time

MAX_MESSAGE = 1024 * 1024

def encode(message):
    payload = json.dumps(message, separators=(",", ":")).encode()
    return struct.pack("!I", len(payload)) + payload

def recv_exact(sock, size, *, deadline=None):
    chunks = []
    while size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("root-control message deadline exceeded")
            sock.settimeout(remaining)
        chunk = sock.recv(size)
        if not chunk:
            raise ConnectionError("peer closed connection")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)

def decode(sock, *, deadline=None):
    length = struct.unpack("!I", recv_exact(sock, 4, deadline=deadline))[0]
    if length > MAX_MESSAGE:
        raise ValueError("message too large")
    return json.loads(recv_exact(sock, length, deadline=deadline).decode())
