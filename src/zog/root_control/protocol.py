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

def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate request field")
        result[key] = value
    return result


def decode(sock, *, deadline=None):
    length = struct.unpack("!I", recv_exact(sock, 4, deadline=deadline))[0]
    if not 0 < length <= MAX_MESSAGE:
        raise ValueError("invalid message length")
    result = json.loads(recv_exact(sock, length, deadline=deadline).decode("utf-8"),
                        object_pairs_hook=_unique_pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(
                            ValueError("invalid JSON constant")))
    if type(result) is not dict:
        raise ValueError("request must be an object")
    return result
