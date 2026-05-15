"""
TCP framing for the Approach B broker (cleartext ciphertext + metadata only).

Transport is plain TCP on loopback for the lab; file confidentiality does not
rely on TLS to the broker — only on AES-GCM ciphertext and the wrapped DEK.
"""

from __future__ import annotations

import enum
import struct
from typing import Final, Protocol

MAGIC: Final[bytes] = b"EVB2"
PROTOCOL_VERSION: Final[int] = 1
HEADER_STRUCT: Final[struct.Struct] = struct.Struct("!4sBBHI")
MAX_BODY_LEN: Final[int] = 64 * 1024 * 1024 + 256
SESSION_ID_LEN: Final[int] = 16


class Command(enum.IntEnum):
    PUT_CHUNK = 1
    GET_CHUNK = 2
    LIST_CHUNKS = 3
    PUT_MANIFEST = 4
    GET_MANIFEST = 5


class BrokerProtocolError(Exception):
    pass


class _Sock(Protocol):
    def recv(self, n: int, /) -> bytes: ...
    def sendall(self, b: bytes, /) -> None: ...


def recv_exact(sock: _Sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise BrokerProtocolError("connection closed while reading frame")
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: _Sock) -> tuple[int, bytes]:
    hdr = recv_exact(sock, HEADER_STRUCT.size)
    magic, ver, cmd, _res, ln = HEADER_STRUCT.unpack(hdr)
    if magic != MAGIC:
        raise BrokerProtocolError("bad magic")
    if ver != PROTOCOL_VERSION:
        raise BrokerProtocolError("bad protocol version")
    if ln > MAX_BODY_LEN:
        raise BrokerProtocolError("frame too large")
    body = recv_exact(sock, ln) if ln else b""
    return cmd, body


def write_frame(sock: _Sock, cmd: int, body: bytes) -> None:
    if len(body) > MAX_BODY_LEN:
        raise BrokerProtocolError("body too large")
    sock.sendall(
        HEADER_STRUCT.pack(MAGIC, PROTOCOL_VERSION, cmd & 0xFF, 0, len(body)) + body
    )


def pack_ok(payload: bytes = b"") -> bytes:
    return b"\x00" + payload


def pack_err(message: str) -> bytes:
    raw = message.encode("utf-8")
    if len(raw) > 8192:
        raw = raw[:8192]
    return b"\x01" + struct.pack("!I", len(raw)) + raw


def parse_status_body(body: bytes) -> tuple[bool, bytes]:
    if not body:
        raise BrokerProtocolError("empty status body")
    if body[0] == 0:
        return True, body[1:]
    if body[0] == 1:
        if len(body) < 5:
            raise BrokerProtocolError("truncated error body")
        (elen,) = struct.unpack("!I", body[1:5])
        msg = body[5 : 5 + elen]
        if len(msg) != elen:
            raise BrokerProtocolError("error length mismatch")
        return False, msg
    raise BrokerProtocolError("unknown status byte")


def pack_put_chunk(*, session_id: bytes, chunk_index: int, ciphertext: bytes) -> bytes:
    if len(session_id) != SESSION_ID_LEN:
        raise BrokerProtocolError("bad session_id length")
    if len(ciphertext) > MAX_BODY_LEN - SESSION_ID_LEN - 8 - 4:
        raise BrokerProtocolError("chunk too large")
    return (
        session_id
        + struct.pack("!Q", chunk_index)
        + struct.pack("!I", len(ciphertext))
        + ciphertext
    )


def unpack_put_chunk(body: bytes) -> tuple[bytes, int, bytes]:
    need = SESSION_ID_LEN + 8 + 4
    if len(body) < need:
        raise BrokerProtocolError("truncated PUT_CHUNK")
    sid = body[:SESSION_ID_LEN]
    idx = struct.unpack("!Q", body[SESSION_ID_LEN : SESSION_ID_LEN + 8])[0]
    (clen,) = struct.unpack("!I", body[SESSION_ID_LEN + 8 : SESSION_ID_LEN + 12])
    if clen > MAX_BODY_LEN:
        raise BrokerProtocolError("declared chunk length absurd")
    rest = body[SESSION_ID_LEN + 12 :]
    if len(rest) != clen:
        raise BrokerProtocolError("PUT_CHUNK length mismatch")
    return sid, idx, rest


def pack_session_chunk_query(*, session_id: bytes, chunk_index: int) -> bytes:
    if len(session_id) != SESSION_ID_LEN:
        raise BrokerProtocolError("bad session_id length")
    return session_id + struct.pack("!Q", chunk_index)


def unpack_session_chunk_query(body: bytes) -> tuple[bytes, int]:
    if len(body) != SESSION_ID_LEN + 8:
        raise BrokerProtocolError("bad session/chunk query body")
    return body[:SESSION_ID_LEN], struct.unpack("!Q", body[SESSION_ID_LEN:])[0]


def pack_list_chunks(session_id: bytes) -> bytes:
    if len(session_id) != SESSION_ID_LEN:
        raise BrokerProtocolError("bad session_id length")
    return session_id


def unpack_list_response(payload: bytes) -> list[int]:
    if len(payload) < 8:
        raise BrokerProtocolError("truncated LIST response")
    (n,) = struct.unpack("!Q", payload[:8])
    need = 8 + n * 8
    if len(payload) != need:
        raise BrokerProtocolError("LIST indices length mismatch")
    out: list[int] = []
    for i in range(int(n)):
        out.append(struct.unpack("!Q", payload[8 + i * 8 : 16 + i * 8])[0])
    return out


def pack_list_response(indices: list[int]) -> bytes:
    b = struct.pack("!Q", len(indices))
    for x in indices:
        b += struct.pack("!Q", x)
    return b


def pack_put_manifest(*, session_id: bytes, manifest_json: bytes, signature: bytes) -> bytes:
    if len(session_id) != SESSION_ID_LEN:
        raise BrokerProtocolError("bad session_id length")
    if len(manifest_json) > MAX_BODY_LEN // 2:
        raise BrokerProtocolError("manifest json too large")
    if len(signature) > 8192:
        raise BrokerProtocolError("signature too large")
    return (
        session_id
        + struct.pack("!Q", len(manifest_json))
        + manifest_json
        + struct.pack("!Q", len(signature))
        + signature
    )


def unpack_put_manifest(body: bytes) -> tuple[bytes, bytes, bytes]:
    if len(body) < SESSION_ID_LEN + 8:
        raise BrokerProtocolError("truncated PUT_MANIFEST")
    sid = body[:SESSION_ID_LEN]
    pos = SESSION_ID_LEN
    (jlen,) = struct.unpack("!Q", body[pos : pos + 8])
    pos += 8
    if jlen > MAX_BODY_LEN:
        raise BrokerProtocolError("manifest length absurd")
    if len(body) < pos + jlen + 8:
        raise BrokerProtocolError("truncated manifest json")
    mj = body[pos : pos + jlen]
    pos += jlen
    (slen,) = struct.unpack("!Q", body[pos : pos + 8])
    pos += 8
    if slen > 8192:
        raise BrokerProtocolError("signature length absurd")
    if len(body) != pos + slen:
        raise BrokerProtocolError("PUT_MANIFEST tail mismatch")
    sig = body[pos : pos + slen]
    return sid, mj, sig


def pack_get_manifest(session_id: bytes) -> bytes:
    if len(session_id) != SESSION_ID_LEN:
        raise BrokerProtocolError("bad session_id length")
    return session_id


def unpack_get_manifest_response(payload: bytes) -> tuple[bytes, bytes]:
    if len(payload) < 8:
        raise BrokerProtocolError("truncated GET_MANIFEST")
    (jlen,) = struct.unpack("!Q", payload[:8])
    pos = 8
    if len(payload) < pos + jlen + 8:
        raise BrokerProtocolError("truncated manifest json in response")
    mj = payload[pos : pos + jlen]
    pos += jlen
    (slen,) = struct.unpack("!Q", payload[pos : pos + 8])
    pos += 8
    if len(payload) != pos + slen:
        raise BrokerProtocolError("GET_MANIFEST tail mismatch")
    return mj, payload[pos : pos + slen]


def pack_get_manifest_response(manifest_json: bytes, signature: bytes) -> bytes:
    return (
        struct.pack("!Q", len(manifest_json))
        + manifest_json
        + struct.pack("!Q", len(signature))
        + signature
    )


def pack_get_chunk_response(ciphertext: bytes) -> bytes:
    return struct.pack("!Q", len(ciphertext)) + ciphertext


def unpack_get_chunk_response(payload: bytes) -> bytes:
    if len(payload) < 8:
        raise BrokerProtocolError("truncated GET_CHUNK payload")
    (ln,) = struct.unpack("!Q", payload[:8])
    data = payload[8:]
    if len(data) != ln:
        raise BrokerProtocolError("GET_CHUNK ciphertext length mismatch")
    return data
