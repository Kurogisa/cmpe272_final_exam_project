"""
Binary framing and streaming semantics for Approach A (over TLS).

TLS supplies record-layer AEAD; this layer binds file size, byte placement,
and a final SHA-256 over plaintext bytes written (fail-closed on mismatch).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import BinaryIO, Protocol


# Hard caps reduce accidental OOM from a malicious peer framing huge lengths.
MAX_FRAME_BYTES = 32 * 1024 * 1024 + 256
MAX_CHUNK_PAYLOAD = 16 * 1024 * 1024
MAX_FILENAME_BYTES = 255
SESSION_ID_BYTES = 16


class MsgType(IntEnum):
    OPEN = 1
    OPEN_ACK = 2
    CHUNK = 3
    EOF = 4
    SERVER_ERROR = 5
    SERVER_OK = 6


class ProtocolError(Exception):
    """Malformed protocol, policy violation, or verification failure."""


class _SockLike(Protocol):
    def sendall(self, data: bytes, /) -> None: ...
    def recv(self, bufsize: int, /) -> bytes: ...


def recv_exact(sock: _SockLike, n: int) -> bytes:
    """Read exactly n bytes or raise (fail-closed on truncation)."""
    if n < 0:
        raise ProtocolError("negative length")
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError("connection closed before complete frame")
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock: _SockLike, msg_type: MsgType, payload: bytes = b"") -> None:
    if len(payload) > MAX_FRAME_BYTES - 1:
        raise ProtocolError("payload too large")
    body = bytes([int(msg_type)]) + payload
    sock.sendall(struct.pack("!I", len(body)) + body)


def recv_frame(sock: _SockLike) -> tuple[MsgType, bytes]:
    (ln,) = struct.unpack("!I", recv_exact(sock, 4))
    if ln == 0 or ln > MAX_FRAME_BYTES:
        raise ProtocolError(f"invalid frame length: {ln}")
    body = recv_exact(sock, ln)
    msg_type = MsgType(body[0])
    return msg_type, body[1:]


@dataclass(frozen=True, slots=True)
class OpenClient:
    file_size: int
    chunk_size: int
    session_id: bytes
    filename: str


def pack_open_client(msg: OpenClient) -> bytes:
    if len(msg.session_id) != SESSION_ID_BYTES:
        raise ProtocolError("session_id must be 16 bytes")
    name_bytes = msg.filename.encode("utf-8")
    if not name_bytes or len(name_bytes) > MAX_FILENAME_BYTES:
        raise ProtocolError("invalid filename length")
    if msg.file_size < 0:
        raise ProtocolError("invalid file_size")
    if msg.chunk_size <= 0 or msg.chunk_size > MAX_CHUNK_PAYLOAD:
        raise ProtocolError("invalid chunk_size")
    return (
        struct.pack("!Q", msg.file_size)
        + struct.pack("!I", msg.chunk_size)
        + msg.session_id
        + struct.pack("!H", len(name_bytes))
        + name_bytes
    )


def unpack_open_client(payload: bytes) -> OpenClient:
    need = 8 + 4 + SESSION_ID_BYTES + 2
    if len(payload) < need:
        raise ProtocolError("truncated OPEN")
    file_size = struct.unpack("!Q", payload[0:8])[0]
    chunk_size = struct.unpack("!I", payload[8:12])[0]
    session_id = payload[12 : 12 + SESSION_ID_BYTES]
    (nlen,) = struct.unpack("!H", payload[12 + SESSION_ID_BYTES : 14 + SESSION_ID_BYTES])
    if nlen == 0 or nlen > MAX_FILENAME_BYTES:
        raise ProtocolError("invalid filename length field")
    rest = payload[14 + SESSION_ID_BYTES :]
    if len(rest) != nlen:
        raise ProtocolError("filename length mismatch")
    filename = rest.decode("utf-8", errors="strict")
    return OpenClient(
        file_size=file_size,
        chunk_size=chunk_size,
        session_id=session_id,
        filename=filename,
    )


def pack_open_ack(*, resume: bool, bytes_on_disk: int) -> bytes:
    status = 1 if resume else 0
    return struct.pack("!B", status) + struct.pack("!Q", bytes_on_disk)


def unpack_open_ack(payload: bytes) -> tuple[bool, int]:
    if len(payload) != 1 + 8:
        raise ProtocolError("invalid OPEN_ACK length")
    status = payload[0]
    if status not in (0, 1):
        raise ProtocolError("invalid OPEN_ACK status")
    (bytes_on_disk,) = struct.unpack("!Q", payload[1:9])
    return bool(status), bytes_on_disk


def pack_chunk(*, offset: int, data: bytes) -> bytes:
    if offset < 0:
        raise ProtocolError("negative offset")
    ln = len(data)
    if ln == 0 or ln > MAX_CHUNK_PAYLOAD:
        raise ProtocolError("invalid chunk payload length")
    return struct.pack("!Q", offset) + struct.pack("!I", ln) + data


def unpack_chunk(payload: bytes) -> tuple[int, bytes]:
    need = 8 + 4
    if len(payload) < need:
        raise ProtocolError("truncated CHUNK header")
    offset = struct.unpack("!Q", payload[0:8])[0]
    (ln,) = struct.unpack("!I", payload[8:12])
    if ln == 0 or ln > MAX_CHUNK_PAYLOAD:
        raise ProtocolError("invalid CHUNK length")
    if len(payload) != need + ln:
        raise ProtocolError("CHUNK length mismatch")
    return offset, payload[12:]


def pack_eof(sha256_digest: bytes) -> bytes:
    if len(sha256_digest) != 32:
        raise ProtocolError("sha256 must be 32 bytes")
    return sha256_digest


def unpack_eof(payload: bytes) -> bytes:
    if len(payload) != 32:
        raise ProtocolError("invalid EOF payload")
    return payload


def pack_server_error(message: str) -> bytes:
    b = message.encode("utf-8", errors="strict")
    if len(b) > 4096:
        raise ProtocolError("error message too long")
    return struct.pack("!H", len(b)) + b


def unpack_server_error(payload: bytes) -> str:
    if len(payload) < 2:
        raise ProtocolError("truncated SERVER_ERROR")
    (elen,) = struct.unpack("!H", payload[0:2])
    if len(payload) != 2 + elen:
        raise ProtocolError("SERVER_ERROR length mismatch")
    return payload[2:].decode("utf-8", errors="strict")


def safe_basename(filename: str) -> str:
    """Reject path traversal; receiver only accepts a single path segment name."""
    name = Path(filename).name
    if not name or name != filename or name in (".", "..") or "/" in filename or "\\" in filename:
        raise ProtocolError("invalid filename (path segments or traversal not allowed)")
    return name


def rebuild_sha256_from_partial(path: Path, *, block_size: int = 1024 * 1024) -> "hashlib._Hash":
    """
    On resume, rebuild SHA-256 state from bytes already persisted.

    Tradeoff: O(bytes_on_disk) read from disk when reconnecting. This avoids
    custom crypto while keeping a single full-file SHA-256 check at EOF.
    """
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(block_size)
            if not block:
                break
            h.update(block)
    return h


def write_chunk_at(
    fp: BinaryIO,
    *,
    file_size: int,
    offset: int,
    data: bytes,
    hasher: "hashlib._Hash",
) -> None:
    if offset < 0 or offset > file_size:
        raise ProtocolError("chunk offset out of range")
    if offset + len(data) > file_size:
        raise ProtocolError("chunk extends past declared file_size")
    fp.seek(offset)
    fp.write(data)
    hasher.update(data)
