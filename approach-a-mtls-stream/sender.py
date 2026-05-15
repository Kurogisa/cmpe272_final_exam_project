#!/usr/bin/env python3
"""
Approach A — mutual TLS streaming sender (TLS client).

Streams a file in bounded-memory chunks over mTLS. Announces total size up
front, supports resume using a stable session id, and verifies the receiver's
terminal acknowledgment after SHA-256 checks (fail-closed).
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import secrets
import socket
import ssl
import sys
import time
from pathlib import Path

_APP_DIR = Path(__file__).resolve().parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

from common import protocol as pr
from common import tls_context as tls_ctx


logger = logging.getLogger("sender")


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _session_id_from_hex(session_hex: str) -> bytes:
    b = bytes.fromhex(session_hex)
    if len(b) != pr.SESSION_ID_BYTES:
        raise ValueError(f"--session-id must be {pr.SESSION_ID_BYTES * 2} hex chars")
    return b


def _hash_prefix(path: Path, nbytes: int, *, block: int = 1024 * 1024) -> "hashlib._Hash":
    """Rebuild SHA-256 over the first nbytes of a file (resume helper)."""
    if nbytes < 0:
        raise ValueError("negative nbytes")
    h = hashlib.sha256()
    remaining = nbytes
    with path.open("rb") as f:
        while remaining > 0:
            chunk = f.read(min(block, remaining))
            if not chunk:
                raise pr.ProtocolError("unexpected EOF while rebuilding hash prefix")
            h.update(chunk)
            remaining -= len(chunk)
    return h


def main() -> int:
    p = argparse.ArgumentParser(description="Approach A — mTLS streaming sender (TLS client).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=27201)
    p.add_argument("--cert", type=Path, required=True, help="Client certificate (PEM)")
    p.add_argument("--key", type=Path, required=True, help="Client private key (PEM)")
    p.add_argument("--ca", type=Path, required=True, help="CA that signed the server (receiver) cert")
    p.add_argument("--input", type=Path, required=True, help="File to send")
    p.add_argument("--remote-name", default=None, help="Basename presented to receiver (default: input name)")
    p.add_argument("--chunk-size", type=int, default=1024 * 1024, help="Plaintext chunk size (bytes)")
    p.add_argument(
        "--session-id",
        default=None,
        help=f"Hex-encoded {pr.SESSION_ID_BYTES}-byte session id (default: random; reuse for resume)",
    )
    p.add_argument("--socket-timeout", type=float, default=3600.0)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    _configure_logging(args.verbose)

    if args.chunk_size <= 0 or args.chunk_size > pr.MAX_CHUNK_PAYLOAD:
        p.error("invalid --chunk-size")

    remote_name = args.remote_name or args.input.name
    pr.safe_basename(remote_name)  # validate early for clearer UX

    session_id: bytes
    if args.session_id:
        try:
            session_id = _session_id_from_hex(args.session_id)
        except ValueError as exc:
            p.error(str(exc))
    else:
        session_id = secrets.token_bytes(pr.SESSION_ID_BYTES)
    if args.session_id is None:
        logger.info("session_id=%s (pass --session-id to resume)", session_id.hex())

    file_size = args.input.stat().st_size
    ctx = tls_ctx.build_client_context(
        certfile=args.cert,
        keyfile=args.key,
        cafile=args.ca,
    )

    raw = socket.create_connection((args.host, args.port), timeout=args.socket_timeout)
    raw.settimeout(args.socket_timeout)

    # Hostname/SNI must match server certificate SANs (localhost + 127.0.0.1 in lab script).
    if args.host in ("127.0.0.1", "0.0.0.0"):
        tls_hostname = "127.0.0.1"
    elif args.host in ("::1",):
        tls_hostname = "::1"
    else:
        tls_hostname = args.host

    tls_sock = ctx.wrap_socket(raw, server_hostname=tls_hostname)
    tls_ctx.log_ssl_cipher(tls_sock)

    start = time.monotonic()
    bytes_sent = 0
    try:
        open_msg = pr.OpenClient(
            file_size=file_size,
            chunk_size=args.chunk_size,
            session_id=session_id,
            filename=remote_name,
        )
        pr.send_frame(tls_sock, pr.MsgType.OPEN, pr.pack_open_client(open_msg))

        msg_type, pl = pr.recv_frame(tls_sock)
        if msg_type != pr.MsgType.OPEN_ACK:
            raise pr.ProtocolError("expected OPEN_ACK")
        _resume_flag, bytes_on_disk = pr.unpack_open_ack(pl)
        if bytes_on_disk > file_size:
            raise pr.ProtocolError("receiver reported more bytes than file size")

        hasher = _hash_prefix(args.input, bytes_on_disk) if bytes_on_disk else hashlib.sha256()

        with args.input.open("rb") as fp:
            fp.seek(bytes_on_disk)
            offset = bytes_on_disk
            while offset < file_size:
                to_read = min(args.chunk_size, file_size - offset)
                data = fp.read(to_read)
                if len(data) != to_read:
                    raise pr.ProtocolError("short read from input file")
                pr.send_frame(tls_sock, pr.MsgType.CHUNK, pr.pack_chunk(offset=offset, data=data))
                hasher.update(data)
                offset += len(data)
                bytes_sent += len(data)

        pr.send_frame(tls_sock, pr.MsgType.EOF, pr.pack_eof(hasher.digest()))

        msg_type, pl = pr.recv_frame(tls_sock)
        if msg_type == pr.MsgType.SERVER_ERROR:
            raise pr.ProtocolError(f"receiver error: {pr.unpack_server_error(pl)}")
        if msg_type != pr.MsgType.SERVER_OK:
            raise pr.ProtocolError(f"unexpected final frame: {msg_type}")

    except Exception as exc:
        logger.error("transfer failed: %s", exc, exc_info=args.verbose)
        return 1
    finally:
        try:
            tls_sock.close()
        except Exception:
            pass

    elapsed = time.monotonic() - start
    mb = file_size / (1024 * 1024)
    tput = (file_size / elapsed) if elapsed > 0 else 0.0
    logger.info(
        "transfer complete: %.2f MiB in %.2fs (%.2f MiB/s effective application throughput)",
        mb,
        elapsed,
        tput / (1024 * 1024),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
