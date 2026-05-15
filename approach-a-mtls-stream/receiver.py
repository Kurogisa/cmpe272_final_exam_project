#!/usr/bin/env python3
"""
Approach A — mutual TLS streaming receiver (TLS server).

Listens on TCP, requires client authentication, streams ciphertext inside TLS
records (AEAD), assembles plaintext to a temp file, verifies SHA-256, then
atomically renames into the output directory (fail-closed).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import socket
import sys
import time
from pathlib import Path
from ssl import SSLSocket

_APP_DIR = Path(__file__).resolve().parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

from common import protocol as pr
from common import tls_context as tls_ctx


logger = logging.getLogger("receiver")


META_SUFFIX = ".meta.json"
PARTIAL_SUFFIX = ".partial"


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _meta_path(output_dir: Path, session_hex: str) -> Path:
    return output_dir / f"{session_hex}{META_SUFFIX}"


def _partial_path(output_dir: Path, session_hex: str) -> Path:
    return output_dir / f"{session_hex}{PARTIAL_SUFFIX}"


def _load_meta(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_meta(path: Path, payload: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


def _fail_closed_cleanup(partial: Path, meta: Path) -> None:
    for p in (partial, meta):
        try:
            if p.exists():
                p.unlink()
        except OSError as exc:
            logger.warning("could not remove %s: %s", p, exc)


def _handle_client(
    conn: SSLSocket,
    *,
    output_dir: Path,
    overwrite: bool,
) -> None:
    tls_ctx.log_ssl_cipher(conn)

    msg_type, payload = pr.recv_frame(conn)
    if msg_type != pr.MsgType.OPEN:
        raise pr.ProtocolError("first frame must be OPEN")
    open_msg = pr.unpack_open_client(payload)
    filename = pr.safe_basename(open_msg.filename)
    session_hex = open_msg.session_id.hex()

    partial = _partial_path(output_dir, session_hex)
    meta = _meta_path(output_dir, session_hex)
    dest = output_dir / filename

    bytes_on_disk = 0
    hasher = hashlib.sha256()
    resume_stream = False

    if partial.exists() and meta.exists():
        meta_obj = _load_meta(meta)
        if (
            int(meta_obj["file_size"]) == open_msg.file_size
            and int(meta_obj["chunk_size"]) == open_msg.chunk_size
            and str(meta_obj["filename"]) == filename
            and str(meta_obj["session_hex"]) == session_hex
        ):
            bytes_on_disk = partial.stat().st_size
            if bytes_on_disk > open_msg.file_size:
                raise pr.ProtocolError("partial file larger than declared file_size")
            if 0 < bytes_on_disk <= open_msg.file_size:
                # Resume (including the edge where all bytes are present but EOF not yet verified).
                hasher = pr.rebuild_sha256_from_partial(partial)
                resume_stream = bytes_on_disk < open_msg.file_size
                logger.info(
                    "resume: session=%s bytes_on_disk=%s resume_stream=%s",
                    session_hex,
                    bytes_on_disk,
                    resume_stream,
                )
        else:
            raise pr.ProtocolError("existing partial/meta mismatch for session; refusing to mix sessions")
    else:
        if partial.exists() ^ meta.exists():
            raise pr.ProtocolError("partial/meta pair inconsistent; manual cleanup required")
        if dest.exists() and not overwrite:
            raise pr.ProtocolError(f"destination exists: {dest} (use --overwrite or pick a new name)")
        partial.touch(exist_ok=False)
        _write_meta(
            meta,
            {
                "session_hex": session_hex,
                "filename": filename,
                "file_size": open_msg.file_size,
                "chunk_size": open_msg.chunk_size,
            },
        )
        logger.info("new transfer: session=%s file=%s size=%s", session_hex, filename, open_msg.file_size)

    pr.send_frame(
        conn,
        pr.MsgType.OPEN_ACK,
        pr.pack_open_ack(resume=bytes_on_disk > 0, bytes_on_disk=bytes_on_disk),
    )

    expected_next = bytes_on_disk
    with partial.open("r+b") as fp:
        while True:
            msg_type, pl = pr.recv_frame(conn)
            if msg_type == pr.MsgType.CHUNK:
                offset, data = pr.unpack_chunk(pl)
                if offset != expected_next:
                    raise pr.ProtocolError("non-contiguous chunk stream (offset mismatch)")
                pr.write_chunk_at(
                    fp,
                    file_size=open_msg.file_size,
                    offset=offset,
                    data=data,
                    hasher=hasher,
                )
                expected_next += len(data)
                fp.flush()
            elif msg_type == pr.MsgType.EOF:
                digest = pr.unpack_eof(pl)
                break
            else:
                raise pr.ProtocolError(f"unexpected frame during transfer: {msg_type}")

        fp.flush()
        try:
            os.fsync(fp.fileno())
        except OSError as exc:
            logger.warning("fsync failed (continuing with best-effort durability): %s", exc)

    actual_size = partial.stat().st_size
    if expected_next != open_msg.file_size or actual_size != open_msg.file_size:
        pr.send_frame(conn, pr.MsgType.SERVER_ERROR, pr.pack_server_error("size mismatch after EOF"))
        _fail_closed_cleanup(partial, meta)
        raise pr.ProtocolError("size mismatch after EOF (fail-closed)")

    if hasher.digest() != digest:
        pr.send_frame(conn, pr.MsgType.SERVER_ERROR, pr.pack_server_error("sha256 mismatch"))
        _fail_closed_cleanup(partial, meta)
        raise pr.ProtocolError("sha256 mismatch (fail-closed)")

    if dest.exists() and not overwrite:
        pr.send_frame(conn, pr.MsgType.SERVER_ERROR, pr.pack_server_error("destination exists"))
        raise pr.ProtocolError("destination exists")

    try:
        os.replace(partial, dest)
    except OSError as exc:
        pr.send_frame(conn, pr.MsgType.SERVER_ERROR, pr.pack_server_error(f"rename failed: {exc}"))
        raise

    try:
        meta.unlink(missing_ok=True)  # type: ignore[arg-type]
    except TypeError:
        if meta.exists():
            meta.unlink()

    pr.send_frame(conn, pr.MsgType.SERVER_OK, b"")
    logger.info("transfer OK: wrote %s (sha256 verified)", dest)


def main() -> int:
    p = argparse.ArgumentParser(description="Approach A — mTLS streaming receiver (TLS server).")
    p.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=27201, help="TCP port")
    p.add_argument("--cert", type=Path, required=True, help="Server certificate (PEM)")
    p.add_argument("--key", type=Path, required=True, help="Server private key (PEM)")
    p.add_argument("--client-ca", type=Path, required=True, help="CA that issued client (sender) certs")
    p.add_argument("--output-dir", type=Path, default=Path("."), help="Directory for output + partial state")
    p.add_argument("--overwrite", action="store_true", help="Allow replacing an existing destination file")
    p.add_argument("--socket-timeout", type=float, default=3600.0, help="Per-socket timeout (seconds)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    _configure_logging(args.verbose)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    ctx = tls_ctx.build_server_context(
        certfile=args.cert,
        keyfile=args.key,
        client_cafile=args.client_ca,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(1)
    logger.info("listening on %s:%s (TLS)", args.host, args.port)

    conn, addr = sock.accept()
    conn.settimeout(args.socket_timeout)
    tls_conn = ctx.wrap_socket(conn, server_side=True)
    start = time.monotonic()
    try:
        _handle_client(tls_conn, output_dir=args.output_dir, overwrite=args.overwrite)
    except Exception as exc:
        logger.error("transfer failed: %s", exc, exc_info=args.verbose)
        try:
            pr.send_frame(tls_conn, pr.MsgType.SERVER_ERROR, pr.pack_server_error(str(exc)))
        except Exception:
            pass
        return 1
    finally:
        elapsed = time.monotonic() - start
        try:
            tls_conn.close()
        except OSError:
            pass
        sock.close()
        logger.info("connection closed (%.2fs wall time)", elapsed)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
