#!/usr/bin/env python3
"""
Approach B — untrusted broker (TCP).

Stores ciphertext chunks and a detached signed manifest. Never decrypts.
"""

from __future__ import annotations

import argparse
import logging
import threading
from pathlib import Path
from socketserver import BaseRequestHandler, ThreadingTCPServer

import sys

_APP_DIR = Path(__file__).resolve().parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

from common import broker_protocol as bp

logger = logging.getLogger("broker")


class BrokerState:
    __slots__ = ("data_dir", "_locks", "_map_lock")

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self._locks: dict[str, threading.Lock] = {}
        self._map_lock = threading.Lock()

    def session_lock(self, session_hex: str) -> threading.Lock:
        with self._map_lock:
            return self._locks.setdefault(session_hex, threading.Lock())

    def session_dir(self, session_id: bytes) -> Path:
        h = session_id.hex()
        if len(h) != 32 or any(c not in "0123456789abcdef" for c in h):
            raise bp.BrokerProtocolError("invalid session id")
        p = self.data_dir / h
        return p


def _chunk_path(session_dir: Path, idx: int) -> Path:
    return session_dir / f"chunk_{idx:019d}.bin"


def _list_indices(session_dir: Path) -> list[int]:
    if not session_dir.is_dir():
        return []
    out: list[int] = []
    for p in session_dir.glob("chunk_*.bin"):
        name = p.name
        if not name.startswith("chunk_") or not name.endswith(".bin"):
            continue
        mid = name[len("chunk_") : -len(".bin")]
        try:
            out.append(int(mid))
        except ValueError:
            continue
    out.sort()
    return out


class BrokerTCPHandler(BaseRequestHandler):
    def handle(self) -> None:
        state: BrokerState = self.server.state  # type: ignore[attr-defined]
        sock = self.request
        try:
            while True:
                try:
                    cmd, body = bp.read_frame(sock)
                except bp.BrokerProtocolError as exc:
                    logger.debug("frame error: %s", exc)
                    break
                try:
                    resp = self._dispatch(state, cmd, body)
                except Exception as exc:
                    logger.warning("handler error: %s", exc)
                    resp = bp.pack_err(str(exc))
                try:
                    bp.write_frame(sock, cmd, resp)
                except OSError:
                    break
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _dispatch(self, state: BrokerState, cmd: int, body: bytes) -> bytes:
        if cmd == int(bp.Command.PUT_CHUNK):
            sid, idx, ct = bp.unpack_put_chunk(body)
            h = sid.hex()
            with state.session_lock(h):
                d = state.session_dir(sid)
                d.mkdir(parents=True, exist_ok=True)
                target = _chunk_path(d, idx)
                tmp = target.with_suffix(target.suffix + ".part")
                tmp.write_bytes(ct)
                tmp.replace(target)
            return bp.pack_ok()

        if cmd == int(bp.Command.GET_CHUNK):
            sid, idx = bp.unpack_session_chunk_query(body)
            h = sid.hex()
            with state.session_lock(h):
                target = _chunk_path(state.session_dir(sid), idx)
                if not target.is_file():
                    return bp.pack_err("chunk not found")
                data = target.read_bytes()
            return bp.pack_ok(bp.pack_get_chunk_response(data))

        if cmd == int(bp.Command.LIST_CHUNKS):
            if len(body) != bp.SESSION_ID_LEN:
                return bp.pack_err("bad LIST body")
            sid = body
            h = sid.hex()
            with state.session_lock(h):
                indices = _list_indices(state.session_dir(sid))
            return bp.pack_ok(bp.pack_list_response(indices))

        if cmd == int(bp.Command.PUT_MANIFEST):
            sid, mj, sig = bp.unpack_put_manifest(body)
            h = sid.hex()
            with state.session_lock(h):
                d = state.session_dir(sid)
                d.mkdir(parents=True, exist_ok=True)
                mj_path = d / "manifest.json"
                sig_path = d / "manifest.sig"
                tmp_m = mj_path.with_suffix(mj_path.suffix + ".part")
                tmp_s = sig_path.with_suffix(sig_path.suffix + ".part")
                tmp_m.write_bytes(mj)
                tmp_s.write_bytes(sig)
                tmp_m.replace(mj_path)
                tmp_s.replace(sig_path)
            return bp.pack_ok()

        if cmd == int(bp.Command.GET_MANIFEST):
            if len(body) != bp.SESSION_ID_LEN:
                return bp.pack_err("bad GET_MANIFEST body")
            sid = body
            h = sid.hex()
            with state.session_lock(h):
                d = state.session_dir(sid)
                mj_path = d / "manifest.json"
                sig_path = d / "manifest.sig"
                if not mj_path.is_file() or not sig_path.is_file():
                    return bp.pack_err("manifest not found")
                mj = mj_path.read_bytes()
                sig = sig_path.read_bytes()
            return bp.pack_ok(bp.pack_get_manifest_response(mj, sig))

        return bp.pack_err(f"unknown command: {cmd}")


class BrokerServer(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler, state: BrokerState):
        super().__init__(server_address, handler)
        self.state = state


def main() -> int:
    p = argparse.ArgumentParser(description="Approach B — ciphertext-only broker (TCP).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=27202)
    p.add_argument(
        "--data-dir",
        type=Path,
        default=_APP_DIR / "broker_data",
        help="Directory for stored ciphertext sessions",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args.data_dir.mkdir(parents=True, exist_ok=True)
    state = BrokerState(args.data_dir)
    srv = BrokerServer((args.host, args.port), BrokerTCPHandler, state)
    logger.info("broker listening on %s:%s data_dir=%s", args.host, args.port, args.data_dir)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        logger.info("shutting down")
    finally:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
