#!/usr/bin/env python3
"""
Approach B — receiver: fetch signed manifest + ciphertext chunks from broker,
verify signatures and AEAD, stream plaintext to a temp file, verify SHA-256,
then atomically rename (fail-closed).
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
from typing import Any

_APP_DIR = Path(__file__).resolve().parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

from common import broker_protocol as bp
from common.broker_client import BrokerClient, BrokerRequestError
from common import chunk_crypto as cc
from common import manifest as mf

logger = logging.getLogger("receiver_download_decrypt")

DOWN_SCHEMA = 1


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _connect(host: str, port: int, *, timeout: float) -> socket.socket:
    delay = 0.5
    last: OSError | None = None
    for attempt in range(8):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            return s
        except OSError as exc:
            last = exc
            logger.warning("connect attempt %s failed: %s", attempt + 1, exc)
            time.sleep(delay)
            delay = min(delay * 2, 5.0)
    assert last is not None
    raise last


def _atomic_write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    data = json.dumps(obj, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    tmp.write_bytes(data)
    tmp.replace(path)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _session_id_from_hex(h: str) -> bytes:
    b = bytes.fromhex(h)
    if len(b) != bp.SESSION_ID_LEN:
        raise ValueError(f"session id must be {bp.SESSION_ID_LEN} bytes ({bp.SESSION_ID_LEN*2} hex chars)")
    return b


def _offset_before_index(chunks_sorted: list[dict[str, Any]], before: int) -> int:
    off = 0
    for ch in chunks_sorted:
        idx = int(ch["index"])
        if idx >= before:
            break
        off += int(ch["plaintext_len"])
    return off


def _check_manifest_freshness(*, issued_ms: int, max_age_sec: int, skew_sec: int) -> None:
    now_ms = int(time.time() * 1000)
    if issued_ms > now_ms + skew_sec * 1000:
        raise ValueError("manifest issued_at is too far in the future (clock skew / forgery)")
    if issued_ms < now_ms - max_age_sec * 1000:
        raise ValueError("manifest is too old (replay / stale transfer rejected)")


def _fail_closed(paths: list[Path]) -> None:
    for p in paths:
        try:
            if p.exists():
                p.unlink()
        except OSError as exc:
            logger.warning("cleanup failed for %s: %s", p, exc)


def main() -> int:
    p = argparse.ArgumentParser(description="Approach B — download ciphertext + decrypt to output file.")
    p.add_argument("--broker-host", default="127.0.0.1")
    p.add_argument("--broker-port", type=int, default=27202)
    p.add_argument("--session-id", required=True, help=f"Hex {bp.SESSION_ID_LEN*2} chars")
    p.add_argument("--receiver-private", type=Path, required=True, help="RSA private PEM (OAEP unwrap DEK)")
    p.add_argument("--sender-public", type=Path, required=True, help="RSA public PEM (verify manifest PSS)")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--max-manifest-age-sec", type=int, default=604800, help="Reject manifests older than this")
    p.add_argument("--clock-skew-sec", type=int, default=300, help="Allowed future skew for issued_at")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--state-path", type=Path, default=None)
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--socket-timeout", type=float, default=7200.0)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    _configure_logging(args.verbose)

    session_id = _session_id_from_hex(args.session_id)
    session_hex = session_id.hex()

    out = args.output.resolve()
    if out.exists() and not args.overwrite and not args.resume:
        raise SystemExit(f"refusing to overwrite existing file: {out} (use --overwrite or --resume)")

    partial = out.parent / f"{out.name}.{session_hex}.partial"
    state_path = args.state_path or (out.parent / f"{out.name}.{session_hex}.bdownload.json")
    state_path = state_path.resolve()

    receiver_priv = args.receiver_private.read_bytes()
    sender_pub = args.sender_public.read_bytes()

    sock = _connect(args.broker_host, args.broker_port, timeout=args.socket_timeout)
    try:
        client = BrokerClient(sock)
        try:
            manifest_bytes, sig = client.get_manifest(session_id=session_id)
        except BrokerRequestError as exc:
            raise SystemExit(f"broker GET_MANIFEST failed: {exc}") from exc

        mf.verify_manifest_rsa_pss_sha256(public_key_pem=sender_pub, manifest_bytes=manifest_bytes, signature=sig)
        m = mf.parse_manifest_bytes(manifest_bytes)
        mf.validate_manifest_schema(m)
        if str(m["session_id_hex"]) != session_hex:
            raise SystemExit("manifest session_id does not match CLI")

        _check_manifest_freshness(
            issued_ms=int(m["issued_at_unix_ms"]),
            max_age_sec=args.max_manifest_age_sec,
            skew_sec=args.clock_skew_sec,
        )

        dek = mf.rsa_oaep_sha256_unwrap(
            private_key_pem=receiver_priv,
            ciphertext=mf.b64d(str(m["dek_wrapped_receiver_b64"])),
        )

        chunks = sorted(m["chunks"], key=lambda c: int(c["index"]))
        plaintext_size = int(m["plaintext_size"])
        expected_full = str(m["plaintext_sha256_hex"])

        start_idx = 0
        if args.resume:
            if not state_path.is_file():
                raise SystemExit("resume requested but state file missing")
            st = _read_json(state_path)
            if int(st.get("schema", -1)) != DOWN_SCHEMA:
                raise SystemExit("unsupported download sidecar schema")
            if st["session_id_hex"] != session_hex:
                raise SystemExit("session mismatch in download sidecar")
            if st["output_path"] != str(out):
                raise SystemExit("output path mismatch in download sidecar")
            start_idx = int(st["next_chunk_index"])
            logger.info("resume from chunk index %s", start_idx)
        else:
            _fail_closed([partial, state_path])

        if args.resume and start_idx > 0:
            need_bytes = _offset_before_index(chunks, start_idx)
            if not partial.is_file() or partial.stat().st_size < need_bytes:
                raise SystemExit("resume requires partial file at least as large as completed prefix")
        elif args.resume and start_idx == 0:
            _fail_closed([partial])

        partial.parent.mkdir(parents=True, exist_ok=True)
        full_h = hashlib.sha256()

        mode = "r+b" if partial.exists() and partial.stat().st_size > 0 else "wb"
        t0 = time.monotonic()
        with partial.open(mode) as fp:
            if start_idx > 0 and mode == "r+b":
                fp.seek(0)
                consumed = 0
                target = _offset_before_index(chunks, start_idx)
                while consumed < target:
                    block = fp.read(min(1024 * 1024, target - consumed))
                    if not block:
                        raise ValueError("partial file shorter than resume offset")
                    full_h.update(block)
                    consumed += len(block)

            for ch in chunks[int(start_idx) :]:
                i = int(ch["index"])
                nonce = mf.b64d(str(ch["nonce_b64"]))
                want_pt_h = str(ch["plaintext_chunk_sha256_hex"])
                want_ct_h = str(ch["ciphertext_sha256_hex"])

                try:
                    ct = client.get_chunk(session_id=session_id, chunk_index=i)
                except BrokerRequestError as exc:
                    raise SystemExit(f"broker GET chunk {i} failed: {exc}") from exc

                if cc.sha256_hex(ct) != want_ct_h:
                    raise ValueError(f"ciphertext sha256 mismatch chunk {i} (broker tamper / corruption)")

                pt = cc.decrypt_chunk(
                    dek=dek,
                    session_id=session_id,
                    chunk_index=i,
                    nonce=nonce,
                    ciphertext=ct,
                )
                if len(pt) != int(ch["plaintext_len"]):
                    raise ValueError(f"plaintext length mismatch chunk {i}")
                if cc.sha256_hex(pt) != want_pt_h:
                    raise ValueError(f"plaintext chunk hash mismatch chunk {i}")

                off = _offset_before_index(chunks, i)
                fp.seek(off)
                fp.write(pt)
                full_h.update(pt)
                fp.flush()

                next_idx = i + 1
                _atomic_write_json(
                    state_path,
                    {
                        "schema": DOWN_SCHEMA,
                        "session_id_hex": session_hex,
                        "output_path": str(out),
                        "next_chunk_index": next_idx,
                    },
                )

                if next_idx % 256 == 0 or next_idx == len(chunks):
                    logger.info("progress: chunk %s/%s", next_idx, len(chunks))

            try:
                os.fsync(fp.fileno())
            except OSError as exc:
                logger.warning("fsync warning: %s", exc)

        if full_h.hexdigest() != expected_full:
            raise ValueError("full plaintext sha256 mismatch (fail-closed)")

        if partial.stat().st_size != plaintext_size:
            raise ValueError("assembled size mismatch vs manifest")

        if out.exists() and not args.overwrite:
            raise SystemExit(f"refusing to replace existing output: {out}")

        try:
            os.replace(partial, out)
        except OSError as exc:
            raise SystemExit(f"atomic rename failed: {exc}") from exc

        try:
            state_path.unlink(missing_ok=True)  # type: ignore[call-arg]
        except TypeError:
            if state_path.exists():
                state_path.unlink()

        elapsed = time.monotonic() - t0
        mb = plaintext_size / (1024 * 1024)
        tput = (plaintext_size / elapsed) if elapsed > 0 else 0.0
        logger.info(
            "download+decrypt OK: %.2f MiB in %.2fs (%.2f MiB/s effective)",
            mb,
            elapsed,
            tput / (1024 * 1024),
        )
    except Exception as exc:
        logger.error("transfer failed: %s", exc, exc_info=args.verbose)
        _fail_closed([partial, state_path])
        raise SystemExit(1) from exc
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, BrokerRequestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
