#!/usr/bin/env python3
"""
Approach B — sender: stream-encrypt file chunks (AES-256-GCM), upload ciphertext
to broker, finalize signed manifest. Broker never sees plaintext or the DEK.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import secrets
import socket
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

_APP_DIR = Path(__file__).resolve().parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

from common import broker_protocol as bp
from common.broker_client import BrokerClient, BrokerRequestError
from common import chunk_crypto as cc
from common import manifest as mf

logger = logging.getLogger("sender_encrypt_upload")

SIDE_SCHEMA = 1


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


def _chunk_count(plaintext_size: int, chunk_size: int) -> int:
    return (plaintext_size + chunk_size - 1) // chunk_size


def _read_plain_chunk(fp, *, index: int, chunk_size: int, plaintext_size: int) -> bytes:
    offset = index * chunk_size
    fp.seek(offset)
    want = min(chunk_size, plaintext_size - offset)
    data = fp.read(want)
    if len(data) != want:
        raise ValueError("short read from plaintext file")
    return data


def _session_id_from_hex(h: str) -> bytes:
    b = bytes.fromhex(h)
    if len(b) != bp.SESSION_ID_LEN:
        raise ValueError(f"session id must be {bp.SESSION_ID_LEN} bytes ({bp.SESSION_ID_LEN*2} hex chars)")
    return b


def _sender_public_pem_from_private(sender_priv_pem: bytes) -> bytes:
    key = serialization.load_pem_private_key(sender_priv_pem, password=None)
    pub = key.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def main() -> int:
    p = argparse.ArgumentParser(description="Approach B — encrypt + upload ciphertext chunks.")
    p.add_argument("--broker-host", default="127.0.0.1")
    p.add_argument("--broker-port", type=int, default=27202)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--chunk-size", type=int, default=1024 * 1024)
    p.add_argument("--receiver-public", type=Path, required=True, help="RSA public PEM (OAEP wrap target)")
    p.add_argument("--sender-private", type=Path, required=True, help="RSA private PEM (PSS manifest signing)")
    p.add_argument("--state-path", type=Path, default=None, help="Resume sidecar JSON (default: beside --input)")
    p.add_argument("--session-id", default=None, help=f"Hex {bp.SESSION_ID_LEN*2} chars; required for --resume")
    p.add_argument("--resume", action="store_true", help="Resume using sidecar + broker LIST state")
    p.add_argument("--socket-timeout", type=float, default=7200.0)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    _configure_logging(args.verbose)

    if args.chunk_size <= 0 or args.chunk_size > bp.MAX_BODY_LEN // 2:
        p.error("invalid --chunk-size")

    input_path = args.input.resolve()
    if not input_path.is_file():
        p.error(f"input not found: {input_path}")

    receiver_pub = args.receiver_public.read_bytes()
    sender_priv = args.sender_private.read_bytes()

    if args.resume:
        if not args.session_id:
            p.error("--resume requires --session-id")
        session_id = _session_id_from_hex(args.session_id)
    else:
        session_id = _session_id_from_hex(args.session_id) if args.session_id else secrets.token_bytes(bp.SESSION_ID_LEN)
        if args.session_id is None:
            logger.info("session_id=%s", session_id.hex())
            logger.info("resume hint: use --session-id %s --resume", session_id.hex())

    state_path = args.state_path
    if state_path is None:
        state_path = input_path.parent / f"{input_path.name}.{session_id.hex()}.bupload.json"
    state_path = state_path.resolve()

    plaintext_size = input_path.stat().st_size
    if plaintext_size == 0:
        p.error("empty input files are not supported for chunked manifests")
    n_chunks = _chunk_count(plaintext_size, args.chunk_size)

    if args.resume:
        side = _read_json(state_path)
        if int(side.get("schema", -1)) != SIDE_SCHEMA:
            raise SystemExit("unsupported sidecar schema")
        if side["session_id_hex"] != session_id.hex():
            raise SystemExit("session id mismatch vs sidecar")
        if side["input_path"] != str(input_path):
            raise SystemExit("input path mismatch vs sidecar")
        if int(side["plaintext_size"]) != plaintext_size or int(side["chunk_size"]) != args.chunk_size:
            raise SystemExit("file size or chunk size mismatch vs sidecar")
        dek = mf.rsa_oaep_sha256_unwrap(
            private_key_pem=sender_priv,
            ciphertext=mf.b64d(side["dek_sender_resume_wrap_b64"]),
        )
        dek_wrapped_receiver = mf.b64d(side["dek_wrapped_receiver_b64"])
    else:
        dek = cc.generate_dek()
        dek_wrapped_receiver = mf.rsa_oaep_sha256_wrap(public_key_pem=receiver_pub, plaintext=dek)
        sender_pub_pem = _sender_public_pem_from_private(sender_priv)
        dek_sender_resume = mf.rsa_oaep_sha256_wrap(public_key_pem=sender_pub_pem, plaintext=dek)
        _atomic_write_json(
            state_path,
            {
                "schema": SIDE_SCHEMA,
                "session_id_hex": session_id.hex(),
                "input_path": str(input_path),
                "chunk_size": args.chunk_size,
                "plaintext_size": plaintext_size,
                "dek_wrapped_receiver_b64": mf.b64e(dek_wrapped_receiver),
                "dek_sender_resume_wrap_b64": mf.b64e(dek_sender_resume),
            },
        )
        logger.info("wrote sidecar %s (contains wrapped DEKs; keep private)", state_path)

    sock = _connect(args.broker_host, args.broker_port, timeout=args.socket_timeout)
    try:
        client = BrokerClient(sock)
        try:
            on_broker = set(client.list_chunks(session_id=session_id))
        except BrokerRequestError as exc:
            raise SystemExit(f"broker LIST failed: {exc}") from exc

        full_h = hashlib.sha256()
        chunks_meta: list[dict[str, Any]] = []

        with input_path.open("rb") as fp:
            for i in range(n_chunks):
                pt = _read_plain_chunk(fp, index=i, chunk_size=args.chunk_size, plaintext_size=plaintext_size)
                full_h.update(pt)
                nonce, ct = cc.encrypt_chunk(dek=dek, session_id=session_id, chunk_index=i, plaintext=pt)
                pt_h = cc.sha256_hex(pt)
                ct_h = cc.sha256_hex(ct)
                if i in on_broker:
                    try:
                        remote = client.get_chunk(session_id=session_id, chunk_index=i)
                    except BrokerRequestError as exc:
                        raise SystemExit(f"broker GET chunk {i} failed: {exc}") from exc
                    if remote != ct:
                        raise SystemExit(f"broker ciphertext mismatch at chunk {i} (fail-closed)")
                else:
                    try:
                        client.put_chunk(session_id=session_id, chunk_index=i, ciphertext=ct)
                    except BrokerRequestError as exc:
                        raise SystemExit(f"broker PUT chunk {i} failed: {exc}") from exc
                    on_broker.add(i)

                chunks_meta.append(
                    {
                        "index": i,
                        "plaintext_len": len(pt),
                        "nonce_b64": mf.b64e(nonce),
                        "plaintext_chunk_sha256_hex": pt_h,
                        "ciphertext_sha256_hex": ct_h,
                    }
                )

                if (i + 1) % 256 == 0 or i + 1 == n_chunks:
                    logger.info("progress: chunk %s/%s", i + 1, n_chunks)

        manifest_obj: dict[str, Any] = {
            "schema_version": mf.MANIFEST_SCHEMA_VERSION,
            "nonce_policy": "derived_v1",
            "session_id_hex": session_id.hex(),
            "issued_at_unix_ms": mf.issued_at_ms(),
            "chunk_size": args.chunk_size,
            "plaintext_size": plaintext_size,
            "plaintext_sha256_hex": full_h.hexdigest(),
            "dek_wrapped_receiver_b64": mf.b64e(dek_wrapped_receiver),
            "chunks": chunks_meta,
        }
        mf.validate_manifest_schema(manifest_obj)
        manifest_bytes = mf.canonical_manifest_json(manifest_obj)
        sig = mf.sign_manifest_rsa_pss_sha256(private_key_pem=sender_priv, manifest_bytes=manifest_bytes)

        try:
            client.put_manifest(session_id=session_id, manifest_json=manifest_bytes, signature=sig)
        except BrokerRequestError as exc:
            raise SystemExit(f"broker PUT_MANIFEST failed: {exc}") from exc

        side = _read_json(state_path)
        side["manifest_uploaded"] = True
        side["issued_at_unix_ms"] = manifest_obj["issued_at_unix_ms"]
        _atomic_write_json(state_path, side)
        logger.info("manifest published for session %s", session_id.hex())
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
