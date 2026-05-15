"""
Canonical manifest encoding and RSA-PSS-SHA256 signatures (Approach B).

The manifest bytes signed by the sender bind chunk metadata, timestamps, and
the receiver-wrapped DEK. The broker stores the manifest + detached signature
without being able to alter them without detection.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MANIFEST_SCHEMA_VERSION = 1


def canonical_manifest_json(payload: dict[str, Any]) -> bytes:
    """Deterministic UTF-8 JSON suitable for signing (sorted keys, minimal separators)."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sign_manifest_rsa_pss_sha256(*, private_key_pem: bytes, manifest_bytes: bytes) -> bytes:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("expected RSA private key PEM")
    return key.sign(
        manifest_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )


def verify_manifest_rsa_pss_sha256(*, public_key_pem: bytes, manifest_bytes: bytes, signature: bytes) -> None:
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("expected RSA public key PEM")
    try:
        key.verify(
            signature,
            manifest_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise ValueError("manifest signature verification failed") from exc


def issued_at_ms() -> int:
    return int(time.time() * 1000)


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def parse_manifest_bytes(data: bytes) -> dict[str, Any]:
    obj = json.loads(data.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("manifest must be a JSON object")
    return obj


def validate_manifest_schema(m: dict[str, Any]) -> None:
    if int(m.get("schema_version", -1)) != MANIFEST_SCHEMA_VERSION:
        raise ValueError("unsupported schema_version")
    for k in (
        "schema_version",
        "nonce_policy",
        "session_id_hex",
        "issued_at_unix_ms",
        "chunk_size",
        "plaintext_size",
        "plaintext_sha256_hex",
        "dek_wrapped_receiver_b64",
        "chunks",
    ):
        if k not in m:
            raise ValueError(f"missing manifest field: {k}")
    if not isinstance(m["chunks"], list) or not m["chunks"]:
        raise ValueError("manifest chunks must be a non-empty list")
    if str(m["nonce_policy"]) != "derived_v1":
        raise ValueError("unsupported nonce_policy")
    for ch in m["chunks"]:
        validate_chunk_entry(ch)
    chunks_sorted = sorted(m["chunks"], key=lambda c: int(c["index"]))
    expected = list(range(len(chunks_sorted)))
    got = [int(c["index"]) for c in chunks_sorted]
    if got != expected:
        raise ValueError("chunk indices must be contiguous starting at 0")


def validate_chunk_entry(ch: Any) -> None:
    if not isinstance(ch, dict):
        raise ValueError("chunk entry must be an object")
    for k in (
        "index",
        "plaintext_len",
        "nonce_b64",
        "plaintext_chunk_sha256_hex",
        "ciphertext_sha256_hex",
    ):
        if k not in ch:
            raise ValueError(f"missing chunk field: {k}")


def rsa_oaep_sha256_wrap(*, public_key_pem: bytes, plaintext: bytes) -> bytes:
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("expected RSA public key PEM")
    return key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def rsa_oaep_sha256_unwrap(*, private_key_pem: bytes, ciphertext: bytes) -> bytes:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("expected RSA private key PEM")
    return key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
