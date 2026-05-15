"""
AES-256-GCM chunk encryption using cryptography (Approach B).

Nonces are derived deterministically from (session_id, chunk_index) so uploads
can be resumed without persisting ciphertext locally. The manifest still lists
each nonce explicitly so receivers can cross-check derivation policy.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Final

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEK_LEN: Final[int] = 32
NONCE_LEN: Final[int] = 12


def generate_dek() -> bytes:
    return secrets.token_bytes(DEK_LEN)


def derive_chunk_nonce(*, session_id: bytes, chunk_index: int) -> bytes:
    if len(session_id) != 16:
        raise ValueError("session_id must be 16 bytes")
    if chunk_index < 0:
        raise ValueError("chunk_index must be non-negative")
    return hashlib.sha256(b"EVB2-GCM-v1" + session_id + chunk_index.to_bytes(8, "big", signed=False)).digest()[
        :NONCE_LEN
    ]


def _aad(session_id: bytes, chunk_index: int) -> bytes:
    if len(session_id) != 16:
        raise ValueError("session_id must be 16 bytes")
    if chunk_index < 0:
        raise ValueError("chunk_index must be non-negative")
    return b"EVB2" + session_id + chunk_index.to_bytes(8, "big", signed=False)


def encrypt_chunk(
    *,
    dek: bytes,
    session_id: bytes,
    chunk_index: int,
    plaintext: bytes,
) -> tuple[bytes, bytes]:
    """Returns (nonce12, ciphertext_including_tag)."""
    if len(dek) != DEK_LEN:
        raise ValueError("DEK must be 32 bytes for AES-256")
    nonce = derive_chunk_nonce(session_id=session_id, chunk_index=chunk_index)
    aes = AESGCM(dek)
    ct = aes.encrypt(nonce, plaintext, _aad(session_id, chunk_index))
    return nonce, ct


def decrypt_chunk(
    *,
    dek: bytes,
    session_id: bytes,
    chunk_index: int,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    if len(dek) != DEK_LEN:
        raise ValueError("DEK must be 32 bytes for AES-256")
    expected = derive_chunk_nonce(session_id=session_id, chunk_index=chunk_index)
    if nonce != expected:
        raise ValueError("nonce does not match derived policy")
    aes = AESGCM(dek)
    return aes.decrypt(nonce, ciphertext, _aad(session_id, chunk_index))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
