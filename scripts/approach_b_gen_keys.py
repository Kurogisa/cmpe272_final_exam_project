#!/usr/bin/env python3
"""
Generate RSA key material for Approach B (envelope + broker).

- receiver_rsa_{private,public}.pem — RSA-OAEP unwrap (receiver) / wrap (sender)
- sender_rsa_{private,public}.pem — RSA-PSS manifest signatures (sender) / verify (receiver)

Uses the cryptography library only (no openssl CLI required).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _write_pem(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.chmod(0o600)
    tmp.replace(path)


def main() -> int:
    p = argparse.ArgumentParser(description="Generate Approach B RSA keypairs (4096-bit).")
    p.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "approach-b-envelope-broker" / "keys",
    )
    args = p.parse_args()
    out = args.out_dir
    if any((out / f).exists() for f in ("receiver_rsa_private.pem", "sender_rsa_private.pem")):
        print(f"Refusing to overwrite existing keys under {out}", flush=True)
        return 1

    print(f"[+] Writing keys to {out}", flush=True)

    receiver_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    sender_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    for name, key in (("receiver_rsa", receiver_key), ("sender_rsa", sender_key)):
        priv_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _write_pem(out / f"{name}_private.pem", priv_pem)
        _write_pem(out / f"{name}_public.pem", pub_pem)

    print("[+] receiver_rsa_* — receiver keeps private; sender needs public for DEK wrapping.")
    print("[+] sender_rsa_* — sender keeps private; receiver needs public for manifest verification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
