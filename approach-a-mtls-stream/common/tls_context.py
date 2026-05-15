"""
Mutual TLS context factories for Approach A.

All certificate verification stays enabled (CERT_REQUIRED). Self-signed lab
chains are carried by a shared CA file; hostnames are validated against SANs.
"""

from __future__ import annotations

import logging
import ssl
from pathlib import Path

logger = logging.getLogger(__name__)


def build_server_context(
    *,
    certfile: Path,
    keyfile: Path,
    client_cafile: Path,
) -> ssl.SSLContext:
    """
    Receiver (TLS server): authenticate clients with certs issued by CA.

    client_cafile should be the same CA that issued client certificates.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(client_cafile))
    # Require client certificate on the TLS handshake.
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    return ctx


def build_client_context(
    *,
    certfile: Path,
    keyfile: Path,
    cafile: Path,
) -> ssl.SSLContext:
    """
    Sender (TLS client): validate server cert against CA; present client cert.

    Pass server_hostname= to SSLContext.wrap_socket for SNI + name verification.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(cafile))
    ctx.check_hostname = True
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    return ctx


def log_ssl_cipher(sock: ssl.SSLSocket) -> None:
    """Post-handshake diagnostics (cipher suite, TLS version)."""
    try:
        cipher = sock.cipher()
        version = sock.version()
        logger.info("TLS established: version=%s cipher=%s", version, cipher)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Could not read TLS parameters: %s", exc)
