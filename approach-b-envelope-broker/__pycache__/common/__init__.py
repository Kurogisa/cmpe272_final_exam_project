"""
Shared helpers for Approach B (envelope encryption + untrusted broker).

The broker is assumed malicious with respect to confidentiality and availability;
cryptographic binding and verification live here and in the CLI entrypoints.
"""
