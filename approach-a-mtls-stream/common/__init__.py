"""
Shared helpers for Approach A (mutual TLS streaming transfer).

Security-sensitive logic (framing, TLS context construction) lives in
submodules so sender.py and receiver.py stay thin and auditable.
"""
