# AI_NOTES.md

Notes for humans and AI assistants working on this repository.

## Intent

Two **architecturally different** secure file-transfer designs for CMPE 272:

1. **Approach A** — Streaming over **mutual TLS** (channel security + incremental SHA-256).
2. **Approach B** — **Encrypt-then-store** with an **untrusted broker** + **signed manifest** (object security).

Neither approach loads a 4GB file fully into RAM; both use **chunked streaming**.

## Where to look

| Topic | Location |
|-------|----------|
| A: TLS policy | `approach-a-mtls-stream/common/tls_context.py` |
| A: Framing, resume, SHA-256 | `approach-a-mtls-stream/common/protocol.py` |
| A: CLIs | `sender.py`, `receiver.py` |
| A: Certs | `scripts/approach_a_gen_certs.sh`, `scripts/openssl-a-*.ext` |
| B: Manifest + RSA helpers | `approach-b-envelope-broker/common/manifest.py` |
| B: AES-GCM + deterministic nonce | `approach-b-envelope-broker/common/chunk_crypto.py` |
| B: Wire format | `approach-b-envelope-broker/common/broker_protocol.py`, `broker_client.py` |
| B: CLIs | `sender_encrypt_upload.py`, `receiver_download_decrypt.py`, `broker_server.py` |
| B: Keys | `scripts/approach_b_gen_keys.py` → `approach-b-envelope-broker/keys/` |

## Ports

- **27201** — Approach A default.
- **27202** — Approach B broker default.

## Secrets & artifacts (never commit)

- `approach-a-mtls-stream/certs/` — private keys.
- `approach-b-envelope-broker/keys/` — RSA private PEMs.
- `approach-b-envelope-broker/broker_data/` — ciphertext staging.
- `*.bupload.json` — contains **wrapped DEKs** (sender sidecar).
- `*.partial`, `*.meta.json`, `*.bdownload.json` — transfer state.

`.gitignore` already excludes most of these.

## Common grading pitfalls

1. **Approach A receiver** accepts **one connection per process** then exits; for a new transfer, restart `receiver.py`.
2. **Session IDs** must match between resume attempts; Approach A logs hex on first sender run.
3. **Approach B** sender logs `session_id` on two lines to keep hex parseable for scripts.
4. **Verification** must use the same `shasum -a 256` (or `scripts/verify_hash.sh`) on **plaintext** paths after successful completion.

## Allowed crypto stack

- **cryptography** library for RSA/AES-GCM (Approach B) and any PEM parsing.
- **ssl** / **socket** for Approach A TLS.
- **hashlib**, **hmac** (if used), **pathlib**, **argparse** — stdlib.

Do **not** add hand-rolled ciphers, CBC-only MAC-less modes, or nonce reuse.

## Section 8 — AI use (course disclosure — edit in your own words)

This section satisfies typical **“Section 8”** style requirements: disclose how AI tools were used and what **you** validated.

**Tooling (fill in):** I used **[e.g. Cursor with Claude / ChatGPT / other]** while building this project.

**What the AI helped with (examples — adjust to truth):**

- High-level **architecture split** (mTLS streaming vs envelope + broker) and **directory layout**.
- **Boilerplate and structure** for Python CLIs, framing, and documentation (`README.md`, `DESIGN.md`).
- **Debugging** when integrating OpenSSL-generated certs, TLS hostname checks, and broker framing.

**What I did myself / must remain responsible for (examples — adjust to truth):**

- Ran **every end-to-end test** on my machine: **Approach A** (`receiver.py` / `sender.py`) and **Approach B** (`broker_server.py` / `sender_encrypt_upload.py` / `receiver_download_decrypt.py`).
- Verified **SHA-256** matches between source and output using `shasum -a 256` or `scripts/verify_hash.sh`.
- Read **critical security paths** (TLS verify modes, AEAD usage, fail-closed branches, no nonce reuse) and aligned them with the course threat model.
- Recorded the **demo** (see **DEMO.md**) showing **4 GiB** (or course-specified size) and hash verification for **both** approaches.

**Academic integrity:** AI suggestions were **reviewed, tested, and understood** before submission. Any errors remaining are my responsibility.

**Instructor-specific:** If your syllabus defines “Section 8” differently, paste their exact bullets here and tick them off.

## Extending safely

- **Approach A:** TLS to broker is orthogonal; if added, still keep **chunk AEAD semantics** in B and **app-level SHA-256** in A unless explicitly redesigned.
- **Approach B:** Replacing RSA-OAEP DEK wrap with **HPKE** would improve archival FS story; update DESIGN.md and manifest schema together.
