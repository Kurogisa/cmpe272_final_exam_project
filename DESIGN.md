# CMPE 272 — Secure Transfer: Design & Threat Model

This document complements **README.md** with architecture, algorithms, CIAA mapping, and explicit threat-model mitigations.

---

## 1. Architecture (ASCII)

### Approach A — mutual TLS streaming (direct peer)

```
  +-----------+                      +-----------+
  |  SENDER   |  TCP + TLS 1.3       | RECEIVER  |
  | (client)  |  mTLS + AEAD records | (server)  |
  +-----+-----+                      +-----+-----+
        |                                  |
        |  OPEN / CHUNK / EOF frames      |
        |  (length-prefixed app protocol)  |
        v                                  v
   [read file                  [write *.partial
    in chunks]                  verify SHA-256]
        |                                  |
        +---------- loopback 127.0.0.1 -----+
```

**Trust boundary:** the TLS channel between authenticated endpoints. No third-party storage.

### Approach B — envelope encryption + untrusted broker

```
  +-----------+   ciphertext +    +-----------+   ciphertext +    +-----------+
  |  SENDER   |   framed PUT    |  BROKER    |   framed GET    |  RECEIVER  |
  | encrypt   +---------------->| store only +---------------->| decrypt    |
  | sign man. |   TCP (EVB2)    | no DEK     |   TCP (EVB2)    | verify man.|
  +-----------+                 +-----------+                 +-----------+
        |                             |                             |
        +-- AES-256-GCM (DEK)         |         RSA-OAEP unwrap DEK +
            RSA-OAEP wrap DEK         |         RSA-PSS verify manifest
            RSA-PSS sign manifest      |         AES-GCM decrypt chunks
```

**Trust boundary:** broker is **untrusted for confidentiality** (must not learn plaintext or DEK) and **untrusted for integrity** (must not undetectably alter ciphertext/manifest).

---

## 2. CIAA mapping

| Property | Approach A | Approach B |
|----------|------------|------------|
| **Confidentiality** | TLS 1.3 negotiated **AEAD** (e.g. AES-256-GCM or ChaCha20-Poly1305) on the wire; passive eavesdropper on the path sees ciphertext only. | **AES-256-GCM** on file chunks; **DEK** wrapped to receiver RSA-OAEP inside **signed** manifest; broker stores ciphertext only. |
| **Integrity** | TLS record authentication + application **SHA-256** over the full plaintext byte stream; chunk framing is **contiguous** (no sparse skip attacks). | Per-chunk **GCM tag** + **SHA-256** of each ciphertext in manifest + **SHA-256** of each plaintext chunk + **full-file SHA-256**; manifest **RSA-PSS-SHA256**. |
| **Authenticity** | **Mutual TLS**: both peers present X.509 certs validated under a shared **CA** (`CERT_REQUIRED`, no verification bypass). | **RSA-PSS** manifest signature (sender key) + **RSA-OAEP** DEK wrapping to receiver public key; receiver holds private unwrap key. |
| **Availability** | **Resume** via session-scoped partial file + meta; configurable socket timeouts; clear partial state on cryptographic failure. | **Resume** upload (broker LIST + sidecar) and **resume** download (sidecar + partial); broker uses idempotent chunk PUT; timeouts configurable. |

**Fail-closed:** any verification failure (TLS, AEAD decrypt, PSS verify, OAEP unwrap, chunk hash, full-file hash, size mismatch) → **non-zero exit**, unsafe partial files removed or not promoted to final names.

---

## 3. Exact algorithms & parameters

| Mechanism | Where | Library / standard |
|-----------|--------|---------------------|
| **TLS 1.3** (preferred), TLS ≥ 1.2 floor | Approach A | CPython `ssl` → OpenSSL |
| **ECDHE** key exchange | Approach A (TLS 1.3 default) | OpenSSL negotiation |
| **TLS AEAD** (e.g. **TLS_AES_256_GCM_SHA384**) | Approach A records | OpenSSL |
| **AES-256-GCM** | Approach B chunks | `cryptography` `AESGCM` |
| **SHA-256** | Full file + chunk digests (B), incremental full hash (A) | `hashlib` |
| **RSA-OAEP** with **SHA-256** + **MGF1-SHA256** | Approach B DEK wrap (receiver + sender-resume wrap) | `cryptography` asymmetric padding |
| **RSA-PSS** with **SHA-256**, salt = digest length | Approach B manifest signature | `cryptography` |
| **X.509** mutual auth | Approach A | `ssl` + PEM chains |
| **Deterministic GCM nonce** (`derived_v1`) | Approach B | `SHA-256("EVB2-GCM-v1" \|\| session_id \|\| BE64(chunk_index))[:12]` |

**Approach B AAD for GCM:** `b"EVB2" || session_id(16) || chunk_index(uint64 BE)`.

---

## 4. Chunk size rationale

- **Default 1 MiB (`1048576` bytes)** balances syscall/TLS framing overhead and **bounded RAM** per iteration (read buffer + ciphertext/tag).
- Upper bounds exist in code to limit malicious **frame sizes** (DoS on a single connection).
- **4 GiB** at 1 MiB ⇒ **4096** chunks (order-of-magnitude for test planning).

---

## 5. Replay protection (Approach B)

- Manifest includes **`issued_at_unix_ms`**.
- Receiver rejects manifests **too old** (`--max-manifest-age-sec`, default **604800** = 7 days) and **too far in the future** (`--clock-skew-sec`, default **300** s) relative to local wall time.
- **Limitation:** this is **soft replay protection** (policy window), not a nonce-based online protocol replay cache. Tighten windows for demos; for production, add session tickets stored by receiver or use a short-lived manifest token.

---

## 6. Forward secrecy

| Topic | Approach A | Approach B |
|-------|------------|------------|
| **In transit** | TLS 1.3 with **ECDHE** provides **forward secrecy for the channel** per connection (past ciphertext on the wire is hard to decrypt after ephemeral DH secrets are gone). | TCP to broker is **not modeled as confidential** beyond ciphertext; FS for **file ciphertext at rest** is **not** provided by RSA-OAEP wrapping of a static DEK for archived blobs if the **receiver long-term private key** is later compromised (attacker could unwrap historical DEKs from stored manifests). |
| **Mitigation / honesty** | Rely on TLS 1.3 defaults; log negotiated cipher. | If archival FS against receiver key compromise is required, use an ephemeral KEM (e.g. HPKE) or per-session ephemeral ECDH to derive DEK, at higher complexity. |

---

## 7. Why the broker cannot read plaintext

1. The broker never receives the **DEK** in plaintext: it only stores **RSA-OAEP ciphertext** of the DEK inside the **signed manifest**, and the receiver’s **private** key is required to unwrap.
2. File body on disk at the broker is **AES-GCM ciphertext**; without the DEK, the broker cannot decrypt.
3. The **manifest integrity** is bound by **RSA-PSS** under the **sender’s** signing key; a malicious broker cannot forge a new manifest that passes verification without the sender’s private key.

**Transport caveat:** the lab broker protocol is **cleartext TCP on loopback**. An attacker who can read loopback could read **ciphertext and signed manifests**, not plaintext, unless they also break AES-GCM or steal private keys.

---

## 8. Why fail-closed behavior matters

- **Silent partial acceptance** would violate integrity and availability expectations: users could assume a file is complete when it is truncated or wrong.
- **Promotion without verification** (e.g. renaming before hash check) would allow **undetected corruption or attack**.
- This project **deletes or withholds final output** on failure and exits non-zero so automation and humans cannot mistake a bad state for success.

---

## 9. Threat model table

| Threat | Approach A mitigations | Approach B mitigations |
|--------|------------------------|-------------------------|
| **Passive eavesdrop (on path)** | TLS AEAD ciphertext; no plaintext on wire. | Ciphertext chunks + wrapped DEK on wire; still no plaintext without keys. |
| **MITM modify bytes in flight** | TLS **MAC/AEAD** rejects tampered records; app **SHA-256** rejects wrong file. | Chunk **GCM** failure or hash mismatch; manifest **PSS** detects manifest tampering. |
| **Spoofed sender** | mTLS: receiver requires valid **client cert** issued under CA. | Manifest **PSS** verifies with configured **sender public** key. |
| **Spoofed receiver** | mTLS: sender validates **server cert** + hostname/SAN policy. | Only holder of **receiver private** key unwraps DEK; wrong key ⇒ unwrap failure. |
| **Replay attack** | Resumption is bound to **session id** + partial file state; new transfers use new session ids. | Manifest **timestamp window**; session-scoped chunk namespace (`session_id` in paths). |
| **Interrupted transfer** | Partial file + meta; resume with same session id; hash rebuilt from prefix on resume (**O(bytes received)** read tradeoff). | Sender resume via broker **LIST** + sidecar; receiver resume via partial + sidecar; broker stores durable ciphertext. |
| **Malicious broker** | N/A (no broker). | Cannot derive plaintext without DEK; cannot forge manifest without **sender sign** key; swapping chunk bytes detected by **ciphertext hash** vs manifest (and GCM tag on decrypt). |

---

## 10. Interrupted transfer & resumability (summary)

| System | Local artifacts | Resume mechanism | Notable tradeoff |
|--------|-----------------|------------------|------------------|
| **A** | `{session}.partial`, `{session}.meta.json` under `--output-dir` | Same `--session-id`, compatible OPEN fields | Re-hash of partial prefix on receiver may re-read disk. |
| **B** | Sender: `*.bupload.json`; Receiver: `*.bdownload.json`, `*.<session>.partial` | `--resume` + same keys/input/output policy | Deterministic nonces to avoid storing ciphertext in sender sidecar; **RSA-OAEP** archival FS caveat above. |

---

## 11. Simplifications (explicit)

1. **Loopback-only demos** reduce exposure but **do not remove** the need for correct crypto (verification stays on).
2. **Approach B broker TCP** is not wrapped in TLS; justified for a local lab where the graded property is **end-to-end ciphertext to the broker**, not link encryption to the broker process.
3. **Clock-based replay policy** in Approach B depends on reasonable local time; VMs should use NTP for meaningful windows.

---

## References in repo

- Approach A: `approach-a-mtls-stream/common/protocol.py`, `common/tls_context.py`
- Approach B: `approach-b-envelope-broker/common/manifest.py`, `common/chunk_crypto.py`, `common/broker_protocol.py`
