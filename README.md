# CMPE 272 — Secure 4GB File Transfer (Two Architectures)

Graduate-level project: **two architecturally distinct** designs that stream a large file over **TCP on loopback** with **CIAA** goals (confidentiality, integrity, authenticity, availability), **no full-file RAM buffering**, **AEAD-only** payload cryptography, **mutual or cryptographic endpoint authentication**, **fail-closed** verification, and **SHA-256** of the delivered plaintext.

| Approach | Folder | Idea |
|----------|--------|------|
| **A — mTLS streaming** | `approach-a-mtls-stream/` | Direct sender→receiver over **mutual TLS**; TLS record **AEAD** protects bytes in flight; app protocol adds **chunk framing + final SHA-256**. |
| **B — envelope + broker** | `approach-b-envelope-broker/` | Sender **encrypts first** (AES-256-GCM); **broker stores ciphertext only**; **signed manifest** binds metadata; receiver verifies signature then decrypts. |

See **DESIGN.md** for diagrams, algorithms, threat model, and tradeoffs. See **AI_NOTES.md** for ports, secret paths, common grading pitfalls, and **AI use (Section 8)**. See **DEMO.md** for setup detail. For a **line-by-line recording script** (narration + commands from start to end), see **RECORDING_SCRIPT.md**.

---

## Requirements

- **Python 3.12**
- **OpenSSL** CLI (for Approach A certificate generation only)
- Dependencies: `requirements.txt` (`cryptography`; stdlib `ssl`, `socket`, `hashlib`, etc.)

---

## Installation

From the repository root:

```bash
python3.12 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Approach A — mutual TLS streaming

### 1) Generate certificates (once per machine / lab)

```bash
chmod +x scripts/approach_a_gen_certs.sh
./scripts/approach_a_gen_certs.sh
```

Artifacts land in `approach-a-mtls-stream/certs/` (`ca.crt`, `server.crt`+`server.key` for the **receiver**, `client.crt`+`client.key` for the **sender**). The script refuses to overwrite existing keys; delete that directory first to regenerate.

### 2) Create a 4GB test file (does not load 4GB into Python)

```bash
chmod +x scripts/gen_4gb_file.sh
./scripts/gen_4gb_file.sh ./large4g.bin
```

This uses `dd` and streams from the OS; adjust the script if you prefer another method.

### 3) Run receiver (TLS server), then sender (TLS client)

**Receiver** (listens on `127.0.0.1:27201` by default). Add **`--overwrite`** if the destination file might already exist from an earlier run (otherwise the receiver rejects the transfer with “destination exists”):

```bash
cd approach-a-mtls-stream
python receiver.py \
  --cert certs/server.crt --key certs/server.key \
  --client-ca certs/ca.crt \
  --output-dir /path/to/outdir --overwrite -v
```

**Sender**:

```bash
cd approach-a-mtls-stream
python sender.py \
  --cert certs/client.crt --key certs/client.key \
  --ca certs/ca.crt \
  --input /path/to/large4g.bin \
  --chunk-size 1048576 -v
```

The sender logs **`session_id=...`** (32 hex chars). To **resume** after interruption, rerun the **receiver** (new listen/accept), then the **sender** with the same session id:

```bash
python sender.py ... --session-id <HEX_FROM_LOG> ...
```

The receiver keeps `{session}.partial` + `{session}.meta.json` under `--output-dir` until the transfer completes and passes SHA-256.

### Hash verification (Approach A)

```bash
shasum -a 256 /path/to/large4g.bin /path/to/outdir/<remote-basename>
# or:
./scripts/verify_hash.sh /path/to/large4g.bin /path/to/outdir/<remote-basename>
```

### Throughput (Approach A)

After a successful run, the sender logs **effective application-layer MiB/s** (wall clock, full file size). For stable numbers, avoid competing CPU load; chunk size defaults to **1 MiB** (`--chunk-size`).

### Resumability (Approach A)

- **Requires** the same `--session-id` on the sender and compatible partial state on the receiver (`*.partial` + `*.meta.json` under `--output-dir`).
- **Tradeoff:** on resume, the implementation may **re-read the already-received prefix** from disk to rebuild the incremental SHA-256 state (documented in DESIGN.md).
- Chunks are **contiguous by byte offset**; gaps or reordering fail closed.

---

## Approach B — encrypted envelope + broker

### 1) Generate RSA key material (once)

```bash
python scripts/approach_b_gen_keys.py --out-dir approach-b-envelope-broker/keys
```

Produces `receiver_rsa_{private,public}.pem` and `sender_rsa_{private,public}.pem`. The script refuses to overwrite existing PEMs in that folder.

### 2) Start the broker (stores ciphertext only)

```bash
cd approach-b-envelope-broker
python broker_server.py --host 127.0.0.1 --port 27202 \
  --data-dir ./broker_data -v
```

### 3) Sender, then receiver

**Sender** (encrypt + upload chunks + signed manifest):

```bash
python sender_encrypt_upload.py \
  --broker-host 127.0.0.1 --broker-port 27202 \
  --input /path/to/large4g.bin \
  --receiver-public keys/receiver_rsa_public.pem \
  --sender-private keys/sender_rsa_private.pem \
  --chunk-size 1048576 -v
```

Logs **`session_id=...`** and a **resume hint** line. A sidecar `*.bupload.json` is written next to the input (or `--state-path`) and contains **wrapped key material** — treat it as **secret**.

**Receiver** (download + verify + decrypt):

```bash
python receiver_download_decrypt.py \
  --broker-host 127.0.0.1 --broker-port 27202 \
  --session-id <HEX> \
  --receiver-private keys/receiver_rsa_private.pem \
  --sender-public keys/sender_rsa_public.pem \
  --output /path/to/out.bin -v
```

### Hash verification (Approach B)

```bash
shasum -a 256 /path/to/large4g.bin /path/to/out.bin
./scripts/verify_hash.sh /path/to/large4g.bin /path/to/out.bin
```

### Throughput (Approach B)

The receiver logs **MiB/s** after successful decrypt and rename. End-to-end time includes broker I/O and crypto.

### Resumability (Approach B)

- **Sender:** `--resume --session-id <HEX>` with the same input path, chunk size, and sidecar. Recomputes deterministic ciphertext for each chunk and **GETs** existing broker chunks to detect tampering before skipping re-upload.
- **Receiver:** `--resume` uses `*.bdownload.json` and a session-scoped partial file `*.<session>.partial`; requires the partial to cover the completed prefix.
- **Replay control:** manifest `issued_at_unix_ms` is checked against `--max-manifest-age-sec` (default 7 days) and `--clock-skew-sec`.

---

## Ports (defaults)

| Component | Default port |
|-----------|----------------|
| Approach A receiver | `27201` |
| Approach B broker | `27202` |

Change with `--port` / `--broker-port` if needed.

---

## Project layout

```
requirements.txt
README.md
DESIGN.md
AI_NOTES.md
DEMO.md
RECORDING_SCRIPT.md
scripts/
  approach_a_gen_certs.sh
  approach_b_gen_keys.py
  gen_4gb_file.sh
  verify_hash.sh
  openssl-a-server.ext
  openssl-a-client.ext
approach-a-mtls-stream/
  sender.py
  receiver.py
  common/
approach-b-envelope-broker/
  broker_server.py
  sender_encrypt_upload.py
  receiver_download_decrypt.py
  common/
```

---

## Security notes (short)

- **No custom cryptography** — TLS / AES-GCM / RSA-OAEP / RSA-PSS via **cryptography** and CPython **ssl**.
- **Fail closed:** TLS verify failures, AEAD/tag failures, hash mismatches, and manifest/signature failures cause **non-zero exit** and cleanup of unsafe partial outputs (see DESIGN.md).
- **Approach B broker path** is **not** TLS-wrapped in this lab build; confidentiality of the file still rests on **AES-GCM ciphertext** and **RSA-OAEP–wrapped DEK** held only in the signed manifest.

For full threat-model and CIAA mapping, read **DESIGN.md**.
