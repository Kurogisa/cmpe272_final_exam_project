# Demo walkthrough (2–3 minute style)

Use this script for a **screen recording** or **live demo**. Paths assume a **macOS/Linux** shell and a clone at **`$REPO`** — set it to your machine (example: `export REPO="$HOME/cmpe272_final"`).

**Prerequisites:** `python3.12`, `openssl` (for certs), ~**4 GiB free disk** for the test file, venv with `pip install -r requirements.txt`, certs under Approach A, keys under Approach B (see root `README.md`).

**Recording tips:** use a large terminal font; run `ls -lh` on the 4 GiB file before/after; keep **hash output on screen**; for Approach B, briefly show `ls broker_data/<session>/` with `manifest.json` visible.

**Line-by-line script:** for a single document from “start recording” through both hashes (with **Say:** / **Run:** cues), use **`RECORDING_SCRIPT.md`** in the repo root.

---

## 0) One-time environment (show once at start of recording)

```bash
export REPO="$HOME/cmpe272_final"    # <-- change to your clone path
cd "$REPO"
source .venv/bin/activate
chmod +x scripts/gen_4gb_file.sh scripts/verify_hash.sh scripts/approach_a_gen_certs.sh
```

If certs/keys are missing:

```bash
./scripts/approach_a_gen_certs.sh
python scripts/approach_b_gen_keys.py --out-dir approach-b-envelope-broker/keys
```

---

## 1) Create the 4 GiB file (same file for both approaches)

Creates **4096 × 1 MiB = 4 GiB** via `dd` (does not load into Python RAM):

```bash
./scripts/gen_4gb_file.sh /tmp/large4g.bin
ls -lh /tmp/large4g.bin
```

**Note:** This can take **several minutes** depending on disk speed. You can **start recording after** this step finishes to keep the video under 2–3 minutes, or speed up the video editor for the `dd` segment.

---

## 2) Approach A — mutual TLS (receiver then sender)

**Terminal 1 — receiver** (keep running; `--overwrite` avoids “destination exists” on repeat demos):

```bash
cd "$REPO/approach-a-mtls-stream"
source "$REPO/.venv/bin/activate"
mkdir -p /tmp/demo272_a_out
python receiver.py --cert certs/server.crt --key certs/server.key --client-ca certs/ca.crt \
  --output-dir /tmp/demo272_a_out --overwrite -v
```

Wait for: `listening on 127.0.0.1:27201`

**Terminal 2 — sender:**

```bash
cd "$REPO/approach-a-mtls-stream"
source "$REPO/.venv/bin/activate"
python sender.py --cert certs/client.crt --key certs/client.key --ca certs/ca.crt \
  --input /tmp/large4g.bin --chunk-size 1048576 -v
```

Wait for: `transfer complete` and receiver `transfer OK`.

**Verify hash (any terminal):**

```bash
shasum -a 256 /tmp/large4g.bin /tmp/demo272_a_out/large4g.bin
# Expect: two identical hashes on two lines
```

Optional:

```bash
"$REPO/scripts/verify_hash.sh" /tmp/large4g.bin /tmp/demo272_a_out/large4g.bin
```

**Narration cue:** mention **TLS 1.3** + **AES-GCM-class** cipher in the sender log, **mTLS**, and **SHA-256 match**.

---

## 3) Approach B — broker + envelope (broker → sender → receiver)

**Terminal 1 — broker** (fresh `broker_data` for a clean story):

```bash
cd "$REPO/approach-b-envelope-broker"
source "$REPO/.venv/bin/activate"
rm -rf broker_data && mkdir broker_data
python broker_server.py --host 127.0.0.1 --port 27202 --data-dir ./broker_data -v
```

**Terminal 2 — sender:**

```bash
cd "$REPO/approach-b-envelope-broker"
source "$REPO/.venv/bin/activate"
python sender_encrypt_upload.py --broker-host 127.0.0.1 --broker-port 27202 \
  --input /tmp/large4g.bin \
  --receiver-public keys/receiver_rsa_public.pem \
  --sender-private keys/sender_rsa_private.pem \
  --chunk-size 1048576 -v
```

Wait for: `manifest published`. In the log, copy the **32 hex character** `session_id` (from the line `session_id=...` only — not the placeholder text).

**Quick way to list the session folder name** (must match what the broker wrote):

```bash
ls "$REPO/approach-b-envelope-broker/broker_data/"
```

Use that directory name as `SESSION_HEX` below.

**Terminal 3 — receiver:**

```bash
mkdir -p /tmp/demo272_b_out
cd "$REPO/approach-b-envelope-broker"
source "$REPO/.venv/bin/activate"
python receiver_download_decrypt.py --broker-host 127.0.0.1 --broker-port 27202 \
  --session-id SESSION_HEX \
  --receiver-private keys/receiver_rsa_private.pem \
  --sender-public keys/sender_rsa_public.pem \
  --output /tmp/demo272_b_out/large4g.bin -v
```

Replace **`SESSION_HEX`** with the **actual** 32-character folder name from `broker_data/` (same value as in the sender log).

**Verify hash:**

```bash
shasum -a 256 /tmp/large4g.bin /tmp/demo272_b_out/large4g.bin
"$REPO/scripts/verify_hash.sh" /tmp/large4g.bin /tmp/demo272_b_out/large4g.bin
```

**Narration cue:** broker only has **ciphertext** + **signed manifest**; receiver verifies **RSA-PSS** then **AES-GCM** decrypt; hashes match source.

**Stop broker:** Terminal 1 → **Ctrl+C**.

---

## 4) Optional B-roll for the grader

Show manifest presence (use the same session folder name you used for `receiver_download_decrypt.py`):

```bash
ls "$REPO/approach-b-envelope-broker/broker_data/YOUR_SESSION_HEX/"
```

Expected: `manifest.json`, `manifest.sig`, `chunk_*.bin` files.

---

## 5) If you are short on time

- Pre-generate `/tmp/large4g.bin` **before** recording.
- Record **only**: hash proof for A, then cut, then hash proof for B (same source file).
- State aloud: file size is **4 GiB**, same input path for both approaches, **SHA-256 match** proves byte-identical delivery.
