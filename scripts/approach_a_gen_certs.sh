#!/usr/bin/env bash
# Generate a private CA and mutual-TLS certificate pairs for Approach A.
# Requires OpenSSL 1.1.1+ (macOS Homebrew: brew install openssl).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/approach-a-mtls-stream/certs"
mkdir -p "${OUT}"
cd "${OUT}"

if [[ -f ca.key ]] || [[ -f server.key ]] || [[ -f client.key ]]; then
  echo "Refusing to overwrite existing keys in ${OUT}. Remove files first if you intend to regenerate." >&2
  exit 1
fi

OPENSSL="${OPENSSL:-openssl}"

echo "[+] Generating CA (4096-bit RSA)..."
"${OPENSSL}" genrsa -out ca.key 4096
"${OPENSSL}" req -new -x509 -days 825 -key ca.key -out ca.crt \
  -subj "/O=CMPE272/OU=Approach-A/CN=Approach-A-Dev-CA"

echo "[+] Generating server (receiver) key + certificate (localhost SAN)..."
"${OPENSSL}" genrsa -out server.key 4096
"${OPENSSL}" req -new -key server.key -out server.csr \
  -subj "/O=CMPE272/OU=Approach-A/CN=localhost"
"${OPENSSL}" x509 -req -days 825 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -copy_extensions none \
  -extfile "${ROOT}/scripts/openssl-a-server.ext"

echo "[+] Generating client (sender) key + certificate..."
"${OPENSSL}" genrsa -out client.key 4096
"${OPENSSL}" req -new -key client.key -out client.csr \
  -subj "/O=CMPE272/OU=Approach-A/CN=mtls-sender-client"
"${OPENSSL}" x509 -req -days 825 -in client.csr -CA ca.crt -CAkey ca.key \
  -CAserial ca.srl -out client.crt \
  -extfile "${ROOT}/scripts/openssl-a-client.ext"

chmod 600 ca.key server.key client.key
rm -f server.csr client.csr

echo "[+] Wrote material under: ${OUT}"
echo "    CA:       ca.crt   (trust anchor for both peers)"
echo "    Receiver: server.crt + server.key"
echo "    Sender:   client.crt + client.key"
