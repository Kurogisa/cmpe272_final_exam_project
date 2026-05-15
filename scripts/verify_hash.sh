#!/usr/bin/env bash
# Compare SHA-256 of two files (fail-closed on mismatch).
# Usage: ./scripts/verify_hash.sh <file_a> <file_b>
set -euo pipefail

A="${1:-}"
B="${2:-}"
if [[ -z "${A}" || -z "${B}" ]]; then
  echo "usage: $0 <file_a> <file_b>" >&2
  exit 2
fi

HA="$(shasum -a 256 "${A}" | awk '{print $1}')"
HB="$(shasum -a 256 "${B}" | awk '{print $1}')"
echo "${A}  ${HA}"
echo "${B}  ${HB}"
if [[ "${HA}" != "${HB}" ]]; then
  echo "MISMATCH (fail-closed)" >&2
  exit 1
fi
echo "OK: digests match"
