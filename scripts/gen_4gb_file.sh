#!/usr/bin/env bash
# Create a 4GiB file without loading it into RAM (uses dd streaming).
# Usage: ./scripts/gen_4gb_file.sh <output_path>
set -euo pipefail

OUT="${1:-}"
if [[ -z "${OUT}" ]]; then
  echo "usage: $0 <output_path>" >&2
  exit 2
fi

# 4096 * 1 MiB = 4 GiB
BS=1M
COUNT=4096

echo "Writing ${COUNT} x ${BS} = 4 GiB to ${OUT} ..." >&2
dd if=/dev/zero of="${OUT}" bs="${BS}" count="${COUNT}" status=progress conv=fsync
echo "Done: ${OUT}" >&2
