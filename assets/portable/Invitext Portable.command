#!/bin/sh
set -eu

portable_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$portable_dir"
chmod +x ./itx ./invitext 2>/dev/null || true
PATH="$portable_dir:$PATH"
export PATH

printf '\n  Invitext Portable\n'
printf '  Folder: %s\n\n' "$portable_dir"
printf '  Try: itx --help\n'
printf '  Example: itx inspect photo.jpg\n\n'

exec "${SHELL:-/bin/sh}" -i
