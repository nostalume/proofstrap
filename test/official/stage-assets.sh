#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { printf 'usage: %s OUTPUT_DIR\n' "$0" >&2; exit 2; }
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output=$1
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM

mkdir "$output"
go -C "$root" build -trimpath -buildvcs=true -o "$temporary/proofstrap-pack" ./cmd/proofstrap-pack
"$temporary/proofstrap-pack" build --input "$root/profiles/core" --output "$output/core.pstrap" >/dev/null
"$temporary/proofstrap-pack" build --input "$root/profiles/linux" --output "$output/linux.pstrap" >/dev/null
(cd "$output" && sha256sum core.pstrap linux.pstrap > checksums.txt)
cmp "$root/release/packs.sha256" "$output/checksums.txt"
