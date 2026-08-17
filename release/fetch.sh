#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { printf 'usage: %s OUTPUT_DIR\n' "$0" >&2; exit 2; }
output=$1
[ ! -e "$output" ] || { printf 'output already exists: %s\n' "$output" >&2; exit 1; }

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(cat "$root/release/catalogue-version")
base="https://github.com/nostalume/proofstrap-core-profiles/releases/download/$version"
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
mkdir "$temporary/assets"

for name in core.pstrap linux.pstrap checksums.txt; do
  curl -fsSL --retry 3 -o "$temporary/assets/$name" "$base/$name"
done
cmp "$root/release/packs.sha256" "$temporary/assets/checksums.txt"
(cd "$temporary/assets" && sha256sum --check --status checksums.txt)
mv "$temporary/assets" "$output"
