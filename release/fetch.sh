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
mkdir "$temporary/download" "$temporary/extract"

archive=proofstrap-core-profiles.tar.gz
for name in "$archive" checksums.txt; do curl -fsSL --retry 3 -o "$temporary/download/$name" "$base/$name"; done
cmp "$root/release/catalogue.sha256" "$temporary/download/checksums.txt"
(cd "$temporary/download" && sha256sum --check --status checksums.txt)
tar -xzf "$temporary/download/$archive" -C "$temporary/extract" --strip-components=1 --no-same-owner
(cd "$temporary/extract" && sha256sum --check --status checksums.txt)
mv "$temporary/extract" "$output"
