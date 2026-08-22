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
mkdir "$temporary/download" "$temporary/assets"

for name in core.pstrap linux.pstrap checksums.txt; do curl -fsSL --retry 3 -o "$temporary/download/$name" "$base/$name"; done
cmp "$root/release/packs.sha256" "$temporary/download/checksums.txt"
(cd "$temporary/download" && sha256sum --check --status checksums.txt)
core=$(sed -n '1s/  core\.pstrap$//p' "$root/release/packs.sha256")
linux=$(sed -n '2s/  linux\.pstrap$//p' "$root/release/packs.sha256")
mkdir -p "$temporary/assets/packs/sha256"
cp "$temporary/download/core.pstrap" "$temporary/assets/packs/sha256/$core.pstrap"
cp "$temporary/download/linux.pstrap" "$temporary/assets/packs/sha256/$linux.pstrap"
printf 'schema = 2\n\nbindings = ["linux"]\nprofiles = [{ profile = "core:bootstrap-cli" }]\n\n[sources]\ncore = "sha256:%s"\nlinux = "sha256:%s"\n' \
  "$core" "$linux" > "$temporary/assets/proofstrap.toml"
(cd "$temporary/assets" && LC_ALL=C find packs/sha256 proofstrap.toml -type f -print | LC_ALL=C sort | xargs sha256sum > checksums.txt)
mv "$temporary/assets" "$output"
