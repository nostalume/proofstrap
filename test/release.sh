#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { printf 'usage: %s DIST_DIR\n' "$0" >&2; exit 2; }
dist=$(CDPATH= cd -- "$1" && pwd); temporary=$(mktemp -d); trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM

[ "$(find "$dist" -mindepth 1 -maxdepth 1 | wc -l)" -eq 6 ] && (cd "$dist" && sha256sum --check --status checksums.txt && cut -d ' ' -f3- checksums.txt | LC_ALL=C sort -c)

check_members() {
  tar -tzf "$1" | LC_ALL=C sort > "$temporary/actual"; shift
  printf '%s\n' "$@" | LC_ALL=C sort > "$temporary/expected"
  cmp "$temporary/expected" "$temporary/actual"
}

for arch in amd64 arm64; do
  name=proofstrap_linux_$arch; packs=$(tar -tzf "$dist/$name.tar.gz" | grep -E "^$name/packs/sha256/[0-9a-f]{64}\.pstrap$"); count=$(printf '%s\n' "$packs" | grep -c .)
  [ "$count" -ge 1 ] && [ "$count" -le 64 ]
  check_members "$dist/$name.tar.gz" "$name/" "$name/LICENSE" "$name/README.md" "$name/docs/" "$name/docs/config.md" "$name/docs/profile.md" "$name/examples/" "$name/examples/bootstrap.toml" "$name/packs/" "$name/packs/sha256/" "$name/proofstrap" $packs
  name=proofstrap-pack_linux_$arch
  check_members "$dist/$name.tar.gz" "$name/" "$name/LICENSE" "$name/README.md" "$name/docs/" "$name/docs/profile.md" "$name/proofstrap-pack"
done

case $(uname -m) in
  x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) printf 'unsupported native Linux architecture\n' >&2; exit 1 ;;
esac
mkdir "$temporary/extract" "$temporary/home" "$temporary/data" "$temporary/tmp"; tar -xzf "$dist/proofstrap_linux_$arch.tar.gz" -C "$temporary/extract"; tar -xzf "$dist/proofstrap-pack_linux_$arch.tar.gz" -C "$temporary/extract"
runtime=$temporary/extract/proofstrap_linux_$arch/proofstrap
pack_root=$temporary/extract/proofstrap_linux_$arch/packs/sha256
run() { env HOME="$temporary/home" XDG_DATA_HOME="$temporary/data" TMPDIR="$temporary/tmp" "$runtime" "$@"; }

"$temporary/extract/proofstrap-pack_linux_$arch/proofstrap-pack" --help >/dev/null
run plan --config "$temporary/extract/proofstrap_linux_$arch/examples/bootstrap.toml" --output "$temporary/adjacent.plan" > "$temporary/adjacent.out" || [ "$?" -eq 1 ]
[ -f "$temporary/adjacent.plan" ]
index=0
for object in "$pack_root"/*.pstrap; do
  digest=$(basename "$object" .pstrap)
  run inspect --digest "sha256:$digest" "$object" > "$temporary/inspect-$index.json"
  grep -E '"kind": "(semantic|binding)"' "$temporary/inspect-$index.json" >/dev/null
  grep -F '"scopes": []' "$temporary/inspect-$index.json" >/dev/null
  index=$((index + 1))
done
first=$(find "$pack_root" -type f | LC_ALL=C sort | head -n 1)
digest=$(basename "$first" .pstrap)
run inspect "$first" > "$temporary/derived.json"
cmp "$temporary/inspect-0.json" "$temporary/derived.json"
run import "$first" > "$temporary/import.json"
grep -F '"user"' "$temporary/import.json" >/dev/null
run import --digest "sha256:$digest" "$first" > "$temporary/import-asserted.json"
cmp "$temporary/import.json" "$temporary/import-asserted.json"
stored=$temporary/data/proofstrap/packs/sha256/$digest.pstrap
cmp "$first" "$stored"
[ "$(find "$temporary/data" -type f | wc -l)" -eq 1 ]
[ -z "$(find "$temporary/home" "$temporary/tmp" -mindepth 1 -print -quit)" ]
