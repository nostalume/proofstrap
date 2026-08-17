#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { printf 'usage: %s DIST_DIR\n' "$0" >&2; exit 2; }
dist=$(CDPATH= cd -- "$1" && pwd)
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM

[ "$(find "$dist" -mindepth 1 -maxdepth 1 | wc -l)" -eq 6 ]
(cd "$dist" && sha256sum --check --status checksums.txt)
core=$(sed -n '1s/  core\.pstrap$//p' "$root/release/packs.sha256")
linux=$(sed -n '2s/  linux\.pstrap$//p' "$root/release/packs.sha256")

check_members() {
  tar -tzf "$1" | LC_ALL=C sort > "$temporary/actual"
  shift
  printf '%s\n' "$@" | LC_ALL=C sort > "$temporary/expected"
  cmp "$temporary/expected" "$temporary/actual"
}

for arch in amd64 arm64; do
  name=proofstrap_linux_$arch
  check_members "$dist/$name.tar.gz" "$name/" "$name/LICENSE" "$name/README.md" \
    "$name/docs/" "$name/docs/config.md" "$name/docs/profile.md" "$name/packs/" \
    "$name/packs/sha256/" "$name/packs/sha256/$core.pstrap" \
    "$name/packs/sha256/$linux.pstrap" "$name/proofstrap"
  name=proofstrap-pack_linux_$arch
  check_members "$dist/$name.tar.gz" "$name/" "$name/LICENSE" "$name/README.md" \
    "$name/docs/" "$name/docs/profile.md" "$name/proofstrap-pack"
done

case $(uname -m) in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) printf 'unsupported native Linux architecture\n' >&2; exit 1 ;;
esac
mkdir "$temporary/extract" "$temporary/home" "$temporary/data" "$temporary/tmp"
tar -xzf "$dist/proofstrap_linux_$arch.tar.gz" -C "$temporary/extract"
tar -xzf "$dist/proofstrap-pack_linux_$arch.tar.gz" -C "$temporary/extract"
runtime=$temporary/extract/proofstrap_linux_$arch/proofstrap
author=$temporary/extract/proofstrap-pack_linux_$arch/proofstrap-pack
core_pack=$temporary/extract/proofstrap_linux_$arch/packs/sha256/$core.pstrap
linux_pack=$temporary/extract/proofstrap_linux_$arch/packs/sha256/$linux.pstrap
run() { env HOME="$temporary/home" XDG_DATA_HOME="$temporary/data" TMPDIR="$temporary/tmp" "$runtime" "$@"; }

run --help >/dev/null
"$author" --help >/dev/null
run inspect --digest "sha256:$core" "$core_pack" > "$temporary/core.json"
run inspect --digest "sha256:$linux" "$linux_pack" > "$temporary/linux.json"
grep -F '"kind": "semantic"' "$temporary/core.json" >/dev/null
grep -F '"kind": "binding"' "$temporary/linux.json" >/dev/null
[ "$(grep -c '"handle"' "$temporary/linux.json")" -eq 1 ]
grep -F "\"digest\": \"sha256:$core\"" "$temporary/linux.json" >/dev/null
[ "$(grep -h -F '"scopes": []' "$temporary/core.json" "$temporary/linux.json" | wc -l)" -eq 2 ]
run import --digest "sha256:$core" "$core_pack"
stored=$temporary/data/proofstrap/packs/sha256/$core.pstrap
cmp "$core_pack" "$stored"
[ "$(find "$temporary/data" -type f | wc -l)" -eq 1 ]
[ -z "$(find "$temporary/home" "$temporary/tmp" -mindepth 1 -print -quit)" ]
