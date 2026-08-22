#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { printf 'usage: %s DIST_DIR\n' "$0" >&2; exit 2; }
dist=$(CDPATH= cd -- "$1" && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
[ "$(find "$dist" -mindepth 1 -maxdepth 1 | wc -l)" -eq 6 ]
(cd "$dist" && sha256sum --check --status checksums.txt && cut -d ' ' -f3- checksums.txt | LC_ALL=C sort -c)

check() {
  tar -tzf "$1" | LC_ALL=C sort > "$temporary/actual"; shift
  printf '%s\n' "$@" | LC_ALL=C sort > "$temporary/expected"
  cmp "$temporary/expected" "$temporary/actual"
}
for arch in amd64 arm64; do
  name=proofstrap_linux_$arch
  check "$dist/$name.tar.gz" "$name/" "$name/LICENSE" "$name/README.md" "$name/docs/" "$name/docs/config.md" "$name/docs/profile.md" "$name/proofstrap"
  name=proofstrap-pack_linux_$arch
  check "$dist/$name.tar.gz" "$name/" "$name/LICENSE" "$name/README.md" "$name/docs/" "$name/docs/profile.md" "$name/proofstrap-pack"
done
case $(uname -m) in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) printf 'unsupported native Linux architecture\n' >&2; exit 1 ;; esac
mkdir "$temporary/extract"
tar -xzf "$dist/proofstrap_linux_$arch.tar.gz" -C "$temporary/extract"
tar -xzf "$dist/proofstrap-pack_linux_$arch.tar.gz" -C "$temporary/extract"
"$temporary/extract/proofstrap_linux_$arch/proofstrap" --help >/dev/null
"$temporary/extract/proofstrap-pack_linux_$arch/proofstrap-pack" --help >/dev/null
