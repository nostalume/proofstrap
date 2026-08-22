#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

build_once() {
  output=$1 work=$2
  mkdir -p "$output" "$work"
  epoch=$(git -C "$root" show -s --format=%ct HEAD)
  for arch in amd64 arm64; do
    runtime="$work/proofstrap_linux_$arch"
    author="$work/proofstrap-pack_linux_$arch"
    mkdir -p "$runtime/docs" "$author/docs"
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go -C "$root" build -trimpath -buildvcs=true -ldflags='-s -w' -o "$runtime/proofstrap" ./cmd/proofstrap
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go -C "$root" build -trimpath -buildvcs=true -ldflags='-s -w' -o "$author/proofstrap-pack" ./cmd/proofstrap-pack
    cp "$root/README.md" "$root/LICENSE" "$runtime/"
    cp "$root/docs/config.md" "$root/docs/profile.md" "$runtime/docs/"
    cp "$root/README.md" "$root/LICENSE" "$author/"
    cp "$root/docs/profile.md" "$author/docs/"
    for name in "proofstrap_linux_$arch" "proofstrap-pack_linux_$arch"; do
      tar --format=gnu --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C "$work" -cf - "$name" | gzip -n > "$output/$name.tar.gz"
    done
  done
  cp "$root/install.sh" "$output/install.sh"
  (cd "$output" && export LC_ALL=C && sha256sum ./*.tar.gz install.sh > checksums.txt)
}

temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
if [ "${1:-}" = --twice ]; then
  [ "$#" -eq 1 ] || { printf 'usage: %s --twice\n' "$0" >&2; exit 2; }
  build_once "$temporary/one" "$temporary/work-one"
  build_once "$temporary/two" "$temporary/work-two"
  for file in "$temporary/one"/*; do cmp "$file" "$temporary/two/$(basename "$file")"; done
  exit 0
fi
[ "$#" -eq 1 ] || { printf 'usage: %s OUTPUT_DIR\n' "$0" >&2; exit 2; }
[ ! -e "$1" ] || { printf 'output already exists: %s\n' "$1" >&2; exit 1; }
build_once "$temporary/output" "$temporary/work"
mv "$temporary/output" "$1"
