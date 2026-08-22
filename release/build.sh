#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

admit_assets() {
  assets=$1
  work=$2
  [ -d "$assets" ] && [ ! -L "$assets" ] || { printf 'invalid pack asset directory\n' >&2; return 1; }
  for file in proofstrap.toml checksums.txt; do [ -f "$assets/$file" ] && [ ! -L "$assets/$file" ] || return 1; done
  [ -d "$assets/packs/sha256" ] && [ ! -L "$assets/packs" ] && [ ! -L "$assets/packs/sha256" ] || return 1
  count=$(find "$assets/packs/sha256" -mindepth 1 -maxdepth 1 -type f | wc -l)
  [ "$count" -ge 1 ] && [ "$count" -le 64 ] || return 1
  [ "$(find "$assets" -type f | wc -l)" -eq $((count + 2)) ] || return 1
  [ -z "$(find "$assets" -mindepth 1 ! -type d ! -type f -print -quit)" ] || return 1
  for object in "$assets"/packs/sha256/*.pstrap; do
    name=$(basename "$object" .pstrap)
    case "$name" in ""|*[!0-9a-f]*) return 1 ;; esac
    [ "${#name}" -eq 64 ] && [ "$(sha256sum "$object" | cut -d ' ' -f 1)" = "$name" ] || return 1
  done
  (cd "$assets" && sha256sum --check --status checksums.txt)
  cp "$assets/proofstrap.toml" "$work/bootstrap.toml"
  mkdir -p "$work/packs/sha256"
  cp "$assets"/packs/sha256/*.pstrap "$work/packs/sha256/"
}

build_once() {
  output=$1
  work=$2
  assets=$3
  mkdir -p "$output" "$work"
  admit_assets "$assets" "$work"
  epoch=$(git -C "$root" show -s --format=%ct HEAD)

  for arch in amd64 arm64; do
    name="proofstrap_linux_$arch"
    stage="$work/$name"
    author_stage="$work/proofstrap-pack_linux_$arch"
    mkdir -p "$stage/docs" "$stage/examples" "$stage/packs/sha256" "$author_stage/docs"
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
      go -C "$root" build -trimpath -buildvcs=true -ldflags='-s -w' \
      -o "$stage/proofstrap" ./cmd/proofstrap
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
      go -C "$root" build -trimpath -buildvcs=true -ldflags='-s -w' \
      -o "$author_stage/proofstrap-pack" ./cmd/proofstrap-pack
    cp "$root/README.md" "$root/LICENSE" "$stage/"
    cp "$root/docs/config.md" "$root/docs/profile.md" "$stage/docs/"
    cp "$work/bootstrap.toml" "$stage/examples/"
    cp "$root/README.md" "$root/LICENSE" "$author_stage/"
    cp "$root/docs/profile.md" "$author_stage/docs/"
    cp "$work"/packs/sha256/*.pstrap "$stage/packs/sha256/"
    chmod 0444 "$stage/examples/bootstrap.toml" "$stage/packs/sha256/"*.pstrap
  done

  runtime="$work/proofstrap_linux_amd64/proofstrap"
  for object in "$work"/packs/sha256/*.pstrap; do
    "$runtime" inspect "$object" >/dev/null
  done
  "$runtime" plan --config "$work/bootstrap.toml" --output "$work/bootstrap.plan" > "$work/bootstrap.out" || [ "$?" -eq 1 ]
  [ -f "$work/bootstrap.plan" ]

  for arch in amd64 arm64; do
    for artifact in "proofstrap_linux_$arch" "proofstrap-pack_linux_$arch"; do
      tar --format=gnu --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
        -C "$work" -cf - "$artifact" | gzip -n > "$output/$artifact.tar.gz"
    done
  done
  cp "$root/install.sh" "$output/install.sh"
  (cd "$output" && export LC_ALL=C && sha256sum ./*.tar.gz install.sh > checksums.txt)
}

temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
if [ "${1:-}" = --twice ]; then
  [ "$#" -eq 2 ] || { printf 'usage: %s --twice ASSET_DIR\n' "$0" >&2; exit 2; }
  build_once "$temporary/out-one" "$temporary/one" "$2"
  build_once "$temporary/out-two" "$temporary/two" "$2"
  for file in proofstrap_linux_amd64.tar.gz proofstrap_linux_arm64.tar.gz \
    proofstrap-pack_linux_amd64.tar.gz proofstrap-pack_linux_arm64.tar.gz \
    checksums.txt install.sh; do
    cmp "$temporary/out-one/$file" "$temporary/out-two/$file"
  done
  exit 0
fi

[ "$#" -eq 2 ] || { printf 'usage: %s OUTPUT_DIR ASSET_DIR\n' "$0" >&2; exit 2; }
[ ! -e "$1" ] || { printf 'output already exists: %s\n' "$1" >&2; exit 1; }
build_once "$temporary/output" "$temporary/work" "$2"
mv "$temporary/output" "$1"
