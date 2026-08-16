#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

build_once() {
  output=$1
  work=$2
  mkdir -p "$output" "$work"
  epoch=$(git -C "$root" show -s --format=%ct HEAD)

  "$work/proofstrap-pack-host" build --input "$root/profiles/core" --output "$work/core.pstrap" > "$work/core.digest"
  "$work/proofstrap-pack-host" build --input "$root/profiles/linux" --output "$work/linux.pstrap" > "$work/linux.digest"
  core=$(sed 's/^sha256://' "$work/core.digest")
  linux=$(sed 's/^sha256://' "$work/linux.digest")
  [ "$(sha256sum "$work/core.pstrap" | cut -d ' ' -f 1)" = "$core" ]
  [ "$(sha256sum "$work/linux.pstrap" | cut -d ' ' -f 1)" = "$linux" ]

  for arch in amd64 arm64; do
    name="proofstrap_linux_$arch"
    stage="$work/$name"
    mkdir -p "$stage/spec" "$stage/packs/sha256"
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
      go -C "$root" build -trimpath -buildvcs=true -ldflags='-s -w' \
      -o "$stage/proofstrap" ./cmd/proofstrap
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
      go -C "$root" build -trimpath -buildvcs=true -ldflags='-s -w' \
      -o "$stage/proofstrap-pack" ./cmd/proofstrap-pack
    cp "$root/README.md" "$root/LICENSE" "$stage/"
    cp "$root/spec/config.md" "$root/spec/profile.md" "$stage/spec/"
    cp "$work/core.pstrap" "$stage/packs/sha256/$core.pstrap"
    cp "$work/linux.pstrap" "$stage/packs/sha256/$linux.pstrap"
    chmod 0444 "$stage/packs/sha256/"*.pstrap
    tar --format=gnu --sort=name --mtime="@$epoch" \
      --owner=0 --group=0 --numeric-owner \
      -C "$work" -cf - "$name" | gzip -n > "$output/$name.tar.gz"
  done
  (
    cd "$output"
    sha256sum ./*.tar.gz > checksums.txt
  )

  "$work/proofstrap_linux_amd64/proofstrap" --help >/dev/null
  "$work/proofstrap_linux_amd64/proofstrap-pack" --help >/dev/null
  "$work/proofstrap_linux_amd64/proofstrap" inspect --digest "sha256:$core" "$work/core.pstrap" > "$work/core.json"
  "$work/proofstrap_linux_amd64/proofstrap" inspect --digest "sha256:$linux" "$work/linux.pstrap" > "$work/linux.json"
  grep -q '"kind": "semantic"' "$work/core.json"
  grep -q '"kind": "binding"' "$work/linux.json"
  [ "$(grep -c '"handle"' "$work/linux.json")" -eq 1 ]
  grep -q "\"digest\": \"sha256:$core\"" "$work/linux.json"
}

prepare_host_builder() {
  destination=$1
  go -C "$root" build -trimpath -buildvcs=true -o "$destination" ./cmd/proofstrap-pack
}

if [ "${1:-}" = --twice ]; then
  temporary=$(mktemp -d)
  trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
  prepare_host_builder "$temporary/proofstrap-pack-host"
  mkdir "$temporary/one" "$temporary/two"
  cp "$temporary/proofstrap-pack-host" "$temporary/one/proofstrap-pack-host"
  cp "$temporary/proofstrap-pack-host" "$temporary/two/proofstrap-pack-host"
  build_once "$temporary/out-one" "$temporary/one"
  build_once "$temporary/out-two" "$temporary/two"
  cmp "$temporary/out-one/proofstrap_linux_amd64.tar.gz" "$temporary/out-two/proofstrap_linux_amd64.tar.gz"
  cmp "$temporary/out-one/proofstrap_linux_arm64.tar.gz" "$temporary/out-two/proofstrap_linux_arm64.tar.gz"
  cmp "$temporary/out-one/checksums.txt" "$temporary/out-two/checksums.txt"
  exit 0
fi

[ "$#" -eq 1 ] || {
  printf 'usage: %s OUTPUT_DIR | --twice\n' "$0" >&2
  exit 2
}
output=$1
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
prepare_host_builder "$temporary/proofstrap-pack-host"
build_once "$output" "$temporary"
