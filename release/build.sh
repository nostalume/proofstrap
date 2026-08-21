#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

admit_assets() {
  assets=$1
  work=$2
  [ -d "$assets" ] && [ ! -L "$assets" ] || { printf 'invalid pack asset directory\n' >&2; return 1; }
  [ "$(find "$assets" -mindepth 1 -maxdepth 1 | wc -l)" -eq 3 ] || {
    printf 'pack asset directory must contain exactly three files\n' >&2
    return 1
  }
  for file in core.pstrap linux.pstrap checksums.txt; do
    [ -f "$assets/$file" ] && [ ! -L "$assets/$file" ] || {
      printf 'invalid pack asset: %s\n' "$file" >&2
      return 1
    }
  done
  (cd "$assets" && sha256sum core.pstrap linux.pstrap) > "$work/observed.sha256"
  cmp "$assets/checksums.txt" "$work/observed.sha256"
  cp "$assets/core.pstrap" "$assets/linux.pstrap" "$work/"
}

build_once() {
  output=$1
  work=$2
  assets=$3
  mkdir -p "$output" "$work"
  admit_assets "$assets" "$work"
  core=$(sed -n '1s/  core\.pstrap$//p' "$work/observed.sha256")
  linux=$(sed -n '2s/  linux\.pstrap$//p' "$work/observed.sha256")
  [ "${#core}" -eq 64 ] && [ "${#linux}" -eq 64 ]
  printf 'schema = 2\n\nbindings = ["linux"]\nprofiles = [{ profile = "core:bootstrap-cli" }]\n\n[sources]\ncore = "sha256:%s"\nlinux = "sha256:%s"\n' \
    "$core" "$linux" > "$work/bootstrap.toml"
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
    cp "$work/core.pstrap" "$stage/packs/sha256/$core.pstrap"
    cp "$work/linux.pstrap" "$stage/packs/sha256/$linux.pstrap"
    chmod 0444 "$stage/examples/bootstrap.toml" "$stage/packs/sha256/"*.pstrap
  done

  "$work/proofstrap_linux_amd64/proofstrap" inspect --digest "sha256:$core" "$work/core.pstrap" > "$work/core.json"
  "$work/proofstrap_linux_amd64/proofstrap" inspect --digest "sha256:$linux" "$work/linux.pstrap" > "$work/linux.json"
  grep -F '"kind": "semantic"' "$work/core.json" >/dev/null
  grep -F '"kind": "binding"' "$work/linux.json" >/dev/null
  [ "$(grep -c '"handle"' "$work/linux.json")" -eq 1 ]
  grep -F "\"digest\": \"sha256:$core\"" "$work/linux.json" >/dev/null

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
