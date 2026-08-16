#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
"$root/test/release/fetch-assets.sh" "$temporary/valid"

expect_failure() {
  name=$1
  assets=$2
  output="$temporary/out-$name"
  if "$root/test/release/build.sh" "$output" "$assets" >/dev/null 2>&1; then
    printf 'release admitted invalid %s assets\n' "$name" >&2
    exit 1
  fi
  [ ! -e "$output" ] || { printf 'failed %s input published output\n' "$name" >&2; exit 1; }
}

cp -a "$temporary/valid" "$temporary/corrupt"
printf x >> "$temporary/corrupt/core.pstrap"
expect_failure corrupt "$temporary/corrupt"

cp -a "$temporary/valid" "$temporary/swapped"
mv "$temporary/swapped/core.pstrap" "$temporary/swapped/hold"
mv "$temporary/swapped/linux.pstrap" "$temporary/swapped/core.pstrap"
mv "$temporary/swapped/hold" "$temporary/swapped/linux.pstrap"
expect_failure swapped "$temporary/swapped"

cp -a "$temporary/valid" "$temporary/duplicate"
head -n 1 "$temporary/duplicate/checksums.txt" >> "$temporary/duplicate/checksums.txt"
expect_failure duplicate "$temporary/duplicate"

cp -a "$temporary/valid" "$temporary/extra"
: > "$temporary/extra/unexpected"
expect_failure extra "$temporary/extra"

cp -a "$temporary/valid" "$temporary/wrong-kind"
cp "$temporary/wrong-kind/core.pstrap" "$temporary/wrong-kind/linux.pstrap"
(cd "$temporary/wrong-kind" && sha256sum core.pstrap linux.pstrap > checksums.txt)
expect_failure wrong-kind "$temporary/wrong-kind"

"$root/test/release/build.sh" "$temporary/output" "$temporary/valid"
