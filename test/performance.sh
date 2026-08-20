#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
metrics="$temporary/metrics"

record() {
  printf '%s=%s\n' "$1" "$2" >> "$metrics"
}

record revision "$(git -C "$root" rev-parse HEAD)"
record go_version "$(go version | tr ' ' '_')"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go -C "$root" build -trimpath -buildvcs=true -ldflags='-s -w' \
  -o "$temporary/proofstrap" ./cmd/proofstrap
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go -C "$root" build -trimpath -buildvcs=true -ldflags='-s -w' \
  -o "$temporary/proofstrap-pack" ./cmd/proofstrap-pack
record runtime_amd64_bytes "$(wc -c < "$temporary/proofstrap" | tr -d ' ')"
record author_amd64_bytes "$(wc -c < "$temporary/proofstrap-pack" | tr -d ' ')"

"$root/release/fetch.sh" "$temporary/assets"
"$root/release/build.sh" "$temporary/dist" "$temporary/assets"
for archive in "$temporary/dist"/proofstrap_linux_*.tar.gz; do
  name=$(basename "$archive" .tar.gz)
  record "archive_${name#proofstrap_linux_}_bytes" "$(wc -c < "$archive" | tr -d ' ')"
done

go -C "$root" test ./internal/app -run '^$' \
  -bench 'Benchmark(BuildPlanDirect|ComposeProfile|ApplyNoop)$' \
  -benchmem -benchtime=5x -count=20 > "$temporary/bench"
awk '/^Benchmark/ {
  name=$1
  sub(/-[0-9]+$/, "", name)
  count[name]++
  ns[name]+=$3
  bytes[name]+=$5
  allocs[name]+=$7
}
END {
  for (name in count) {
    printf "benchmark_%s_samples=%d\n", name, count[name]
    printf "benchmark_%s_mean_ns_per_op=%.0f\n", name, ns[name]/count[name]
    printf "benchmark_%s_mean_bytes_per_op=%.0f\n", name, bytes[name]/count[name]
    printf "benchmark_%s_mean_allocs_per_op=%.0f\n", name, allocs[name]/count[name]
  }
}' "$temporary/bench" >> "$metrics"

LC_ALL=C sort "$metrics"
