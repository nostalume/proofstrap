#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
metrics="$temporary/metrics"

printf 'revision=%s\n' "$(git -C "$root" rev-parse HEAD)" > "$metrics"
printf 'go_version=%s\n' "$(go version | tr ' ' '_')" >> "$metrics"

for command in proofstrap proofstrap-pack; do
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go -C "$root" build -trimpath -buildvcs=true -ldflags='-s -w' \
    -o "$temporary/$command" "./cmd/$command"
done
printf 'runtime_amd64_bytes=%s\nauthor_amd64_bytes=%s\n' \
  "$(wc -c < "$temporary/proofstrap" | tr -d ' ')" "$(wc -c < "$temporary/proofstrap-pack" | tr -d ' ')" >> "$metrics"

"$root/release/build.sh" "$temporary/dist"
for archive in "$temporary/dist"/proofstrap_linux_*.tar.gz; do
  name=$(basename "$archive" .tar.gz)
  printf 'archive_%s_bytes=%s\n' "${name#proofstrap_linux_}" "$(wc -c < "$archive" | tr -d ' ')" >> "$metrics"
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
    printf "benchmark_%s_samples=%d\nbenchmark_%s_mean_ns_per_op=%.0f\n", name, count[name], name, ns[name]/count[name]
    printf "benchmark_%s_mean_bytes_per_op=%.0f\nbenchmark_%s_mean_allocs_per_op=%.0f\n", name, bytes[name]/count[name], name, allocs[name]/count[name]
  }
}' "$temporary/bench" >> "$metrics"

LC_ALL=C sort "$metrics"
