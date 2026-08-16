#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
mkdir -p "$temporary/bin" "$temporary/home" "$temporary/tmp"
"$root/test/release/fetch-assets.sh" "$temporary/assets"
"$root/test/release/build.sh" "$temporary/dist" "$temporary/assets"

cat > "$temporary/bin/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -s) printf 'Linux\n' ;;
  -m) printf 'x86_64\n' ;;
  *) exit 64 ;;
esac
EOF
cat > "$temporary/bin/curl" <<'EOF'
#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output=$2; shift 2 ;;
    --fail|--location|--show-error|--silent) shift ;;
    *) url=$1; shift ;;
  esac
done
case "$url" in
  */checksums.txt) cp "$RELEASE_DIST/checksums.txt" "$output" ;;
  */proofstrap_linux_amd64.tar.gz) cp "$RELEASE_DIST/proofstrap_linux_amd64.tar.gz" "$output" ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$temporary/bin/uname" "$temporary/bin/curl"

PATH="$temporary/bin:/usr/bin:/bin" \
HOME="$temporary/home" TMPDIR="$temporary/tmp" RELEASE_DIST="$temporary/dist" \
  sh "$root/install.sh"

launcher="$temporary/home/.local/bin/proofstrap"
[ -L "$launcher" ]
target=$(readlink "$launcher")
case "$target" in
  .proofstrap-releases/*/proofstrap) ;;
  *) printf 'unexpected launcher target: %s\n' "$target" >&2; exit 1 ;;
esac
[ "$(find "$temporary/home/.local/bin/.proofstrap-releases" -path '*/packs/sha256/*.pstrap' -type f | wc -l)" -eq 2 ]
if find "$temporary/home/.local/bin/.proofstrap-releases" -name proofstrap-pack -print -quit | grep -q .; then
  printf 'author tool escaped into runtime generation\n' >&2
  exit 1
fi
"$launcher" inspect > "$temporary/inspect.json"
[ "$(grep -c '"adjacent"' "$temporary/inspect.json")" -eq 2 ]
