#!/bin/sh
set -eu

system=$(uname -s)
[ "$system" = Linux ] || {
  printf 'unsupported operating system: %s\n' "$system" >&2
  exit 1
}
machine=$(uname -m)
case "$machine" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) printf 'unsupported architecture: %s\n' "$machine" >&2; exit 1 ;;
esac

base=https://github.com/nostalume/proofstrap/releases/latest/download
archive="proofstrap_linux_${arch}.tar.gz"
member="proofstrap_linux_${arch}/proofstrap"
install_dir=${PROOFSTRAP_INSTALL_DIR:-"$HOME/.local/bin"}
tmp=$(mktemp -d)
install_tmp=
cleanup() {
  status=$?
  trap - EXIT
  rm -rf -- "$tmp" || :
  [ -z "$install_tmp" ] || rm -f -- "$install_tmp" || :
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

curl --fail --location --show-error --silent "$base/$archive" -o "$tmp/$archive"
curl --fail --location --show-error --silent "$base/checksums.txt" -o "$tmp/checksums.txt"

selected=
while read -r checksum filename extra; do
  if [ "$filename" = "./$archive" ] && [ -z "${extra:-}" ]; then
    case "$checksum" in
      ""|*[!0-9a-fA-F]*) continue ;;
    esac
    [ "${#checksum}" -eq 64 ] || continue
    [ -z "$selected" ] || {
      printf 'duplicate checksum for %s\n' "$archive" >&2
      exit 1
    }
    selected=$checksum
  fi
done < "$tmp/checksums.txt"
[ -n "$selected" ] || {
  printf 'checksum missing for %s\n' "$archive" >&2
  exit 1
}
printf '%s  ./%s\n' "$selected" "$archive" > "$tmp/selected-checksum"
(cd "$tmp" && sha256sum --check selected-checksum)

tar -xOzf "$tmp/$archive" "$member" > "$tmp/proofstrap"
[ -s "$tmp/proofstrap" ] || {
  printf 'archive member %s is empty\n' "$member" >&2
  exit 1
}
mkdir -p "$install_dir"
install_tmp=$(mktemp "$install_dir/.proofstrap.XXXXXX")
install -m 0755 "$tmp/proofstrap" "$install_tmp"
mv -f -- "$install_tmp" "$install_dir/proofstrap"
install_tmp=