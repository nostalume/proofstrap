#!/bin/sh
set -eu

[ "$(uname -s)" = Linux ] || { printf 'unsupported operating system\n' >&2; exit 1; }
case $(uname -m) in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) printf 'unsupported architecture\n' >&2; exit 1 ;; esac
base=https://github.com/nostalume/proofstrap/releases/latest/download
archive=proofstrap_linux_$arch.tar.gz
root=proofstrap_linux_$arch
install_dir=${PROOFSTRAP_INSTALL_DIR:-"$HOME/.local/bin"}
releases=$install_dir/.proofstrap-releases
launcher=$install_dir/proofstrap
tmp=$(mktemp -d); stage=; link_tmp=; legacy_stage=
cleanup() {
  status=$?; trap - EXIT
  rm -rf -- "$tmp"
  [ -z "$stage" ] || rm -rf -- "$stage"
  [ -z "$link_tmp" ] || rm -f -- "$link_tmp"
  [ -z "$legacy_stage" ] || rm -rf -- "$legacy_stage"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

curl -fsSL "$base/$archive" -o "$tmp/$archive"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"
[ "$(wc -c < "$tmp/$archive")" -le 33554432 ] || { printf 'archive exceeds 32 MiB\n' >&2; exit 1; }
selected=$(awk -v file="./$archive" '$2 == file && NF == 2 && length($1) == 64 && $1 !~ /[^0-9a-fA-F]/ { print $1 }' "$tmp/checksums.txt")
[ "$(printf '%s\n' "$selected" | grep -c .)" -eq 1 ] || { printf 'checksum missing or duplicated\n' >&2; exit 1; }
printf '%s  ./%s\n' "$selected" "$archive" > "$tmp/selected"
(cd "$tmp" && sha256sum --check --status selected)
generation=$(sha256sum "$tmp/$archive" | cut -d ' ' -f 1)

tar -tzf "$tmp/$archive" | LC_ALL=C sort > "$tmp/members"
printf '%s\n' "$root/" "$root/LICENSE" "$root/README.md" "$root/docs/" "$root/docs/config.md" "$root/docs/profile.md" "$root/proofstrap" | LC_ALL=C sort > "$tmp/expected"
cmp "$tmp/expected" "$tmp/members" >/dev/null || { printf 'unexpected release members\n' >&2; exit 1; }
tar -tvzf "$tmp/$archive" | awk 'substr($1,1,1) !~ /[-d]/ || $3 !~ /^[0-9]+$/ || total+$3 > 33554432 { exit 1 } { total += $3 }'
mkdir "$tmp/extract"
tar --no-same-owner --no-same-permissions -xzf "$tmp/$archive" -C "$tmp/extract"
extracted=$tmp/extract/$root
for path in "$extracted" "$extracted/docs"; do [ -d "$path" ] && [ ! -L "$path" ] || exit 1; done
for path in proofstrap README.md LICENSE docs/config.md docs/profile.md; do [ -f "$extracted/$path" ] && [ ! -L "$extracted/$path" ] || exit 1; done
"$extracted/proofstrap" --help >/dev/null

mkdir -p "$install_dir" "$releases"
stage=$(mktemp -d "$releases/.stage.XXXXXX")
mkdir "$stage/docs"
install -m 0755 "$extracted/proofstrap" "$stage/proofstrap"
for path in README.md LICENSE; do install -m 0644 "$extracted/$path" "$stage/$path"; done
for path in config.md profile.md; do install -m 0644 "$extracted/docs/$path" "$stage/docs/$path"; done
final=$releases/$generation
[ ! -e "$final" ] || { printf 'release generation already exists\n' >&2; exit 1; }
mv -T -n -- "$stage" "$final"
[ ! -e "$stage" ] || { printf 'release publication conflicted\n' >&2; exit 1; }
stage=

if [ -e "$launcher" ] && [ ! -L "$launcher" ]; then
  [ -f "$launcher" ] || { printf 'existing launcher is unsafe\n' >&2; exit 1; }
  legacy=$releases/legacy-$(sha256sum "$launcher" | cut -d ' ' -f 1)
  if [ ! -e "$legacy" ]; then
    legacy_stage=$(mktemp -d "$releases/.legacy.XXXXXX")
    install -m 0755 "$launcher" "$legacy_stage/proofstrap"
    mv -T -n -- "$legacy_stage" "$legacy"
    [ ! -e "$legacy_stage" ] || { printf 'legacy publication conflicted\n' >&2; exit 1; }
    legacy_stage=
  fi
fi
link_tmp=$install_dir/.proofstrap-link.$$
[ ! -e "$link_tmp" ] || { printf 'launcher staging name exists\n' >&2; exit 1; }
ln -s ".proofstrap-releases/$generation/proofstrap" "$link_tmp"
mv -Tf -- "$link_tmp" "$launcher"
link_tmp=
printf 'installed: %s\n' "$launcher"
printf 'next: create proofstrap.toml or use a distributed workspace, then run proofstrap plan\n'
