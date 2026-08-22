#!/bin/sh
set -eu

[ "$(uname -s)" = Linux ] || { printf 'unsupported operating system\n' >&2; exit 1; }
case $(uname -m) in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) printf 'unsupported architecture\n' >&2; exit 1 ;;
esac

base=https://github.com/nostalume/proofstrap/releases/latest/download
archive="proofstrap_linux_$arch.tar.gz"
root="proofstrap_linux_$arch"
install_dir=${PROOFSTRAP_INSTALL_DIR:-"$HOME/.local/bin"}
releases="$install_dir/.proofstrap-releases"
launcher="$install_dir/proofstrap"
tmp=$(mktemp -d)
work=
stage=
link_tmp=
legacy_stage=
cleanup() {
  status=$?
  trap - EXIT
  rm -rf -- "$tmp"
  [ -z "$work" ] || rm -rf -- "$work"
  [ -z "$stage" ] || rm -rf -- "$stage"
  [ -z "$link_tmp" ] || rm -f -- "$link_tmp"
  [ -z "$legacy_stage" ] || rm -rf -- "$legacy_stage"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

curl --fail --location --show-error --silent "$base/$archive" -o "$tmp/$archive"
curl --fail --location --show-error --silent "$base/checksums.txt" -o "$tmp/checksums.txt"
[ "$(wc -c < "$tmp/$archive")" -le 33554432 ] || { printf 'archive exceeds 32 MiB\n' >&2; exit 1; }
selected=
while read -r checksum filename extra; do
  [ "$filename" = "./$archive" ] && [ -z "${extra:-}" ] || continue
  case "$checksum" in ""|*[!0-9a-fA-F]*) continue ;; esac
  [ "${#checksum}" -eq 64 ] || continue
  [ -z "$selected" ] || { printf 'duplicate checksum for %s\n' "$archive" >&2; exit 1; }
  selected=$checksum
done < "$tmp/checksums.txt"
[ -n "$selected" ] || { printf 'checksum missing for %s\n' "$archive" >&2; exit 1; }
printf '%s  ./%s\n' "$selected" "$archive" > "$tmp/selected-checksum"
(cd "$tmp" && sha256sum --check selected-checksum)
generation=$(sha256sum "$tmp/$archive" | cut -d ' ' -f 1)

mkdir -p "$install_dir" "$releases"
work=$(mktemp -d "$releases/.work.XXXXXX")
LC_ALL=C tar -tvzf "$tmp/$archive" > "$work/listing"
awk 'NF < 6 || $3 !~ /^[0-9]+$/ || total + $3 > 33554432 { exit 1 } { total += $3; print substr($1, 1, 1) "\t" $6 }' "$work/listing" > "$work/members"
[ -z "$(cut -f2 "$work/members" | LC_ALL=C sort | uniq -d)" ] || {
  printf 'archive contains duplicate members\n' >&2
  exit 1
}
pack_count=0
tab=$(printf '\t')
while IFS="$tab" read -r type member; do
  case "$type:$member" in
    "d:$root/"|"d:$root/docs/"|"d:$root/examples/"|"d:$root/packs/"|"d:$root/packs/sha256/") ;;
    "-:$root/proofstrap"|"-:$root/README.md"|"-:$root/LICENSE"|"-:$root/docs/config.md"|"-:$root/docs/profile.md"|"-:$root/examples/bootstrap.toml") ;;
    "-:$root/packs/sha256/"*.pstrap)
      name=${member##*/}; digest=${name%.pstrap}
      case "$digest" in ""|*[!0-9a-f]*) printf 'invalid pack member: %s\n' "$member" >&2; exit 1 ;; esac
      [ "${#digest}" -eq 64 ] || { printf 'invalid pack member: %s\n' "$member" >&2; exit 1; }
      pack_count=$((pack_count + 1)) ;;
    *) printf 'unsafe or unexpected archive member: %s\n' "$member" >&2; exit 1 ;;
  esac
done < "$work/members"
[ "$pack_count" -ge 1 ] && [ "$pack_count" -le 64 ] || { printf 'archive must contain 1..64 packs\n' >&2; exit 1; }
for member in "$root/" "$root/docs/" "$root/examples/" "$root/packs/" "$root/packs/sha256/" \
  "$root/proofstrap" "$root/README.md" "$root/LICENSE" "$root/docs/config.md" \
  "$root/docs/profile.md" "$root/examples/bootstrap.toml"; do
  [ "$(cut -f2 "$work/members" | grep -Fxc "$member")" -eq 1 ] || {
    printf 'archive member is missing: %s\n' "$member" >&2
    exit 1
  }
done

mkdir "$work/extract"
tar --no-same-owner --no-same-permissions -xzf "$tmp/$archive" -C "$work/extract"
extracted="$work/extract/$root"
for directory in "$extracted" "$extracted/docs" "$extracted/examples" "$extracted/packs" "$extracted/packs/sha256"; do
  [ -d "$directory" ] && [ ! -L "$directory" ] || { printf 'unsafe extracted directory\n' >&2; exit 1; }
done
for file in proofstrap README.md LICENSE docs/config.md docs/profile.md examples/bootstrap.toml; do
  [ -f "$extracted/$file" ] && [ ! -L "$extracted/$file" ] || { printf 'unsafe extracted file: %s\n' "$file" >&2; exit 1; }
done

index=0
for object in "$extracted"/packs/sha256/*.pstrap; do
  [ -f "$object" ] && [ ! -L "$object" ] || { printf 'unsafe pack object\n' >&2; exit 1; }
  name=$(basename "$object" .pstrap)
  observed=$(sha256sum "$object" | cut -d ' ' -f 1)
  [ "$observed" = "$name" ] || { printf 'pack digest does not match filename: %s\n' "$name" >&2; exit 1; }
  "$extracted/proofstrap" inspect --digest "sha256:$name" "$object" > "$work/inspect-$index.json"
  index=$((index + 1))
done

stage=$(mktemp -d "$releases/.stage.XXXXXX")
mkdir -p "$stage/docs" "$stage/examples" "$stage/packs/sha256"
install -m 0755 "$extracted/proofstrap" "$stage/proofstrap"
for file in README.md LICENSE; do install -m 0644 "$extracted/$file" "$stage/$file"; done
for file in config.md profile.md; do install -m 0644 "$extracted/docs/$file" "$stage/docs/$file"; done
install -m 0444 "$extracted/examples/bootstrap.toml" "$stage/examples/bootstrap.toml"
for object in "$extracted"/packs/sha256/*.pstrap; do install -m 0444 "$object" "$stage/packs/sha256/$(basename "$object")"; done
final="$releases/$generation"
[ ! -e "$final" ] || { printf 'release generation already exists: %s\n' "$generation" >&2; exit 1; }
mv -T -n -- "$stage" "$final"
[ ! -e "$stage" ] || { printf 'release generation publication conflicted\n' >&2; exit 1; }
stage=

if [ -e "$launcher" ] && [ ! -L "$launcher" ]; then
  [ -f "$launcher" ] || { printf 'existing launcher is unsafe\n' >&2; exit 1; }
  legacy="$releases/legacy-$(sha256sum "$launcher" | cut -d ' ' -f 1)"
  if [ ! -e "$legacy" ]; then
    legacy_stage=$(mktemp -d "$releases/.legacy.XXXXXX")
    install -m 0755 "$launcher" "$legacy_stage/proofstrap"
    mv -T -n -- "$legacy_stage" "$legacy"
    [ ! -e "$legacy_stage" ] || { rm -rf -- "$legacy_stage"; printf 'legacy publication conflicted\n' >&2; exit 1; }
    legacy_stage=
  fi
fi

link_tmp="$install_dir/.proofstrap-link.$$"
[ ! -e "$link_tmp" ] || { printf 'launcher staging name already exists\n' >&2; exit 1; }
ln -s ".proofstrap-releases/$generation/proofstrap" "$link_tmp"
mv -Tf -- "$link_tmp" "$launcher"
link_tmp=
starter="$final/examples/bootstrap.toml"
printf 'starter config: %s\n' "$starter"
printf 'plan directly: %s plan --config %s --output ./plan.json\n' "$launcher" "$starter"
printf 'or customize: cp -- "%s" ./proofstrap.toml && proofstrap plan\n' "$starter"
