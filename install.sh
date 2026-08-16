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
root="proofstrap_linux_${arch}"
install_dir=${PROOFSTRAP_INSTALL_DIR:-"$HOME/.local/bin"}
releases="$install_dir/.proofstrap-releases"
launcher="$install_dir/proofstrap"
tmp=$(mktemp -d)
stage=
link_tmp=
cleanup() {
  status=$?
  trap - EXIT
  rm -rf -- "$tmp" || :
  [ -z "$stage" ] || rm -rf -- "$stage" || :
  [ -z "$link_tmp" ] || rm -f -- "$link_tmp" || :
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
generation=$(sha256sum "$tmp/$archive" | cut -d ' ' -f 1)

tar -tzf "$tmp/$archive" > "$tmp/members"
LC_ALL=C tar -tvzf "$tmp/$archive" > "$tmp/member-details"
[ -z "$(grep -Ev '^[-d]' "$tmp/member-details")" ] || {
  printf 'archive contains links or special members\n' >&2
  exit 1
}
[ "$(wc -l < "$tmp/members")" -eq 12 ] || {
  printf 'archive has unexpected member count\n' >&2
  exit 1
}
for member in \
  "$root/" \
  "$root/spec/" \
  "$root/packs/" \
  "$root/packs/sha256/" \
  "$root/proofstrap" \
  "$root/proofstrap-pack" \
  "$root/README.md" \
  "$root/LICENSE" \
  "$root/spec/config.md" \
  "$root/spec/profile.md"; do
  grep -Fx "$member" "$tmp/members" >/dev/null || {
    printf 'archive member is missing: %s\n' "$member" >&2
    exit 1
  }
done
[ "$(grep -Ec "^$root/packs/sha256/[0-9a-f]{64}\.pstrap$" "$tmp/members")" -eq 2 ] || {
  printf 'archive pack members are invalid\n' >&2
  exit 1
}

mkdir "$tmp/extract"
tar -xzf "$tmp/$archive" -C "$tmp/extract"
extracted="$tmp/extract/$root"
[ -d "$extracted" ] && [ ! -L "$extracted" ] || {
  printf 'archive root is missing or unsafe\n' >&2
  exit 1
}
for directory in spec packs packs/sha256; do
  [ -d "$extracted/$directory" ] && [ ! -L "$extracted/$directory" ] || {
    printf 'archive directory is missing or unsafe: %s\n' "$directory" >&2
    exit 1
  }
done
for file in proofstrap proofstrap-pack README.md LICENSE spec/config.md spec/profile.md; do
  [ -f "$extracted/$file" ] && [ ! -L "$extracted/$file" ] || {
    printf 'archive file is missing or unsafe: %s\n' "$file" >&2
    exit 1
  }
done
[ "$(find "$extracted" -mindepth 1 -type d | wc -l)" -eq 3 ] || {
  printf 'archive has unexpected directories\n' >&2
  exit 1
}
[ "$(find "$extracted" -type f | wc -l)" -eq 8 ] || {
  printf 'archive has unexpected files\n' >&2
  exit 1
}
[ -z "$(find "$extracted" -mindepth 1 ! -type d ! -type f -print -quit)" ] || {
  printf 'archive has unsupported members\n' >&2
  exit 1
}

pack_count=0
semantic_count=0
binding_count=0
semantic_digest=
binding_inspect=
for object in "$extracted"/packs/sha256/*.pstrap; do
  [ -f "$object" ] || continue
  name=$(basename "$object" .pstrap)
  case "$name" in
    ""|*[!0-9a-f]*) printf 'invalid pack filename: %s\n' "$name" >&2; exit 1 ;;
  esac
  [ "${#name}" -eq 64 ] || {
    printf 'invalid pack filename: %s\n' "$name" >&2
    exit 1
  }
  observed=$(sha256sum "$object" | cut -d ' ' -f 1)
  [ "$observed" = "$name" ] || {
    printf 'pack digest does not match filename: %s\n' "$name" >&2
    exit 1
  }
  inspect="$tmp/inspect-$pack_count.json"
  "$extracted/proofstrap" inspect --digest "sha256:$name" "$object" > "$inspect"
  if grep -q '"kind"[[:space:]]*:[[:space:]]*"semantic"' "$inspect"; then
    semantic_count=$((semantic_count + 1))
    semantic_digest=$name
  elif grep -q '"kind"[[:space:]]*:[[:space:]]*"binding"' "$inspect"; then
    binding_count=$((binding_count + 1))
    binding_inspect=$inspect
  else
    printf 'pack inspection has unknown kind: %s\n' "$name" >&2
    exit 1
  fi
  pack_count=$((pack_count + 1))
done
[ "$pack_count" -eq 2 ] && [ "$semantic_count" -eq 1 ] && [ "$binding_count" -eq 1 ] || {
  printf 'archive must contain one semantic and one binding pack\n' >&2
  exit 1
}
[ "$(grep -c '"handle"' "$binding_inspect")" -eq 1 ] &&
  grep -q "\"digest\": \"sha256:$semantic_digest\"" "$binding_inspect" || {
  printf 'binding pack does not require the bundled semantic pack exactly\n' >&2
  exit 1
}

mkdir -p "$install_dir" "$releases"
stage=$(mktemp -d "$releases/.stage.XXXXXX")
mkdir -p "$stage/spec" "$stage/packs/sha256"
install -m 0755 "$extracted/proofstrap" "$stage/proofstrap"
install -m 0755 "$extracted/proofstrap-pack" "$stage/proofstrap-pack"
install -m 0644 "$extracted/README.md" "$stage/README.md"
install -m 0644 "$extracted/LICENSE" "$stage/LICENSE"
install -m 0644 "$extracted/spec/config.md" "$stage/spec/config.md"
install -m 0644 "$extracted/spec/profile.md" "$stage/spec/profile.md"
for object in "$extracted"/packs/sha256/*.pstrap; do
  install -m 0444 "$object" "$stage/packs/sha256/$(basename "$object")"
done
final="$releases/$generation"
[ ! -e "$final" ] || {
  printf 'release generation already exists: %s\n' "$generation" >&2
  exit 1
}
mv -T -n -- "$stage" "$final"
[ ! -e "$stage" ] || {
  printf 'release generation publication conflicted\n' >&2
  exit 1
}
stage=

if [ -e "$launcher" ] && [ ! -L "$launcher" ]; then
  [ -f "$launcher" ] || {
    printf 'existing launcher is not a regular file or symlink\n' >&2
    exit 1
  }
  legacy_hash=$(sha256sum "$launcher" | cut -d ' ' -f 1)
  legacy="$releases/legacy-$legacy_hash"
  if [ ! -e "$legacy" ]; then
    legacy_stage=$(mktemp -d "$releases/.legacy.XXXXXX")
    install -m 0755 "$launcher" "$legacy_stage/proofstrap"
    mv -T -n -- "$legacy_stage" "$legacy"
    [ ! -e "$legacy_stage" ] || {
      rm -rf -- "$legacy_stage"
      printf 'legacy generation publication conflicted\n' >&2
      exit 1
    }
  fi
fi

link_tmp="$install_dir/.proofstrap-link.$$"
[ ! -e "$link_tmp" ] || {
  printf 'launcher staging name already exists\n' >&2
  exit 1
}
ln -s ".proofstrap-releases/$generation/proofstrap" "$link_tmp"
mv -Tf -- "$link_tmp" "$launcher"
link_tmp=
