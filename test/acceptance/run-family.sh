#!/bin/sh
set -eu

usage() {
  printf 'usage: %s alpine packages-services | tumbleweed all\n' "$0" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
family=$1
scenario=$2
case "$family:$scenario" in
  alpine:packages-services|tumbleweed:all) ;;
  *) usage ;;
esac
[ "$(uname -m)" = x86_64 ] || { printf 'acceptance requires an x86_64 host\n' >&2; exit 1; }

root_command() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo -- "$@"
  fi
}

required='curl sha256sum tar timeout systemd-run systemd-nspawn machinectl nsenter mountpoint'
[ "$(id -u)" -eq 0 ] || required="$required sudo"
[ "$family" = alpine ] || required="$required zypper rpm systemd-machine-id-setup"
for command in $required; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'missing host prerequisite: %s\n' "$command" >&2
    exit 1
  }
done
command -v go >/dev/null 2>&1 || { printf 'missing host prerequisite: go\n' >&2; exit 1; }
[ "$(systemctl is-system-running)" = running ] || {
  printf 'host systemd is not running\n' >&2
  exit 1
}
if [ "$(id -u)" -ne 0 ]; then
  sudo -n true 2>/dev/null || {
    printf 'acceptance requires root or non-interactive sudo authority\n' >&2
    exit 1
  }
fi

project=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
store=/var/tmp/proofstrap-acceptance
target=$store/$family-root
sentinel=$store/.proofstrap-family-acceptance-v1
unit=proofstrap-$family-acceptance.service
machine=proofstrap-$family-acceptance
work=$(mktemp -d)
started=false

machine_absent() {
  ! root_command machinectl list --no-legend | awk '{print $1}' | grep -Fxq "$machine"
}

stop_target() {
  if root_command systemctl is-active --quiet "$unit" 2>/dev/null; then
    root_command timeout 10 systemctl stop "$unit" || true
  fi
  if ! machine_absent; then
    root_command machinectl terminate "$machine"
    for attempt in $(seq 1 100); do
      machine_absent && break
      sleep 0.1
    done
  fi
  started=false
  machine_absent && ! root_command systemctl is-active --quiet "$unit" 2>/dev/null
}

cleanup() {
  status=$?
  trap - EXIT
  set +e
  cleanup_failed=false
  stop_target || cleanup_failed=true
  if [ -e "$store" ]; then
    resolved=$(root_command readlink -f "$store")
    value=$(root_command cat "$sentinel" 2>/dev/null)
    if [ "$resolved" = "$store" ] && [ "$value" = proofstrap-family-acceptance-v1 ] &&
       ! root_command mountpoint -q "$target" &&
       ! grep -F " $target/" /proc/self/mountinfo >/dev/null && machine_absent; then
      root_command rm -rf -- "$store"
    else
      printf 'cleanup refused uncertain acceptance target: %s\n' "$store" >&2
      cleanup_failed=true
    fi
  fi
  rm -rf -- "$work"
  if [ "$cleanup_failed" = true ] && [ "$status" -eq 0 ]; then status=1; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

[ ! -e "$store" ] || { printf 'acceptance store already exists: %s\n' "$store" >&2; exit 1; }
printf 'proofstrap-family-acceptance-v1\n' > "$work/sentinel"
root_command install -d -m 0700 -o root -g root "$store" "$target"
root_command install -m 0600 -o root -g root "$work/sentinel" "$sentinel"

"$project/test/release/fetch-assets.sh" "$work/assets"
"$project/test/release/build.sh" "$work/dist" "$work/assets"
release=$work/dist/proofstrap_linux_amd64.tar.gz
release_hash=$(sha256sum "$release" | awk '{print $1}')

prepare_alpine() {
  archive=$work/alpine-minirootfs.tar.gz
  url=https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.1-x86_64.tar.gz
  expected=41f73e3cf5fa919b8aa5ca6b30dc48f0da2720776d7423e2a7748211456fe081
  curl --fail --location --show-error --silent --output "$archive" "$url"
  [ "$(sha256sum "$archive" | awk '{print $1}')" = "$expected" ] || {
    printf 'Alpine minirootfs digest mismatch\n' >&2
    return 1
	  }
	  root_command tar -xzf "$archive" -C "$target"
	  root_command chroot "$target" /sbin/apk add --no-cache openrc openssh-server ca-certificates
}

prepare_tumbleweed() {
  root_command zypper --installroot "$target" --non-interactive --gpg-auto-import-keys \
    install --no-recommends systemd zypper rpm shadow timezone openssh ca-certificates glibc
  for key in /usr/lib/rpm/gnupg/keys/*.asc; do
    root_command rpm --root "$target" --import "$key"
  done
  root_command systemd-machine-id-setup --root="$target"
  root_command install -d "$target/etc/zypp/repos.d" "$target/etc/zypp/services.d" \
    "$target/usr/share/zypp/local/service"
  root_command cp -a /etc/zypp/repos.d/. "$target/etc/zypp/repos.d/"
  if [ -d /etc/zypp/services.d ]; then
    root_command cp -a /etc/zypp/services.d/. "$target/etc/zypp/services.d/"
  fi
  root_command cp -a /usr/share/zypp/local/service/openSUSE "$target/usr/share/zypp/local/service/"
  root_command zypper --root "$target" --non-interactive modifyrepo --disable openSUSE:repo-openh264
}

if [ "$family" = alpine ]; then prepare_alpine; else prepare_tumbleweed; fi
root_command install -d "$target/opt" "$target/etc"
printf 'nameserver 1.1.1.1\n' > "$work/resolv.conf"
root_command install -m 0644 "$work/resolv.conf" "$target/etc/resolv.conf"
root_command tar -xzf "$release" -C "$target/opt"
root_command install -m 0644 "$project/examples/alpine.toml" "$target/etc/proofstrap.toml"

leader=
enter_target() {
  root_command nsenter --target "$leader" --mount --uts --ipc --net --pid --root --wd -- "$@"
}

start_target() {
  private=$1
  network=
  [ "$private" = true ] && network=--private-network
  root_command systemd-run --unit="$unit" --service-type=exec --collect \
    /usr/bin/systemd-nspawn --quiet --directory="$target" --machine="$machine" \
    --resolv-conf=off --keep-unit $network --boot
  started=true
  leader=
  for attempt in $(seq 1 30); do
    leader=$(root_command machinectl show "$machine" --property=Leader --value 2>/dev/null || true)
    if [ -n "$leader" ]; then
      if [ "$family" = alpine ]; then
        if enter_target /bin/true >/dev/null 2>&1; then
          enter_target openrc sysinit >/dev/null 2>&1 || true
          enter_target openrc boot >/dev/null 2>&1 || true
          enter_target openrc default >/dev/null 2>&1 || true
          enter_target rc-status --runlevel >/dev/null 2>&1 && return 0
        fi
	      else
	        state=$(enter_target systemctl is-system-running 2>/dev/null || true)
	        case "$state" in running|degraded) return 0 ;; esac
	      fi
    fi
    sleep 1
  done
	  printf 'target init did not become ready: %s\n' "${state:-unknown}" >&2
  return 1
}

clear_outputs() {
  root_command rm -f -- "$target/root/plan.json" "$target/root/journal.json" "$target/root/receipt.json"
}

plan_target() {
  clear_outputs
  set +e
  plan_output=$(enter_target /opt/proofstrap_linux_amd64/proofstrap plan \
    --config /etc/proofstrap.toml --output /root/plan.json 2>&1)
  plan_exit=$?
  set -e
  printf '%s\n' "$plan_output"
  [ "$plan_exit" -eq 0 ] || return "$plan_exit"
  digest=$(printf '%s\n' "$plan_output" | sed -n 's/^digest: //p')
  [ "$(printf '%s\n' "$digest" | wc -l)" -eq 1 ] && [ -n "$digest" ]
}

apply_target() {
  expected_exit=$1
  set +e
  enter_target /opt/proofstrap_linux_amd64/proofstrap apply --plan /root/plan.json \
    --accept "$digest" --journal /root/journal.json --receipt /root/receipt.json
  actual_exit=$?
  set -e
  [ "$actual_exit" -eq "$expected_exit" ] || {
    printf 'Apply exit %s, expected %s\n' "$actual_exit" "$expected_exit" >&2
    if [ "$family" = alpine ]; then
      enter_target rc-service sshd status || true
      enter_target ps -o pid,stat,comm,args || true
    fi
    return 1
  }
}

start_target false
if [ "$family" = alpine ]; then
  enter_target apk update
else
  enter_target zypper --non-interactive --gpg-auto-import-keys refresh
fi
plan_target
printf '%s\n' "$plan_output" | grep -F 'operation: package:' >/dev/null
printf '%s\n' "$plan_output" | grep -F ':barrier' >/dev/null
apply_target 3
enter_target grep -F '"status":"partial"' /root/receipt.json >/dev/null
if [ "$family" = alpine ]; then
  enter_target apk info --exists ca-certificates curl git gzip tar vim openssh-server
  enter_target ssh-keygen -A
else
  enter_target rpm -q ca-certificates curl git gzip tar vim openssh-server
fi

stop_target
start_target true
if [ "$family" = alpine ]; then enter_target /bin/busybox ip link set lo up; fi
plan_target
printf '%s\n' "$plan_output" | grep -F 'operation: service:' >/dev/null
apply_target 0
enter_target grep -F '"status":"converged"' /root/receipt.json >/dev/null
if [ "$family" = alpine ]; then
  enter_target rc-update show default | grep -F sshd >/dev/null
  enter_target rc-service sshd status
else
  [ "$(enter_target systemctl is-enabled sshd.service)" = enabled ]
  [ "$(enter_target systemctl is-active sshd.service)" = active ]
fi

plan_target
! printf '%s\n' "$plan_output" | grep -q '^operation:'
apply_target 0
enter_target grep -F '"status":"converged","operations":[]' /root/receipt.json >/dev/null
printf 'acceptance: %s %s release=sha256:%s converged\n' "$family" "$scenario" "$release_hash"
