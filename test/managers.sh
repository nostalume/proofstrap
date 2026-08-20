#!/bin/sh
set -eu
LC_ALL=C; export LC_ALL

if [ "${1:-}" = _enter ]; then
	target=$2; shift 2
	mount -t proc proc "$target/proc"
	for device in null zero random urandom console tty; do mount --bind "/dev/$device" "$target/dev/$device"; done
	exec chroot "$target" "$@"
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd); version=$(cat "$root/test/managers-version")
pins=$root/test/managers.sha256; cache=${PROOFSTRAP_MANAGER_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/proofstrap/cases/$version}
base=https://github.com/nostalume/proofstrap/releases/download/$version; generation= part= leader= leader_start= supervisor= supervisor_start= tier= case_id= reported=0
outer_uid=$(id -u); outer_gid=$(id -g); login=$(id -un)
subuid=$(awk -F: -v user="$login" '$1 == user && $3 >= 65535 { print $2; exit }' /etc/subuid 2>/dev/null || :); subgid=$(awk -F: -v user="$login" '$1 == user && $3 >= 65535 { print $2; exit }' /etc/subgid 2>/dev/null || :)

result() { reported=1; printf '%s case=%s %s\n' "$1" "$case_id" "$2"; }
fail() { result FAIL "$1" >&2; exit 1; }
unavailable() { result UNAVAILABLE "$1" >&2; exit 69; }
same_process() { [ -r "/proc/$1/stat" ] && [ "$(awk '{print $22}' "/proc/$1/stat")" = "$2" ]; }
find_leader() {
	expected=$1; count=0; while [ "$count" -lt 200 ]; do
		children=$(pgrep -P "$supervisor" || :); if [ "$(printf '%s\n' "$children" | awk 'NF {n++} END {print n+0}')" -eq 1 ] && [ "$(cat "/proc/$children/comm" 2>/dev/null || :)" = "$expected" ]; then leader=$children; leader_start=$(awk '{print $22}' "/proc/$leader/stat"); return; fi
		count=$((count + 1)); sleep .1
	done; fail "reason=target-leader"
}

stop_target() {
	if [ "$tier" = openrc ]; then pid=$leader; born=$leader_start; else pid=${supervisor:-$leader}; born=${supervisor_start:-$leader_start}; fi
	[ -n "$pid" ] || return 0; fallback=0
	if same_process "$pid" "$born"; then
		kill -TERM "$pid"; count=0
		while same_process "$pid" "$born" && [ "$count" -lt 100 ]; do count=$((count + 1)); sleep .1; done
		if same_process "$pid" "$born"; then kill -KILL "$pid"; fallback=1; fi
	fi
	[ -z "$supervisor" ] || wait "$supervisor" 2>/dev/null || :
	if { [ -n "$leader" ] && same_process "$leader" "$leader_start"; } || { [ -n "$supervisor" ] && same_process "$supervisor" "$supervisor_start"; }; then return 1; fi
	leader= leader_start= supervisor= supervisor_start=; return "$fallback"
}

remove_generation() {
	if [ "$outer_uid" -eq 0 ]; then rm -rf "$generation"
	else unshare --map-users "0:$outer_uid:1" --map-users "1:$subuid:65535" --map-groups "0:$outer_gid:1" --map-groups "1:$subgid:65535" -- /bin/rm -rf "$generation"; fi
}

cleanup() {
	status=$?; [ "$status" -eq 0 ] || [ "$reported" -eq 1 ] || result FAIL "reason=command" >&2
	[ -z "$part" ] || rm -f "$part"; stop_target || status=1
	if [ -n "$generation" ]; then
		if [ -f "$generation/SENTINEL.proofstrap-manager" ] && [ -z "$leader" ] && [ -z "$supervisor" ] && ! grep -F "$generation/root" /proc/self/mountinfo >/dev/null 2>&1; then
			remove_generation
		else
			result FAIL "cleanup=$generation" >&2; status=1
		fi
	fi
	exit "$status"
}
trap cleanup EXIT HUP INT TERM

select_case() {
	case "$case_id" in
		package:apt) physical=package-apt; domain=package; backend=apt; tier=package ;;
		package:dnf4) physical=package-dnf4; domain=package; backend=dnf4; tier=package ;;
		package:dnf5) physical=package-dnf5; domain=package; backend=dnf5; tier=package ;;
		package:zypper) physical=package-zypper-systemd; domain=package; backend=zypper; tier=package ;;
		package:apk) physical=package-apk-openrc; domain=package; backend=apk; tier=package ;;
		service:systemd) physical=package-zypper-systemd; domain=service; backend=systemd; tier=systemd ;;
		service:openrc) physical=package-apk-openrc; domain=service; backend=openrc; tier=openrc ;;
		*) fail "reason=unknown-case" ;;
	esac
	archive=${physical}_linux_amd64.tar.gz
	digest=$(awk -v name="$archive" '$2 == name { print $1 }' "$pins")
	[ "${#digest}" -eq 64 ] || fail "reason=missing-pin"
}

resolve_case() {
	[ "$(uname -m)" = x86_64 ] || unavailable "reason=architecture"
	mkdir -p "$cache"; object=$cache/$archive
	if [ ! -f "$object" ]; then
		command -v curl >/dev/null || unavailable "reason=curl"; part=$(mktemp "$cache/.${archive}.XXXXXX")
		curl -fL --proto '=https' --tlsv1.2 "$base/$archive" -o "$part" || { rm -f "$part"; fail "reason=download"; }
		printf '%s  %s\n' "$digest" "$part" | sha256sum -c - >/dev/null 2>&1 || { rm -f "$part"; fail "reason=digest"; }
		mv "$part" "$object"; part=
	fi
	printf '%s  %s\n' "$digest" "$object" | sha256sum -c - >/dev/null 2>&1 || fail "reason=digest"
}

enter() {
	case "$tier" in
		package)
			if [ "$outer_uid" -eq 0 ]; then unshare --mount --uts --ipc --pid --fork --kill-child=TERM --net -- "$root/test/managers.sh" _enter "$target" "$@"
			else unshare --map-users "0:$outer_uid:1" --map-users "1:$subuid:65535" --map-groups "0:$outer_gid:1" --map-groups "1:$subgid:65535" --mount --uts --ipc --pid --fork --kill-child=TERM --net -- "$root/test/managers.sh" _enter "$target" "$@"; fi ;;
		openrc) nsenter --target "$leader" --user --preserve-credentials --mount --uts --ipc --net --pid --root --wd -- "$@" ;;
		systemd) nsenter --target "$leader" --mount --uts --ipc --net --pid --root --wd -- "$@" ;;
	esac
}

wait_ready() {
	count=0; while [ "$count" -lt 200 ]; do
		case "$tier" in
			openrc) enter /sbin/openrc default >> "$generation/target.log" 2>&1 && return ;;
			systemd) enter /usr/bin/systemctl is-system-running > "$generation/ready" 2>&1 && return ;;
		esac
		count=$((count + 1)); sleep .1
	done
	detail=$(tr '\n' '_' < "$generation/target.log"); ready=$(tr '\n' '_' < "$generation/ready" 2>/dev/null || :); fail "reason=target-timeout detail=$detail ready=$ready"
}

start_target() {
	case "$tier" in
		package) return ;;
		openrc)
			unshare --user --map-root-user --mount --uts --ipc --pid --fork --kill-child=TERM --net --cgroup -- "$root/test/managers.sh" _enter "$target" /sbin/init > "$generation/target.log" 2>&1 &
			supervisor=$!; supervisor_start=$(awk '{print $22}' "/proc/$supervisor/stat")
			find_leader init ;;
		systemd)
			[ "$(id -u)" -eq 0 ] || unavailable "reason=root-authority"
			machine=proofstrap-${case_id#service:}-$$
			systemd-nspawn --boot --register=no --private-network --link-journal=no --settings=no --machine="$machine" --directory="$target" > "$generation/target.log" 2>&1 &
			supervisor=$!; supervisor_start=$(awk '{print $22}' "/proc/$supervisor/stat")
			find_leader systemd ;;
	esac
	wait_ready
}

native_package() {
	case "$backend" in
		apt)
			enter /usr/bin/dpkg-query -W '-f=${binary:Package}\n' proofstrap-fixture proofstrap-fixture-dependency > "$generation/native"
			enter /usr/bin/apt-mark showmanual > "$generation/roots" ;;
		dnf4)
			enter /usr/bin/rpm -q --queryformat '%{NAME}\n' proofstrap-fixture proofstrap-fixture-dependency > "$generation/native"
			[ "$(enter /usr/bin/dnf --cacheonly --quiet repoquery --installed '--queryformat=%{reason}' proofstrap-fixture)" = user ]
			[ "$(enter /usr/bin/dnf --cacheonly --quiet repoquery --installed '--queryformat=%{reason}' proofstrap-fixture-dependency)" = dependency ] ;;
		dnf5)
			enter /usr/bin/rpm -q --queryformat '%{NAME}\n' proofstrap-fixture proofstrap-fixture-dependency > "$generation/native"
			[ "$(enter /usr/bin/dnf5 --setopt=cacheonly=metadata repoquery --installed '--queryformat=%{reason}' proofstrap-fixture)" = User ]
			[ "$(enter /usr/bin/dnf5 --setopt=cacheonly=metadata repoquery --installed '--queryformat=%{reason}' proofstrap-fixture-dependency)" = Dependency ] ;;
		zypper)
			enter /usr/bin/rpm -q --queryformat '%{NAME}\n' proofstrap-fixture proofstrap-fixture-dependency > "$generation/native"
			enter /usr/bin/cat /var/lib/zypp/AutoInstalled > "$generation/roots" ;;
		apk)
			enter /sbin/apk info -e proofstrap-fixture proofstrap-fixture-dependency > "$generation/native"
			enter /bin/cat /etc/apk/world > "$generation/roots" ;;
	esac
	grep -Fx proofstrap-fixture "$generation/native" >/dev/null
	grep -Fx proofstrap-fixture-dependency "$generation/native" >/dev/null
	case "$backend" in
		dnf4|dnf5) : ;;
		zypper) grep -Fx proofstrap-fixture-dependency "$generation/roots" >/dev/null; ! grep -Fx proofstrap-fixture "$generation/roots" >/dev/null ;;
		*) grep -Fx proofstrap-fixture "$generation/roots" >/dev/null; ! grep -Fx proofstrap-fixture-dependency "$generation/roots" >/dev/null ;;
	esac
}

native_service() {
	case "$backend" in
		systemd) [ "$(enter /usr/bin/systemctl is-enabled proofstrap-fixture.service)" = enabled ] && [ "$(enter /usr/bin/systemctl is-active proofstrap-fixture.service)" = active ] ;;
		openrc) enter /sbin/rc-update show default | grep -w proofstrap-fixture >/dev/null; enter /sbin/rc-service proofstrap-fixture status >/dev/null ;;
	esac
}

manager_version() {
	case "$backend" in
		apt) set -- /usr/bin/apt --version ;; dnf4) set -- /usr/bin/dnf --version ;;
		dnf5) set -- /usr/bin/dnf5 --version ;; zypper) set -- /usr/bin/zypper --version ;;
		apk) set -- /sbin/apk --version ;; systemd) set -- /usr/bin/systemctl --version ;;
		openrc) set -- /bin/rc-status --version ;;
	esac
	enter "$@" > "$generation/version"; native_version=$(sed -n '1{s/[[:space:]][[:space:]]*/_/g;p;}' "$generation/version")
}

run_case() {
	case_id=$1; reported=0; began=$(date +%s); select_case; resolve_case
	for tool in tar sha256sum unshare nsenter mount chroot pgrep; do command -v "$tool" >/dev/null || unavailable "reason=$tool"; done
	[ "$outer_uid" -eq 0 ] || [ "$tier" != package ] || { [ -n "$subuid" ] && [ -n "$subgid" ]; } || unavailable "reason=subids"
	generation=$(mktemp -d "${TMPDIR:-/tmp}/proofstrap-manager.XXXXXX")
	touch "$generation/SENTINEL.proofstrap-manager"
	tar --no-same-owner -xzf "$object" -C "$generation"
	target=$generation/root; work=$target/proofstrap-case; mkdir -p "$work"
	for device in null zero random urandom console tty; do [ -e "$target/dev/$device" ] || : > "$target/dev/$device"; done
	install -m 0755 "$generation/proofstrap" "$work/proofstrap"
	install -m 0444 "$generation/semantic.pstrap" "$generation/binding.pstrap" "$work/"
	config=${domain}.toml; install -m 0444 "$generation/$config" "$work/$config"
	start_target
	pass=0
	while :; do
		plan=/proofstrap-case/plan.$pass.json
		receipt_file=/proofstrap-case/receipt.$pass.json
		journal_file=/proofstrap-case/journal.$pass
		if ! enter /proofstrap-case/proofstrap plan --config "/proofstrap-case/$config" --output "$plan" --profile-bundle /proofstrap-case/semantic.pstrap --profile-bundle /proofstrap-case/binding.pstrap > "$generation/review" 2> "$generation/plan.err"; then detail=$(tr '\n' '_' < "$generation/plan.err"); review=$(tr '\n' '_' < "$generation/review"); fail "reason=plan detail=$detail review=$review"; fi
		digest_plan=$(sed -n 's/^digest: //p' "$generation/review"); [ "${#digest_plan}" -eq 71 ] || fail "reason=plan"
		if enter /proofstrap-case/proofstrap apply --plan "$plan" --accept "$digest_plan" --journal "$journal_file" --receipt "$receipt_file" > "$generation/receipt" 2> "$generation/apply.err"; then apply_status=0; else apply_status=$?; fi
		[ "$apply_status" -eq 0 ] && break
		if [ "$apply_status" -eq 3 ] && [ "$pass" -eq 0 ] && grep -F '"status":"partial"' "$generation/receipt" >/dev/null && [ -s "$target$journal_file" ]; then pass=1; continue; fi
		detail=$(tr '\n' '_' < "$generation/apply.err"); receipt=$(tr '\n' '_' < "$generation/receipt"); fail "reason=apply code=$apply_status detail=$detail receipt=$receipt"
	done
	cmp "$generation/receipt" "$target$receipt_file"; [ -s "$target$journal_file" ]
	if [ "$domain" = package ]; then native_package; else native_service; fi
	if ! enter /proofstrap-case/proofstrap plan --config "/proofstrap-case/$config" --output /proofstrap-case/after.json --profile-bundle /proofstrap-case/semantic.pstrap --profile-bundle /proofstrap-case/binding.pstrap > "$generation/after" 2> "$generation/after.err"; then
		detail=$(tr '\n' '_' < "$generation/after.err"); review=$(tr '\n' '_' < "$generation/after"); fail "reason=replan detail=$detail review=$review"
	fi
	grep -F '"operations":[]' "$work/after.json" >/dev/null
	tool_digest=$(sha256sum "$generation/proofstrap" | awk '{print $1}')
	manager_version; [ -n "$native_version" ]
	stop_target || fail "reason=kill-fallback"
	duration=$(($(date +%s) - began))
	result PASS "domain=$domain backend=$backend version=$native_version tool=$tool_digest archive=$digest arch=amd64 duration=${duration}s"
	remove_generation; generation=
}

[ "$version" = cases-v1 ] || { case_id=setup; fail "reason=version"; }
[ -f "$pins" ] && [ "$(wc -l < "$pins")" -eq 5 ] || { case_id=setup; fail "reason=pins"; }
if [ "$#" -eq 0 ]; then set -- package:apt package:dnf4 package:dnf5 package:zypper package:apk service:systemd service:openrc; fi
for selected in "$@"; do run_case "$selected"; done
trap - EXIT HUP INT TERM
