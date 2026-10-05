#!/bin/sh
set -eu

usage() {
	cat >&2 <<'EOF'
Usage: priority-test.sh MANIFEST MANIFEST_SHA256 MODEL ipv4|ipv6 MODULE IFACE SOURCE PORT MASK MARK_A MARK_B [--allow-experimental]
Run after smoke-test.sh loaded this exact group module. Send an external TCP packet to a host behind the router.
MASK must be unused by router policy; A and B should be distinct values within MASK.
EOF
	exit 2
}

[ "$#" -eq 11 ] || [ "$#" -eq 12 ] || usage
manifest=$1 manifest_sha=$2 model=$3 family=$4 module=$5 iface=$6 source=$7 port=$8 mask=$9
shift 9
mark_a=$1 mark_b=$2
shift 2
allow_experimental=0
if [ "$#" -eq 1 ] && [ "$1" = --allow-experimental ]; then
	allow_experimental=1
elif [ "$#" -ne 0 ]; then
	usage
fi

fail() { echo "priority-test: $*" >&2; exit 1; }
case "$model" in KN-[0-9][0-9][0-9][0-9]) ;; *) fail "invalid model: $model" ;; esac
case "$family" in ipv4|ipv6) ;; *) usage ;; esac
case "$iface" in ''|*[!A-Za-z0-9_.:-]*) fail "invalid interface" ;; esac
case "$source" in ''|-*|*[!A-Za-z0-9:.]*) fail "invalid source address" ;; esac
case "$port" in ''|*[!0-9]*) fail "port must be numeric" ;; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || fail "port out of range"
[ "$mark_a" != "$mark_b" ] || fail "MARK_A and MARK_B must differ"

[ "$(id -u)" = 0 ] || fail "must run as root"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
command -v ndmc >/dev/null 2>&1 || fail "ndmc is required to verify this router's hw_id"
to_decimal() {
	jq -nr --arg n "$1" '
		if ($n | test("^0[xX][0-9A-Fa-f]{1,8}$")) then
			reduce (($n[2:] | explode)[]) as $c (0; . * 16 + (if $c >= 48 and $c <= 57 then $c - 48 elif $c >= 65 and $c <= 70 then $c - 55 else $c - 87 end))
		elif ($n | test("^(0|[1-9][0-9]{0,9})$")) then $n | tonumber
		else error("invalid 32-bit mark value") end
		| if . <= 4294967295 then . else error("mark exceeds 32 bits") end
	' 2>/dev/null
}
mask_num=$(to_decimal "$mask") || fail "MASK must be a decimal or 32-bit hex value"
mark_a_num=$(to_decimal "$mark_a") || fail "MARK_A must be a decimal or 32-bit hex value"
mark_b_num=$(to_decimal "$mark_b") || fail "MARK_B must be a decimal or 32-bit hex value"
[ "$mask_num" -ne 0 ] || fail "MASK must be nonzero"
[ "$mark_a_num" -le "$mask_num" ] && [ "$mark_b_num" -le "$mask_num" ] || fail "marks must fit within MASK"
actual_model=$(ndmc -c 'show version' | awk -F: '$1 ~ /^[[:space:]]*hw_id[[:space:]]*$/ { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit }')
case "$actual_model" in NC-[0-9][0-9][0-9][0-9]) actual_model=KN-${actual_model#NC-} ;; esac
[ "$actual_model" = "$model" ] || fail "requested $model but this router reports '${actual_model:-unknown}'"
[ -r "$manifest" ] && [ -r "$module" ] || fail "manifest or module is unreadable"
[ "$(sha256sum "$manifest" | awk '{print $1}')" = "$manifest_sha" ] || fail "manifest SHA256 mismatch"
group=$(jq -er --arg model "$model" '.models[$model].group' "$manifest") || fail "model is absent from manifest"
status=$(jq -er --arg model "$model" '.models[$model].status' "$manifest") || fail "model has no compatibility status"
case "$status" in
	verified|compatible) ;;
	experimental) [ "$allow_experimental" -eq 1 ] || fail "$model is experimental; pass --allow-experimental" ;;
	*) fail "$model status '$status' does not permit a priority test" ;;
esac
expected_file=$(jq -er --arg group "$group" --arg family "$family" '.groups[$group].modules[$family].file' "$manifest") || fail "module is unavailable"
expected_sha=$(jq -er --arg group "$group" --arg family "$family" '.groups[$group].modules[$family].sha256' "$manifest") || fail "module hash missing"
expected_vermagic=$(jq -er --arg group "$group" --arg family "$family" '.groups[$group].modules[$family].vermagic' "$manifest") || fail "module vermagic missing"
expected_version=$(jq -er '.version' "$manifest") || fail "release version missing"
priority=$(jq -er '.contract.priority' "$manifest") || fail "compiled priority missing"
abi=$(jq -er '.contract.table_abi' "$manifest") || fail "table ABI missing"
[ "$(basename "$module")" = "$expected_file" ] || fail "wrong module file for $model/$group"
[ "$(sha256sum "$module" | awk '{print $1}')" = "$expected_sha" ] || fail "module SHA256 mismatch"
[ "${expected_vermagic%% *}" = "$(uname -r)" ] || fail "vermagic kernel does not match uname -r"
if command -v modinfo >/dev/null 2>&1; then
	[ "$(modinfo -F vermagic "$module")" = "$expected_vermagic" ] || fail "module vermagic differs from manifest"
	[ "$(modinfo -F keenpbr_priority "$module")" = "$priority" ] || fail "embedded priority differs from manifest"
	[ "$(modinfo -F keenpbr_table_abi "$module")" = "$abi" ] || fail "embedded table ABI differs from manifest"
fi

if [ "$family" = ipv4 ]; then
	ipt=iptables
	module_name=iptable_keenpbr
else
	ipt=ip6tables
	module_name=ip6table_keenpbr
fi
command -v "$ipt" >/dev/null 2>&1 || fail "$ipt is required"
grep -q "^${module_name} " /proc/modules || fail "$module_name must already be loaded by smoke-test.sh"
[ "$(cat "/sys/module/$module_name/parameters/priority")" = "$priority" ] || fail "loaded priority differs from manifest"
[ "$(cat "/sys/module/$module_name/parameters/table_abi")" = "$abi" ] || fail "loaded table ABI differs from manifest"
[ "$(cat "/sys/module/$module_name/version")" = "$expected_version" ] || fail "loaded version differs from manifest"

if [ "$priority" -lt -150 ]; then
	expected_mark=$mark_a
	order="keenpbr before mangle"
elif [ "$priority" -gt -150 ]; then
	expected_mark=$mark_b
	order="mangle before keenpbr"
else
	fail "priority -150 ties mangle; ordering is undefined"
fi

mangle_chain=KPMANG_$$
keen_chain=KPKEEN_$$
observe_chain=KPOBS_$$
mangle_jump=0
keen_jump=0
observe_jump=0
mangle_chain_added=0
keen_chain_added=0
observe_chain_added=0
# This cleanup function is invoked by the EXIT trap.
# shellcheck disable=SC2329
cleanup() {
	if [ "$observe_jump" -eq 1 ]; then "$ipt" -t filter -D FORWARD -i "$iface" -s "$source" -p tcp -m multiport --dports "$port" -j "$observe_chain" >/dev/null 2>&1 || :; fi
	if [ "$keen_jump" -eq 1 ]; then "$ipt" -t keenpbr -D PREROUTING -i "$iface" -s "$source" -p tcp -m multiport --dports "$port" -j "$keen_chain" >/dev/null 2>&1 || :; fi
	if [ "$mangle_jump" -eq 1 ]; then "$ipt" -t mangle -D PREROUTING -i "$iface" -s "$source" -p tcp -m multiport --dports "$port" -j "$mangle_chain" >/dev/null 2>&1 || :; fi
	if [ "$observe_chain_added" -eq 1 ]; then "$ipt" -t filter -F "$observe_chain" >/dev/null 2>&1 || :; "$ipt" -t filter -X "$observe_chain" >/dev/null 2>&1 || :; fi
	if [ "$keen_chain_added" -eq 1 ]; then "$ipt" -t keenpbr -F "$keen_chain" >/dev/null 2>&1 || :; "$ipt" -t keenpbr -X "$keen_chain" >/dev/null 2>&1 || :; fi
	if [ "$mangle_chain_added" -eq 1 ]; then "$ipt" -t mangle -F "$mangle_chain" >/dev/null 2>&1 || :; "$ipt" -t mangle -X "$mangle_chain" >/dev/null 2>&1 || :; fi
}
trap 'cleanup' EXIT
trap 'exit 1' HUP INT TERM

# These insertions affect only the supplied ingress interface/source/port.
"$ipt" -t mangle -N "$mangle_chain"
mangle_chain_added=1
"$ipt" -t mangle -A "$mangle_chain" -j MARK --set-xmark "$mark_a/$mask"
"$ipt" -t mangle -I PREROUTING 1 -i "$iface" -s "$source" -p tcp -m multiport --dports "$port" -j "$mangle_chain"
mangle_jump=1

"$ipt" -t keenpbr -N "$keen_chain"
keen_chain_added=1
"$ipt" -t keenpbr -A "$keen_chain" -j MARK --set-xmark "$mark_b/$mask"
"$ipt" -t keenpbr -I PREROUTING 1 -i "$iface" -s "$source" -p tcp -m multiport --dports "$port" -j "$keen_chain"
keen_jump=1

"$ipt" -t filter -N "$observe_chain"
observe_chain_added=1
"$ipt" -t filter -A "$observe_chain" -m mark --mark "$expected_mark/$mask" -j RETURN
"$ipt" -t filter -I FORWARD 1 -i "$iface" -s "$source" -p tcp -m multiport --dports "$port" -j "$observe_chain"
observe_jump=1

echo "Send an external TCP packet from $source through $iface to a host behind this router on port $port. Expect $order (mark $expected_mark/$mask); waiting 60 seconds."
count=0
while [ "$count" -lt 30 ]; do
	if "$ipt" -t mangle -L "$mangle_chain" -nvx | awk 'NR > 2 && $3 == "MARK" && $1 ~ /^[0-9]+$/ && $1 > 0 { hit=1 } END { exit !hit }' &&
	   "$ipt" -t keenpbr -L "$keen_chain" -nvx | awk 'NR > 2 && $3 == "MARK" && $1 ~ /^[0-9]+$/ && $1 > 0 { hit=1 } END { exit !hit }' &&
	   "$ipt" -t filter -L "$observe_chain" -nvx | awk 'NR > 2 && $3 == "RETURN" && $1 ~ /^[0-9]+$/ && $1 > 0 { hit=1 } END { exit !hit }'; then
		echo "Priority mark counters observed (shown before cleanup):"
		"$ipt" -t mangle -L "$mangle_chain" -nvx
		"$ipt" -t keenpbr -L "$keen_chain" -nvx
		"$ipt" -t filter -L "$observe_chain" -nvx
		exit 0
	fi
	sleep 2
	count=$((count + 1))
done
fail "expected mark not observed; temporary rules were removed"
