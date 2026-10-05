#!/bin/sh
set -eu

usage() {
	cat >&2 <<'EOF'
Usage: smoke-test.sh MANIFEST MANIFEST_SHA256 MODEL ipv4|ipv6 MODULE IFACE SOURCE PORT MARK MASK [--allow-experimental]
Run on the target Keenetic after arranging an external TCP packet to SOURCE:PORT.
MARK/MASK must use bits reserved for this test. The test leaves the module loaded.
EOF
	exit 2
}

[ "$#" -eq 10 ] || [ "$#" -eq 11 ] || usage
manifest=$1 manifest_sha=$2 model=$3 family=$4 module=$5 iface=$6 source=$7 port=$8 mark=$9
shift 9
mask=$1
shift
allow_experimental=0
if [ "$#" -eq 1 ] && [ "$1" = --allow-experimental ]; then
	allow_experimental=1
elif [ "$#" -ne 0 ]; then
	usage
fi

fail() { echo "smoke-test: $*" >&2; exit 1; }
case "$model" in KN-[0-9][0-9][0-9][0-9]) ;; *) fail "invalid model: $model" ;; esac
case "$family" in ipv4|ipv6) ;; *) usage ;; esac
case "$iface" in ''|*[!A-Za-z0-9_.:-]*) fail "invalid interface" ;; esac
case "$source" in ''|-*|*[!A-Za-z0-9:.]*) fail "invalid source address" ;; esac
case "$port" in ''|*[!0-9]*) fail "port must be numeric" ;; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || fail "port out of range"

[ "$(id -u)" = 0 ] || fail "must run as root"
command -v jq >/dev/null 2>&1 || fail "jq is required to read the release manifest"
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
mark_num=$(to_decimal "$mark") || fail "MARK must be a decimal or 32-bit hex value"
mask_num=$(to_decimal "$mask") || fail "MASK must be a decimal or 32-bit hex value"
[ "$mask_num" -ne 0 ] || fail "MASK must be nonzero"
[ "$mark_num" -le "$mask_num" ] || fail "MARK must fit within MASK"
actual_model=$(ndmc -c 'show version' | awk -F: '$1 ~ /^[[:space:]]*hw_id[[:space:]]*$/ { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit }')
case "$actual_model" in NC-[0-9][0-9][0-9][0-9]) actual_model=KN-${actual_model#NC-} ;; esac
[ "$actual_model" = "$model" ] || fail "requested $model but this router reports '${actual_model:-unknown}'"
[ -r "$manifest" ] || fail "cannot read manifest: $manifest"
[ -r "$module" ] || fail "cannot read module: $module"
actual_manifest_sha=$(sha256sum "$manifest" | awk '{print $1}')
[ "$actual_manifest_sha" = "$manifest_sha" ] || fail "manifest SHA256 mismatch"

group=$(jq -er --arg model "$model" '.models[$model].group' "$manifest") || fail "model is absent from manifest"
status=$(jq -er --arg model "$model" '.models[$model].status' "$manifest") || fail "model has no compatibility status"
case "$status" in
	verified|compatible) ;;
	experimental)
		[ "$allow_experimental" -eq 1 ] || fail "$model is experimental; pass --allow-experimental to test it explicitly"
		;;
	*) fail "$model status '$status' does not permit loading" ;;
esac
expected_file=$(jq -er --arg group "$group" --arg family "$family" '.groups[$group].modules[$family].file' "$manifest") || fail "module is unavailable for $group/$family"
expected_sha=$(jq -er --arg group "$group" --arg family "$family" '.groups[$group].modules[$family].sha256' "$manifest") || fail "module hash is missing from manifest"
expected_vermagic=$(jq -er --arg group "$group" --arg family "$family" '.groups[$group].modules[$family].vermagic' "$manifest") || fail "module vermagic is missing from manifest"
expected_version=$(jq -er '.version' "$manifest") || fail "release version is missing from manifest"
expected_priority=$(jq -er '.contract.priority' "$manifest") || fail "compiled priority is missing from manifest"
expected_abi=$(jq -er '.contract.table_abi' "$manifest") || fail "table ABI is missing from manifest"
[ "$(basename "$module")" = "$expected_file" ] || fail "expected $expected_file for $model, got $(basename "$module")"
actual_module_sha=$(sha256sum "$module" | awk '{print $1}')
[ "$actual_module_sha" = "$expected_sha" ] || fail "module SHA256 mismatch"
[ "${expected_vermagic%% *}" = "$(uname -r)" ] || fail "manifest vermagic kernel does not match uname -r"
if command -v modinfo >/dev/null 2>&1; then
	actual_vermagic=$(modinfo -F vermagic "$module")
	[ "$actual_vermagic" = "$expected_vermagic" ] || fail "module vermagic differs from manifest"
	[ "$(modinfo -F keenpbr_priority "$module")" = "$expected_priority" ] || fail "embedded module priority differs from manifest"
	[ "$(modinfo -F keenpbr_table_abi "$module")" = "$expected_abi" ] || fail "embedded table ABI differs from manifest"
fi

if [ "$family" = ipv4 ]; then
	ipt=iptables
	restore=iptables-restore
	module_name=iptable_keenpbr
	ipset_family=inet
else
	ipt=ip6tables
	restore=ip6tables-restore
	module_name=ip6table_keenpbr
	ipset_family=inet6
fi
command -v "$ipt" >/dev/null 2>&1 || fail "$ipt is required"
command -v "$restore" >/dev/null 2>&1 || fail "$restore is required"
command -v ipset >/dev/null 2>&1 || fail "ipset is required"
if grep -q "^${module_name} " /proc/modules 2>/dev/null; then
	fail "$module_name is already loaded; refusing to claim or alter a preexisting module"
fi

insmod "$module" || fail "insmod failed (kernel ABI or module dependency mismatch)"
[ "$(cat "/sys/module/$module_name/parameters/priority")" = "$expected_priority" ] || fail "loaded priority differs from manifest"
[ "$(cat "/sys/module/$module_name/parameters/table_abi")" = "$expected_abi" ] || fail "loaded table ABI differs from manifest"
[ "$(cat "/sys/module/$module_name/version")" = "$expected_version" ] || fail "loaded version differs from manifest"

chain=KPSMOKE_$$
restore_chain=KPREST_$$
set_name=kpsmoke_$$
jump_added=0
chain_added=0
restore_added=0
set_added=0
# This cleanup function is invoked by the EXIT trap.
# shellcheck disable=SC2329
cleanup() {
	if [ "$jump_added" -eq 1 ]; then
		"$ipt" -t keenpbr -D PREROUTING -i "$iface" -s "$source" -p tcp -m multiport --dports "$port" -j "$chain" >/dev/null 2>&1 || :
	fi
	if [ "$chain_added" -eq 1 ]; then
		"$ipt" -t keenpbr -F "$chain" >/dev/null 2>&1 || :
		"$ipt" -t keenpbr -X "$chain" >/dev/null 2>&1 || :
	fi
	if [ "$restore_added" -eq 1 ]; then
		"$ipt" -t keenpbr -F "$restore_chain" >/dev/null 2>&1 || :
		"$ipt" -t keenpbr -X "$restore_chain" >/dev/null 2>&1 || :
	fi
	if [ "$set_added" -eq 1 ]; then ipset destroy "$set_name" >/dev/null 2>&1 || :; fi
}
trap 'cleanup' EXIT
trap 'exit 1' HUP INT TERM

ipset create "$set_name" hash:ip family "$ipset_family"
set_added=1
ipset add "$set_name" "$source"
"$ipt" -t keenpbr -N "$chain"
chain_added=1
"$ipt" -t keenpbr -A "$chain" -m set --match-set "$set_name" src -p tcp -m multiport --dports "$port" -m dscp --dscp-class CS0 -j MARK --set-xmark "$mark/$mask"
"$ipt" -t keenpbr -A "$chain" -j RETURN
"$ipt" -t keenpbr -I PREROUTING 1 -i "$iface" -s "$source" -p tcp -m multiport --dports "$port" -j "$chain"
jump_added=1

restore_added=1
printf '*keenpbr\n:%s - [0:0]\n-A %s -j RETURN\nCOMMIT\n' "$restore_chain" "$restore_chain" | "$restore" --noflush || fail "iptables-restore --noflush check failed"
"$ipt" -t keenpbr -L "$chain" -nvx >/dev/null || fail "counter listing failed"

echo "Send a TCP packet from $source to this router on $port through $iface with DSCP CS0. Waiting up to 60 seconds for its scoped rule counter."
count=0
while [ "$count" -lt 30 ]; do
	if "$ipt" -t keenpbr -L "$chain" -nvx | awk 'NR > 2 && $3 == "MARK" && $1 ~ /^[0-9]+$/ && $1 > 0 { hit=1 } END { exit !hit }'; then
		echo "MARK-rule counters after ingress:"
		"$ipt" -t keenpbr -L "$chain" -nvx
		exit 0
	fi
	sleep 2
	count=$((count + 1))
done
fail "no external ingress packet matched; the rule was removed"
