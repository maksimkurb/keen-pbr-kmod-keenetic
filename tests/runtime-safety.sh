#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/id" <<'EOF'
#!/bin/sh
echo 0
EOF
cat >"$tmp/jq" <<'EOF'
#!/bin/sh
case "$4" in
	0x10000000) echo 268435456 ;;
	0x20000000) echo 536870912 ;;
	0x30000000) echo 805306368 ;;
	*) exit 1 ;;
esac
EOF
cat >"$tmp/ndmc" <<'EOF'
#!/bin/sh
echo 'hw_id: KN-9999'
EOF
cat >"$tmp/insmod" <<'EOF'
#!/bin/sh
touch "$INS_MOD_CALLED"
EOF
chmod +x "$tmp/id" "$tmp/jq" "$tmp/ndmc" "$tmp/insmod"

set +e
output=$(PATH="$tmp:$PATH" INS_MOD_CALLED="$tmp/insmod.called" \
	sh "$root/scripts/smoke-test.sh" /missing manifest-sha KN-1810 ipv4 \
	/missing eth0 198.51.100.2 443 0x10000000 0x30000000 --allow-experimental 2>&1)
status=$?
set -e
[ "$status" -ne 0 ] || { echo "expected model mismatch rejection" >&2; exit 1; }
case "$output" in *"router reports 'KN-9999'"*) ;; *) echo "$output" >&2; exit 1 ;; esac
[ ! -e "$tmp/insmod.called" ] || { echo "insmod ran before model validation" >&2; exit 1; }
echo "runtime identity refusal passed"
