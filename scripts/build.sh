#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if (($# != 1)); then echo "usage: $0 <group|KN-model>" >&2; exit 2; fi
TARGET="$1"
SDK_DIR="${SDK_DIR:-$ROOT/.cache/keenetic-sdk}"
OUT_DIR="${OUT_DIR:-$ROOT/out}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
MODE="${KEENPBR_PRIORITY_MODE:-after-mangle}"
case "$JOBS" in ''|*[!0-9]*) echo "JOBS must be a positive integer" >&2; exit 2;; esac
(( JOBS > 0 && JOBS <= 128 )) || { echo "JOBS must be in 1..128" >&2; exit 2; }
TARGET_INFO="$(python3 - "$ROOT" "$TARGET" "$MODE" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/scripts")
from kmodlib import resolve_target, PRIORITIES
group, item = resolve_target(sys.argv[2])
mode = sys.argv[3]
if mode not in PRIORITIES: sys.exit("invalid priority mode: " + mode)
print(group, item["representative"], item["arch"], int(item["ipv6"]), PRIORITIES[mode], sep="\t")
PY
 )" || exit 2
IFS=$'\t' read -r GROUP MODEL ARCH IPV6 PRIORITY <<< "$TARGET_INFO"
"$ROOT/scripts/prepare-sdk.sh" >/dev/null
SDK_DIR="$(realpath "$SDK_DIR")"
mkdir -p "$OUT_DIR"
OUT_DIR="$(realpath "$OUT_DIR")"
[[ -f "$ROOT/package/Makefile" ]] || { echo "missing package/Makefile" >&2; exit 1; }
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$ ]] || { echo "invalid VERSION: $VERSION" >&2; exit 1; }
[[ -d "$ROOT/src" ]] || { echo "missing src/" >&2; exit 1; }
PKG="$SDK_DIR/package/kernel/keenpbr-table"
rm -rf -- "$PKG"
mkdir -p "$PKG"
cp -a "$ROOT/package/Makefile" "$ROOT/src" "$ROOT/LICENSE" "$ROOT/VERSION" "$PKG/"
cd "$SDK_DIR"
./configure.sh "$MODEL"
grep -qx 'CONFIG_PACKAGE_kmod-keenpbr-table=m' .config || printf '%s\n' 'CONFIG_PACKAGE_kmod-keenpbr-table=m' >> .config
make -j"$JOBS" defconfig
# A fresh checkout needs host utilities and the target compiler before Linux is built.
make -j"$JOBS" tools/install
make -j"$JOBS" toolchain/install
make -j"$JOBS" target/linux/compile V=s
make -j"$JOBS" defconfig
grep -Eq '^CONFIG_PACKAGE_kmod-keenpbr-table=m$' .config || { echo "defconfig dropped kmod package config" >&2; exit 1; }
make "package/kernel/keenpbr-table/clean" V=s
make -j"$JOBS" "package/kernel/keenpbr-table/compile" V=s KEENPBR_PRIORITY="$PRIORITY" KEENPBR_VERSION="$VERSION"

KERNEL_DIR="$(find "$SDK_DIR/build_dir" -type f -path "*/linux-*_${MODEL}/linux-4.9/.config" -print -quit | sed 's#/.config$##')"
[[ -n "$KERNEL_DIR" && -f "$KERNEL_DIR/.modules" ]] || { echo "configured kernel tree with .modules not found for $MODEL" >&2; exit 1; }
[[ -f "$KERNEL_DIR/Module.symvers" ]] || { echo "Module.symvers missing from $KERNEL_DIR" >&2; exit 1; }
[[ -f "$KERNEL_DIR/.config" ]] || { echo "kernel .config missing from $KERNEL_DIR" >&2; exit 1; }
[[ -f "$KERNEL_DIR/include/config/kernel.release" ]] || { echo "kernel release evidence missing" >&2; exit 1; }
KERNEL_RELEASE="$(tr -d '[:space:]' < "$KERNEL_DIR/include/config/kernel.release")"
[[ -n "$KERNEL_RELEASE" ]] || { echo "empty kernel.release" >&2; exit 1; }
KERNEL_REF="$(git -C "$KERNEL_DIR" rev-parse HEAD 2>/dev/null || true)"
LOCKED_KERNEL_REF="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["kernel_ref"])' "$ROOT/sdk.lock")"
[[ "$KERNEL_REF" == "$LOCKED_KERNEL_REF" ]] || { echo "kernel source revision mismatch: got ${KERNEL_REF:-unknown}, expected $LOCKED_KERNEL_REF" >&2; exit 1; }
if (( IPV6 )) && ! grep -Eq '^CONFIG_IP6_NF_IPTABLES=[ym]$' "$KERNEL_DIR/.config"; then
  echo "matrix says $GROUP has IPv6, but kernel config lacks CONFIG_IP6_NF_IPTABLES" >&2; exit 1
fi
if (( ! IPV6 )) && grep -Eq '^CONFIG_IP6_NF_IPTABLES=[ym]$' "$KERNEL_DIR/.config"; then
  echo "kernel has IPv6 iptables but matrix marks it unavailable for $GROUP" >&2; exit 1
fi
mapfile -t PKG_DIRS < <(find "$SDK_DIR/build_dir" -type d -path "*/linux-*_${MODEL}/keenpbr-table-${VERSION}/src" -print)
(( ${#PKG_DIRS[@]} == 1 )) || { echo "expected one fresh package build dir for $MODEL, found ${#PKG_DIRS[@]}" >&2; exit 1; }
BUILT="${PKG_DIRS[0]}"
[[ -s "$BUILT/iptable_keenpbr.ko" ]] || { echo "IPv4 module missing" >&2; exit 1; }
if (( IPV6 )); then [[ -s "$BUILT/ip6table_keenpbr.ko" ]] || { echo "IPv6 module missing" >&2; exit 1; }; fi

mkdir -p "$OUT_DIR"
STAGE="$(mktemp -d "$OUT_DIR/.${GROUP}.tmp.XXXXXX")"
trap 'rm -rf -- "$STAGE"' EXIT
mkdir -p "$STAGE/audit"
cp "$BUILT/iptable_keenpbr.ko" "$STAGE/"
if (( IPV6 )); then cp "$BUILT/ip6table_keenpbr.ko" "$STAGE/"; fi
cp "$KERNEL_DIR/.config" "$STAGE/audit/kernel.config"
cp "$KERNEL_DIR/Module.symvers" "$STAGE/audit/Module.symvers"
AUDIT_PATH="$STAGE/audit" PYTHONPATH="$ROOT/scripts" python3 - "$ROOT" "$STAGE" "$GROUP" "$MODEL" "$ARCH" "$MODE" "$PRIORITY" "$VERSION" "$SDK_DIR" "$KERNEL_DIR" "$IPV6" "$KERNEL_REF" "$KERNEL_RELEASE" <<'PY'
import json, os, pathlib, re, sys
from kmodlib import audit_module, fingerprint, sha256, source_sha256
root, stage, group, model, arch, mode, priority, version, sdk, kernel, ipv6, kernel_ref, kernel_release = sys.argv[1:]
stage = pathlib.Path(stage)
audit = pathlib.Path(os.environ["AUDIT_PATH"])
mods = {}
for key, filename in (("ipv4", "iptable_keenpbr.ko"), ("ipv6", "ip6table_keenpbr.ko")):
    path = stage / filename
    if not path.exists(): continue
    details = audit_module(path, audit / key, arch)
    if details["version"] != version: raise SystemExit(f"{filename}: module version {details['version']!r} != {version}")
    if not details["vermagic"] or details["vermagic"].split()[0] != kernel_release: raise SystemExit(f"{filename}: vermagic {details['vermagic']!r} does not match kernel.release {kernel_release!r}")
    if details["keenpbr_priority"] != str(priority): raise SystemExit(f"{filename}: module priority {details['keenpbr_priority']!r} != {priority}")
    if details["keenpbr_table_abi"] != "1": raise SystemExit(f"{filename}: unsupported/missing table ABI {details['keenpbr_table_abi']!r}")
    details["fingerprint"] = fingerprint(path)
    details["file"] = filename
    mods[key] = details
config_hash, symvers_hash = sha256(pathlib.Path(kernel) / ".config"), sha256(pathlib.Path(kernel) / "Module.symvers")
metadata = {"group": group, "representative": model, "arch": arch, "kernel": "4.9-ndm", "kernel_release": kernel_release, "kernel_ref": kernel_ref,
            "sdk_ref": json.loads((pathlib.Path(root) / "sdk.lock").read_text())["ref"],
            "version": version, "priority_mode": mode, "priority": int(priority), "table_abi": 1,
            "source_sha256": source_sha256(root),
            "kernel_config_sha256": config_hash, "module_symvers_sha256": symvers_hash,
            "modules": mods, "ipv6_unavailable_reason": None if ipv6 == "1" else "CONFIG_IP6_NF_IPTABLES is disabled in this target"}
(stage / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
PY
if (( IPV6 )); then
  (cd "$STAGE" && sha256sum iptable_keenpbr.ko ip6table_keenpbr.ko metadata.json > SHA256SUMS)
else
  (cd "$STAGE" && sha256sum iptable_keenpbr.ko metadata.json > SHA256SUMS)
fi
DEST="$OUT_DIR/$GROUP"
OLD="$OUT_DIR/.${GROUP}.old.$$"
[[ ! -e "$DEST" ]] || mv "$DEST" "$OLD"
if mv "$STAGE" "$DEST"; then rm -rf -- "$OLD"; else [[ ! -e "$OLD" ]] || mv "$OLD" "$DEST"; exit 1; fi
trap - EXIT
echo "Built $GROUP from $MODEL ($ARCH), priority=$PRIORITY; output $DEST"
