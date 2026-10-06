#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REQUESTED_SDK_DIR="${SDK_DIR:-}"
SDK_MODEL=""
DESCRIPTOR=""
SDK_INPUT_KEY=""
BUILD_KEY=""
DESCRIPTOR_SHA256=""
MAKE_REPRO_ARGS=()
if [[ "${1:-}" == "--descriptor" ]]; then
  (($# == 2)) || { echo "usage: $0 --descriptor PATH" >&2; exit 2; }
  [[ ! -L "$2" ]] || { echo "refusing symlink descriptor" >&2; exit 2; }
  DESCRIPTOR="$(realpath "$2")"
elif [[ "${1:-}" == "--sdk-model" ]]; then
  (($# == 2)) || { echo "usage: $0 --sdk-model KN-####" >&2; exit 2; }
  SDK_MODEL="$2"
  [[ "$SDK_MODEL" =~ ^KN-[0-9]{4}$ ]] || { echo "invalid SDK model: $SDK_MODEL" >&2; exit 2; }
elif (($# == 1)); then
  TARGET="$1"
else
  echo "usage: $0 <group|KN-model> | --sdk-model KN-#### | --descriptor PATH" >&2
  exit 2
fi
SDK_DIR="${SDK_DIR:-$ROOT/.cache/keenetic-sdk}"
OUT_DIR="${OUT_DIR:-$ROOT/out}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
MODE="${KEENPBR_PRIORITY_MODE:-after-mangle}"
MIPS_CALLS="${KEENPBR_MIPS_CALLS:-sdk}"
[[ "$MIPS_CALLS" == sdk || "$MIPS_CALLS" == long ]] || { echo "KEENPBR_MIPS_CALLS must be sdk or long" >&2; exit 2; }
case "$JOBS" in ''|*[!0-9]*) echo "JOBS must be a positive integer" >&2; exit 2;; esac
(( JOBS > 0 && JOBS <= 128 )) || { echo "JOBS must be in 1..128" >&2; exit 2; }
if [[ -n "$DESCRIPTOR" ]]; then
  DESCRIPTOR_INFO="$(python3 - "$ROOT" "$DESCRIPTOR" <<'PY'
import hashlib, json, pathlib, re, subprocess, sys
root = pathlib.Path(sys.argv[1])
path = pathlib.Path(sys.argv[2])
if path.is_symlink() or not path.is_file(): raise SystemExit("descriptor is missing or unsafe")
data = json.loads(path.read_text())
cfg = data.get("configuration")
contract = {"version": (root / "VERSION").read_text().strip(), "table_abi": 1,
            "priority_mode": "after-mangle", "priority": -149, "mips_calls": "long"}
if data.get("schema_version") != 1 or not isinstance(cfg, dict): raise SystemExit("unsupported descriptor schema")
if data.get("contract") != contract: raise SystemExit("descriptor contract mismatch")
if not re.fullmatch(r"[0-9a-f]{64}", data.get("sdk_input_key", "")): raise SystemExit("invalid sdk_input_key")
if cfg.get("sdk_input_key") != data["sdk_input_key"]: raise SystemExit("configuration sdk_input_key mismatch")
if not re.fullmatch(r"[0-9a-f]{64}", data.get("build_key", "")): raise SystemExit("invalid build_key")
sys.path.insert(0, str(root / "scripts"))
from sdk_matrix import build_key, build_inputs_sha256, verify_build_host
from kmodlib import source_sha256
if data.get("build_inputs_sha256") != build_inputs_sha256(root): raise SystemExit("build inputs differ from descriptor")
if data.get("module_source_sha256") != source_sha256(root): raise SystemExit("module sources differ from descriptor")
if data.get("environment") != json.loads((root / ".ci/build-environment.json").read_text()):
    raise SystemExit("descriptor environment differs from pinned build environment")
try:
    verify_build_host(data["environment"])
except (OSError, ValueError, subprocess.CalledProcessError) as exc:
    raise SystemExit(str(exc))
build = data["environment"].get("build")
required_build = {"timezone", "locale", "source_date_epoch", "kbuild_build_timestamp", "kbuild_build_user", "kbuild_build_host", "host_cc", "host_cxx"}
if not isinstance(build, dict) or set(build) != required_build or type(build["source_date_epoch"]) is not int:
    raise SystemExit("pinned build environment has invalid build fields")
if any(not isinstance(build[key], str) or "\t" in build[key] or "\n" in build[key]
       for key in required_build - {"source_date_epoch"}):
    raise SystemExit("pinned build environment values must be single-line strings")
sdk_path = data["environment"].get("sdk_path")
if not isinstance(sdk_path, str) or not sdk_path.startswith("/") or ".." in pathlib.PurePosixPath(sdk_path).parts:
    raise SystemExit("environment sdk_path must be a safe absolute path")
expected = build_key(cfg, data["build_inputs_sha256"], data["module_source_sha256"], contract["version"], contract, data.get("environment"))
if data["build_key"] != expected: raise SystemExit("descriptor build_key mismatch")
for key, pattern in (("sdk_ref", r"[0-9a-f]{40}"), ("kernel_ref", r"[0-9a-f]{40}"), ("config_sha256", r"[0-9a-f]{64}")):
    if not re.fullmatch(pattern, cfg.get(key, "")): raise SystemExit(f"invalid configuration {key}")
if not re.fullmatch(r"KN-[0-9]{4}", cfg.get("model", "")) or cfg.get("arch") not in {"mips", "mipsel", "aarch64"}:
    raise SystemExit("invalid configuration model/architecture")
config = cfg.get("config", "")
if not re.fullmatch(r"target/linux/[^/]+/KN-[0-9]{4}/ndwrt.config", config): raise SystemExit("unsafe SDK config path")
print(data["sdk_input_key"], data["build_key"], cfg["sdk_ref"], cfg["kernel_ref"], cfg["kernel_source_version"], cfg["model"], cfg["arch"], config, cfg["config_sha256"], hashlib.sha256(path.read_bytes()).hexdigest(), build["timezone"], build["locale"], build["source_date_epoch"], build["kbuild_build_timestamp"], build["kbuild_build_user"], build["kbuild_build_host"], build["host_cc"], build["host_cxx"], sdk_path, sep="\t")
PY
  )" || exit 2
  IFS=$'\t' read -r SDK_INPUT_KEY BUILD_KEY SDK_REF MATRIX_KERNEL_REF KERNEL_SOURCE_VERSION MODEL ARCH SDK_CONFIG SDK_CONFIG_SHA256 DESCRIPTOR_SHA256 BUILD_TZ BUILD_LOCALE BUILD_EPOCH BUILD_TIMESTAMP BUILD_USER BUILD_HOST BUILD_HOST_CC BUILD_HOST_CXX BUILD_SDK_PATH <<< "$DESCRIPTOR_INFO"
  GROUP="$MODEL"; BUILD_KIND="descriptor"; MODE="after-mangle"; PRIORITY=-149; MIPS_CALLS="long"
  export TZ="$BUILD_TZ" LANG="$BUILD_LOCALE" LC_ALL="$BUILD_LOCALE"
  export SOURCE_DATE_EPOCH="$BUILD_EPOCH" KBUILD_BUILD_TIMESTAMP="$BUILD_TIMESTAMP"
  export KERNEL_SOURCE_VERSION
  export KBUILD_BUILD_USER="$BUILD_USER" KBUILD_BUILD_HOST="$BUILD_HOST"
  export HOSTCC="$BUILD_HOST_CC" HOSTCXX="$BUILD_HOST_CXX"
  if ! command -v "$HOSTCC" >/dev/null || ! command -v "$HOSTCXX" >/dev/null; then echo "pinned host compilers are unavailable" >&2; exit 2; fi
  MAKE_REPRO_ARGS+=("SOURCE_DATE_EPOCH=$BUILD_EPOCH" "HOSTCC=$HOSTCC" "HOSTCXX=$HOSTCXX")
  OUT_BASE="${OUT_DIR:-$ROOT/out}"
  OUT_DIR="$OUT_BASE/builds/$BUILD_KEY"
  SDK_DIR="${REQUESTED_SDK_DIR:-$BUILD_SDK_PATH}"
  [[ "$SDK_DIR" == "$BUILD_SDK_PATH" ]] || { echo "SDK_DIR must match pinned path $BUILD_SDK_PATH" >&2; exit 2; }
  [[ ! -L "$SDK_DIR" ]] || { echo "refusing symlink isolated SDK path: $SDK_DIR" >&2; exit 2; }
  mkdir -p "$OUT_DIR"
elif [[ -z "$SDK_MODEL" ]]; then
  python3 - "$ROOT" "$TARGET" "$MODE" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/scripts")
from kmodlib import resolve_target, PRIORITIES
resolve_target(sys.argv[2])
if sys.argv[3] not in PRIORITIES: raise SystemExit("invalid priority mode: " + sys.argv[3])
PY
else
  python3 - "$ROOT" "$MODE" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/scripts")
from kmodlib import PRIORITIES
if sys.argv[2] not in PRIORITIES: raise SystemExit("invalid priority mode: " + sys.argv[2])
PY
fi
if [[ -n "$DESCRIPTOR" ]]; then
  "$ROOT/scripts/prepare-sdk.sh" --ref "$SDK_REF" --tag "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["configuration"]["sdk_tag"])' "$DESCRIPTOR")" --destination "$SDK_DIR" >/dev/null
else
  "$ROOT/scripts/prepare-sdk.sh" >/dev/null
fi
SDK_DIR="$(realpath "$SDK_DIR")"
mkdir -p "$OUT_DIR"
OUT_DIR="$(realpath "$OUT_DIR")"
if [[ -n "$DESCRIPTOR" ]]; then
  BUILD_KIND="descriptor"
  python3 - "$SDK_DIR" "$DESCRIPTOR" "$ROOT" <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[3]) / "scripts"))
from sdk_matrix import verify_configuration
descriptor = json.loads(Path(sys.argv[2]).read_text())
verify_configuration(sys.argv[1], descriptor["configuration"])
PY
  IPV6_MATRIX=0
elif [[ -n "$SDK_MODEL" ]]; then
  BUILD_KIND="sdk-model"
  "$ROOT/scripts/discover-models.py" --sdk "$SDK_DIR" --output "$OUT_DIR/discovery/inventory.json" >/dev/null
  TARGET_INFO="$(python3 - "$ROOT" "$OUT_DIR/discovery/inventory.json" "$SDK_MODEL" "$MODE" "$MIPS_CALLS" <<'PY'
import json, sys
model = sys.argv[3]
inventory = json.load(open(sys.argv[2]))
item = inventory.get("models", {}).get(model)
if not item: sys.exit(f"model is not present in the pinned SDK inventory: {model}")
sys.path.insert(0, sys.argv[1] + "/scripts")
from kmodlib import PRIORITIES
if sys.argv[4] not in PRIORITIES: sys.exit("invalid priority mode: " + sys.argv[4])
if sys.argv[5] not in {"sdk", "long"}: sys.exit("invalid MIPS call policy")
print(model, item["arch"], 0, PRIORITIES[sys.argv[4]], item["config"], item["config_sha256"], sep="\t")
PY
  )" || exit 2
  IFS=$'\t' read -r MODEL ARCH IPV6_MATRIX PRIORITY SDK_CONFIG SDK_CONFIG_SHA256 <<< "$TARGET_INFO"
  GROUP="$MODEL"
else
  BUILD_KIND="group"
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
  IFS=$'\t' read -r GROUP MODEL ARCH IPV6_MATRIX PRIORITY <<< "$TARGET_INFO"
  SDK_CONFIG=""
  SDK_CONFIG_SHA256=""
fi
MODULE_CFLAGS=""
if [[ "$ARCH" == mips || "$ARCH" == mipsel ]] && [[ "$MIPS_CALLS" == long ]]; then
  MODULE_CFLAGS="-mlong-calls"
fi
if [[ -n "$SDK_CONFIG" ]]; then
  [[ -f "$SDK_DIR/$SDK_CONFIG" && ! -L "$SDK_DIR/$SDK_CONFIG" ]] || { echo "unsafe/missing SDK model config: $SDK_CONFIG" >&2; exit 1; }
  [[ "$(sha256sum "$SDK_DIR/$SDK_CONFIG" | cut -d' ' -f1)" == "$SDK_CONFIG_SHA256" ]] || { echo "SDK model config changed after discovery" >&2; exit 1; }
fi
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
make -j"$JOBS" defconfig "${MAKE_REPRO_ARGS[@]}"
# A fresh checkout needs host utilities and the target compiler before Linux is built.
make -j"$JOBS" tools/install "${MAKE_REPRO_ARGS[@]}"
make -j"$JOBS" toolchain/install "${MAKE_REPRO_ARGS[@]}"
make -j"$JOBS" target/linux/compile V=s "${MAKE_REPRO_ARGS[@]}"
make -j"$JOBS" defconfig "${MAKE_REPRO_ARGS[@]}"
grep -Eq '^CONFIG_PACKAGE_kmod-keenpbr-table=m$' .config || { echo "defconfig dropped kmod package config" >&2; exit 1; }
KERNEL_DIR="$(find "$SDK_DIR/build_dir" -type f -path "*/linux-*_${MODEL}/linux-4.9/.config" -print -quit | sed 's#/.config$##')"
[[ -n "$KERNEL_DIR" && -f "$KERNEL_DIR/.modules" ]] || { echo "configured kernel tree with .modules not found for $MODEL" >&2; exit 1; }
[[ -f "$KERNEL_DIR/Module.symvers" && -f "$KERNEL_DIR/.config" && -f "$KERNEL_DIR/include/config/kernel.release" ]] || { echo "kernel config, Module.symvers, or kernel.release evidence missing" >&2; exit 1; }
KERNEL_RELEASE="$(tr -d '[:space:]' < "$KERNEL_DIR/include/config/kernel.release")"
[[ -n "$KERNEL_RELEASE" ]] || { echo "empty kernel.release" >&2; exit 1; }
[[ -e "$KERNEL_DIR/.git" ]] || { echo "kernel source has no repository identity; refusing unverifiable source" >&2; exit 1; }
KERNEL_REF="$(git -C "$KERNEL_DIR" rev-parse HEAD 2>/dev/null || true)"
if [[ -n "$DESCRIPTOR" ]]; then LOCKED_KERNEL_REF="$MATRIX_KERNEL_REF";
else LOCKED_KERNEL_REF="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["kernel_ref"])' "$ROOT/sdk.lock")"; fi
[[ "$KERNEL_REF" == "$LOCKED_KERNEL_REF" ]] || { echo "kernel source revision mismatch: got ${KERNEL_REF:-unknown}, expected $LOCKED_KERNEL_REF" >&2; exit 1; }
PROVIDER_EVIDENCE="$(python3 - "$ROOT" "$KERNEL_DIR" <<'PY'
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / "scripts"))
from sdk_matrix import verify_kernel_providers
kernel = pathlib.Path(sys.argv[2])
print(json.dumps(verify_kernel_providers((kernel / ".config").read_text(),
    (kernel / "Module.symvers").read_text(), kernel), sort_keys=True, separators=(",", ":")))
PY
)"
IPV6_SUPPORTED="$(python3 -c 'import json,sys; print(int(json.loads(sys.argv[1])["ipv6"]["supported"]))' "$PROVIDER_EVIDENCE")"
export PROVIDER_EVIDENCE
if [[ "$BUILD_KIND" == group && "$IPV6_MATRIX" != "$IPV6_SUPPORTED" ]]; then
  echo "matrix IPv6 support does not match effective kernel config for $MODEL" >&2; exit 1
fi
make "package/kernel/keenpbr-table/clean" V=s "${MAKE_REPRO_ARGS[@]}"
EXTRA_MODULE_ARGS=()
[[ -z "$MODULE_CFLAGS" ]] || EXTRA_MODULE_ARGS+=("CFLAGS_MODULE=$MODULE_CFLAGS")
make -j"$JOBS" "package/kernel/keenpbr-table/compile" V=s KEENPBR_PRIORITY="$PRIORITY" KEENPBR_VERSION="$VERSION" "${EXTRA_MODULE_ARGS[@]}" "${MAKE_REPRO_ARGS[@]}"

mapfile -t PKG_DIRS < <(find "$SDK_DIR/build_dir" -type d -path "*/linux-*_${MODEL}/keenpbr-table-${VERSION}/src" -print)
(( ${#PKG_DIRS[@]} == 1 )) || { echo "expected one fresh package build dir for $MODEL, found ${#PKG_DIRS[@]}" >&2; exit 1; }
BUILT="${PKG_DIRS[0]}"
[[ -s "$BUILT/iptable_keenpbr.ko" ]] || { echo "IPv4 module missing" >&2; exit 1; }
if (( IPV6_SUPPORTED )); then [[ -s "$BUILT/ip6table_keenpbr.ko" ]] || { echo "IPv6 module missing" >&2; exit 1; };
else [[ ! -s "$BUILT/ip6table_keenpbr.ko" ]] || { echo "IPv6 module exists although effective kernel config disables it" >&2; exit 1; }; fi

mkdir -p "$OUT_DIR"
if [[ "$BUILD_KIND" == sdk-model ]]; then OUT_PARENT="$OUT_DIR/discovery";
elif [[ "$BUILD_KIND" == descriptor ]]; then OUT_PARENT="$OUT_BASE/builds";
else OUT_PARENT="$OUT_DIR"; fi
mkdir -p "$OUT_PARENT"
if [[ "$BUILD_KIND" == descriptor ]]; then STAGE="$(mktemp -d "$OUT_PARENT/.${BUILD_KEY}.tmp.XXXXXX")";
else STAGE="$(mktemp -d "$OUT_PARENT/.${GROUP}.tmp.XXXXXX")"; fi
trap 'rm -rf -- "$STAGE"' EXIT
mkdir -p "$STAGE/audit"
MODULE_DIR="$STAGE"
if [[ "$BUILD_KIND" == descriptor ]]; then MODULE_DIR="$STAGE/modules"; mkdir -p "$MODULE_DIR"; fi
cp "$BUILT/iptable_keenpbr.ko" "$MODULE_DIR/"
if (( IPV6_SUPPORTED )); then cp "$BUILT/ip6table_keenpbr.ko" "$MODULE_DIR/"; fi
cp "$KERNEL_DIR/.config" "$STAGE/audit/kernel.config"
cp "$KERNEL_DIR/Module.symvers" "$STAGE/audit/Module.symvers"
AUDIT_PATH="$STAGE/audit" MODULE_PATH="$MODULE_DIR" DESCRIPTOR_PATH="$DESCRIPTOR" PYTHONPATH="$ROOT/scripts" python3 - "$ROOT" "$STAGE" "$BUILD_KIND" "$GROUP" "$MODEL" "$ARCH" "$MODE" "$PRIORITY" "$VERSION" "$SDK_DIR" "$KERNEL_DIR" "$IPV6_SUPPORTED" "$KERNEL_REF" "$KERNEL_RELEASE" "$MIPS_CALLS" "$MODULE_CFLAGS" "$SDK_CONFIG_SHA256" "$BUILD_KEY" "$SDK_INPUT_KEY" "$DESCRIPTOR_SHA256" <<'PY'
import json, os, pathlib, re, sys
from kmodlib import audit_module, fingerprint, sha256, source_sha256
from sdk_matrix import build_inputs_sha256
root, stage, build_kind, group, model, arch, mode, priority, version, sdk, kernel, ipv6, kernel_ref, kernel_release, mips_calls, module_cflags, sdk_config_sha256, build_key, sdk_input_key, descriptor_sha256 = sys.argv[1:]
stage = pathlib.Path(stage)
audit = pathlib.Path(os.environ["AUDIT_PATH"])
module_dir = pathlib.Path(os.environ["MODULE_PATH"])
mods = {}
for key, filename in (("ipv4", "iptable_keenpbr.ko"), ("ipv6", "ip6table_keenpbr.ko")):
    path = module_dir / filename
    if not path.exists(): continue
    details = audit_module(path, audit / key, arch)
    if details["version"] != version: raise SystemExit(f"{filename}: module version {details['version']!r} != {version}")
    if not details["vermagic"] or details["vermagic"].split()[0] != kernel_release: raise SystemExit(f"{filename}: vermagic {details['vermagic']!r} does not match kernel.release {kernel_release!r}")
    if details["keenpbr_priority"] != str(priority): raise SystemExit(f"{filename}: module priority {details['keenpbr_priority']!r} != {priority}")
    if details["keenpbr_table_abi"] != "1": raise SystemExit(f"{filename}: unsupported/missing table ABI {details['keenpbr_table_abi']!r}")
    details["fingerprint"] = fingerprint(path)
    details["file"] = f"modules/{filename}" if build_kind == "descriptor" else filename
    mods[key] = details
config_hash, symvers_hash = sha256(pathlib.Path(kernel) / ".config"), sha256(pathlib.Path(kernel) / "Module.symvers")
descriptor = json.loads(pathlib.Path(os.environ["DESCRIPTOR_PATH"]).read_text()) if build_kind == "descriptor" else None
configuration = descriptor["configuration"] if descriptor else None
sdk_ref = configuration["sdk_ref"] if configuration else json.loads((pathlib.Path(root) / "sdk.lock").read_text())["ref"]
downloads = pathlib.Path(sdk) / "dl"
toolchain_archives = {path.name: sha256(path) for path in sorted(downloads.glob("*toolchain*"))
                      if path.is_file() and not path.is_symlink()}
kernel_archives = sorted(downloads.glob(f"linux-{os.environ['KERNEL_SOURCE_VERSION']}.tar.*")) if configuration else []
kernel_archive = kernel_archives[0] if len(kernel_archives) == 1 else None
if descriptor and (not toolchain_archives or kernel_archive is None):
    raise SystemExit("descriptor build lacks unique kernel archive or toolchain archive provenance")
metadata = {"build_kind": build_kind, "group": None if build_kind == "sdk-model" else group,
            "model": model, "representative": model, "arch": arch, "kernel": "4.9-ndm", "kernel_release": kernel_release, "kernel_ref": kernel_ref,
            "sdk_ref": sdk_ref,
            "version": version, "priority_mode": mode, "priority": int(priority), "table_abi": 1,
            "mips_calls": mips_calls, "module_cflags": module_cflags,
            "sdk_config_sha256": sdk_config_sha256 or None,
            "source_sha256": source_sha256(root),
            "kernel_config_sha256": config_hash, "module_symvers_sha256": symvers_hash,
            "ipv6_supported": ipv6 == "1", "modules": mods,
            "ipv6_unavailable_reason": None if ipv6 == "1" else "CONFIG_IP6_NF_IPTABLES is disabled in this target"}
if descriptor:
    metadata.update({"build_key": build_key, "sdk_input_key": sdk_input_key,
                     "descriptor_sha256": descriptor_sha256, "configuration": configuration,
                     "contract": descriptor["contract"],
                     "module_source_sha256": descriptor["module_source_sha256"],
                     "build_inputs_sha256": descriptor["build_inputs_sha256"],
                     "environment": descriptor["environment"],
                     "kernel_source_version": configuration["kernel_source_version"],
                     "kernel_source_evidence": "git-head-equals-resolved-sdk-source-tag",
                     "provider_export_evidence": json.loads(os.environ["PROVIDER_EVIDENCE"]),
                     "toolchain_archive_sha256": toolchain_archives,
                     "kernel_archive_format": kernel_archive.name.removeprefix(f"linux-{configuration['kernel_source_version']}") if kernel_archive else None,
                     "kernel_archive_sha256": sha256(kernel_archive) if kernel_archive and kernel_archive.is_file() else None,
                     "effective_kernel_config_sha256": config_hash,
                     "effective_module_symvers_sha256": symvers_hash})
(stage / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
PY
if (( IPV6_SUPPORTED )); then
  if [[ "$BUILD_KIND" == descriptor ]]; then (cd "$STAGE" && sha256sum modules/iptable_keenpbr.ko modules/ip6table_keenpbr.ko metadata.json > SHA256SUMS);
  else (cd "$STAGE" && sha256sum iptable_keenpbr.ko ip6table_keenpbr.ko metadata.json > SHA256SUMS); fi
else
  if [[ "$BUILD_KIND" == descriptor ]]; then (cd "$STAGE" && sha256sum modules/iptable_keenpbr.ko metadata.json > SHA256SUMS);
  else (cd "$STAGE" && sha256sum iptable_keenpbr.ko metadata.json > SHA256SUMS); fi
fi
if [[ "$BUILD_KIND" == sdk-model ]]; then DEST="$OUT_PARENT/$MODEL"; else DEST="$OUT_PARENT/$GROUP"; fi
if [[ "$BUILD_KIND" == descriptor ]]; then DEST="$OUT_BASE/builds/$BUILD_KEY"; fi
OLD="$OUT_PARENT/.${GROUP}.old.$$"
[[ ! -e "$DEST" ]] || mv "$DEST" "$OLD"
if mv "$STAGE" "$DEST"; then rm -rf -- "$OLD"; else [[ ! -e "$OLD" ]] || mv "$OLD" "$DEST"; exit 1; fi
trap - EXIT
echo "Built $MODEL ($ARCH) [${MIPS_CALLS}${MODULE_CFLAGS:+ $MODULE_CFLAGS}], priority=$PRIORITY; output $DEST"
