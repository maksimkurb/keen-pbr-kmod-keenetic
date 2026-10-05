#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if (($# < 1 || $# > 2)); then echo "usage: $0 <module.ko> [audit-dir]" >&2; exit 2; fi
MODULE="$(realpath "$1")"
[[ -f "$MODULE" ]] || { echo "not a module file: $MODULE" >&2; exit 2; }
AUDIT_DIR="${2:-${MODULE%.ko}.audit}"
mkdir -p "$AUDIT_DIR"
python3 - "$ROOT" "$MODULE" "$AUDIT_DIR" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/scripts")
from kmodlib import audit_module
try:
    details = audit_module(sys.argv[2], sys.argv[3])
except (ValueError, RuntimeError) as exc:
    sys.exit(str(exc))
print(f"ELF={details['elf']['Class']} {details['elf']['Data']} {details['elf']['Machine']}")
print(f"vermagic={details['vermagic'] or '(missing)'} version={details['version'] or '(missing)'}")
print(f"sha256={details['sha256']} undefined_symbols={len(details['undefined_symbols'])}")
print(f"audit={sys.argv[3]}")
PY
