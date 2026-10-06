#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ "${1:-}" == "--models" ]]; then
    OUT_DIR="${2:-$ROOT/out}"
    [[ $# -le 2 ]] || { echo "usage: $0 --models [OUT_DIR]" >&2; exit 2; }
    [[ -d "$OUT_DIR/discovery" ]] || { echo "discovery output not found: $OUT_DIR/discovery" >&2; exit 2; }
    python3 - "$ROOT" "$OUT_DIR" <<'PY'
import json, pathlib, sys
sys.path.insert(0, sys.argv[1] + "/scripts")
from model_tools import atomic_json, candidate_report
out = pathlib.Path(sys.argv[2]).resolve()
try:
    report = candidate_report(out)
    atomic_json(out / "discovery" / "candidate-groups.json", report)
except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
    print(f"candidate comparison failed: {exc}", file=sys.stderr)
    raise SystemExit(1)
print("Candidate equality only; this output does not establish ABI or hardware compatibility.")
print(f"Coverage: {len(report['coverage']['built'])}/{report['coverage']['inventory_total']} built; {len(report['coverage']['missing'])} missing; {len(report['coverage']['failed'])} failed")
for group in report["candidate_groups"]:
    print(f"{group['id']}: {', '.join(group['models'])} ({group['arch']}, IPv6={'yes' if group['ipv6']['supported'] else 'no'})")
print(f"Wrote {out / 'discovery' / 'candidate-groups.json'}")
PY
    exit $?
fi
OUT_DIR="${1:-$ROOT/out}"
[[ -d "$OUT_DIR" ]] || { echo "output directory not found: $OUT_DIR" >&2; exit 2; }
python3 - "$ROOT" "$OUT_DIR" <<'PY'
import json, pathlib, sys
sys.path.insert(0, sys.argv[1] + "/scripts")
from kmodlib import matrix, fingerprint, check_arch, sha256
root, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
groups, _ = matrix()
found = []
for group, cfg in groups.items():
    meta_path = out / group / "metadata.json"
    if not meta_path.is_file(): continue
    meta = json.loads(meta_path.read_text())
    for kind, expected in (("ipv4", "iptable_keenpbr.ko"), ("ipv6", "ip6table_keenpbr.ko")):
        item = meta.get("modules", {}).get(kind)
        if not item: continue
        path = out / group / item.get("file", "")
        if path.parent != out / group or item.get("file") != expected or not path.is_file():
            raise SystemExit(f"{group}/{kind}: unsafe or missing module path")
        check_arch(path, cfg["arch"])
        actual = fingerprint(path)
        if actual != item.get("fingerprint") or sha256(path) != item.get("sha256"):
            raise SystemExit(f"{group}/{kind}: metadata is stale; rebuild audit with inspect-module.sh")
        found.append((kind, group, actual, meta))
by_fingerprint = {}
if not found: raise SystemExit("no audited module outputs found")
for kind, group, fp, meta in found:
    by_fingerprint.setdefault((kind, fp), []).append((group, meta))
print("Candidate equality only; this output does not establish ABI compatibility.")
for (kind, fp), entries in sorted(by_fingerprint.items()):
    if len(entries) < 2: continue
    print(f"{kind}: candidate fingerprint {fp}")
    for group, meta in entries:
        print(f"  {group}: kernel_config={meta['kernel_config_sha256']} Module.symvers={meta['module_symvers_sha256']}")
PY
