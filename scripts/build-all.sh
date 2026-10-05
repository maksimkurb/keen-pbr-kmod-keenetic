#!/usr/bin/env bash
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/out}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(realpath "$OUT_DIR")"
REPORT="$OUT_DIR/build-report.txt"
: > "$REPORT"
GROUP_LIST="$(python3 - "$ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/scripts")
from kmodlib import matrix
groups, _ = matrix()
print("\n".join(groups))
PY
)" || exit 1
[[ -n "$GROUP_LIST" ]] || { echo "matrix contains no groups" >&2; exit 1; }
mapfile -t TARGET_GROUPS <<< "$GROUP_LIST"
total=${#TARGET_GROUPS[@]}
failed=0
for i in "${!TARGET_GROUPS[@]}"; do
  group="${TARGET_GROUPS[$i]}"
  echo "[$((i + 1))/$total] $group"
  if OUT_DIR="$OUT_DIR" "$ROOT/scripts/build.sh" "$group" >"$OUT_DIR/.${group}.build.log" 2>&1; then
    echo "OK $group" | tee -a "$REPORT"
    python3 - "$OUT_DIR/$group/metadata.json" <<'PY' | tee -a "$REPORT"
import json, sys
meta = json.load(open(sys.argv[1]))
for kind, item in meta["modules"].items():
    print(f"  {kind}: size={item['size']} vermagic={item['vermagic']} sha256={item['sha256']}")
if "ipv6" not in meta["modules"]:
    print(f"  ipv6: unavailable ({meta['ipv6_unavailable_reason']})")
PY
  else
    status=$?
    echo "FAIL $group (exit $status; see .$group.build.log)" | tee -a "$REPORT"
    tail -n 30 "$OUT_DIR/.${group}.build.log"
    failed=$((failed + 1))
  fi
done
echo "Built $((total - failed))/$total groups" | tee -a "$REPORT"
exit "$((failed > 0))"
