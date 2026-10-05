#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK_DIR="${SDK_DIR:-$ROOT/.cache/keenetic-sdk}"
python3 - "$ROOT/sdk.lock" "$SDK_DIR" <<'PY'
import json, pathlib, subprocess, sys
lock = json.loads(pathlib.Path(sys.argv[1]).read_text())
path = pathlib.Path(sys.argv[2]).expanduser().resolve()
ref = lock["ref"]
if not path.exists():
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", lock["repository"], str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "checkout", "--detach", ref], check=True)
if not (path / ".git").exists():
    sys.exit(f"SDK_DIR is not a git checkout: {path}")
head = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
if head != ref:
    sys.exit(f"SDK checkout mismatch: HEAD={head}, required {ref}")
dirty = subprocess.run(["git", "-C", str(path), "diff", "--quiet", "HEAD", "--" ]).returncode
if dirty:
    sys.exit("SDK has tracked modifications; restore them before building")
if not (path / "configure.sh").is_file():
    sys.exit("pinned SDK checkout has no configure.sh")
print(path)
PY
