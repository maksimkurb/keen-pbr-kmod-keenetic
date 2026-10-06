#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK_DIR="${SDK_DIR:-$ROOT/.cache/keenetic-sdk}"
if [[ "${1:-}" == "--ref" ]]; then
  if (($# != 6)) || [[ "$3" != "--tag" || "$5" != "--destination" ]]; then
    echo "usage: $0 --ref SHA --tag TAG --destination PATH" >&2
    exit 2
  fi
  python3 - "$ROOT/sdk.lock" "$2" "$4" "$6" <<'PY'
import json, pathlib, re, subprocess, sys
lock = json.loads(pathlib.Path(sys.argv[1]).read_text())
ref, tag, raw_path = sys.argv[2], sys.argv[3], pathlib.Path(sys.argv[4]).expanduser()
if raw_path.is_symlink(): sys.exit(f"refusing symlink SDK destination: {raw_path}")
path = raw_path.resolve()
if not re.fullmatch(r"[0-9a-f]{40}", ref): sys.exit("invalid SDK ref")
if subprocess.run(["git", "check-ref-format", f"refs/tags/{tag}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
    sys.exit("invalid SDK tag")
path.parent.mkdir(parents=True, exist_ok=True)
cloned = not path.exists()
if cloned:
    subprocess.run(["git", "clone", "--no-checkout", "--no-tags", lock["repository"], str(path)], check=True)
if path.is_symlink() or not (path / ".git").exists(): sys.exit(f"SDK_DIR is not a git checkout: {path}")
tag_ref = f"refs/tags/{tag}"
if subprocess.run(["git", "-C", str(path), "show-ref", "--verify", "--quiet", tag_ref]).returncode:
    subprocess.run(["git", "-C", str(path), "fetch", "--no-tags", "origin", f"{tag_ref}:{tag_ref}"], check=True)
tag_commit = subprocess.check_output(["git", "-C", str(path), "rev-parse", f"{tag_ref}^{{commit}}"], text=True).strip()
if tag_commit != ref: sys.exit(f"SDK tag mismatch: {tag} resolves to {tag_commit}, expected {ref}")
if subprocess.run(["git", "-C", str(path), "cat-file", "-e", f"{ref}^{{commit}}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
    sys.exit("SDK tag commit object is unavailable")
head = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], text=True, capture_output=True)
if cloned or head.returncode or head.stdout.strip() != ref:
    subprocess.run(["git", "-C", str(path), "checkout", "--detach", ref], check=True)
if subprocess.run(["git", "-C", str(path), "diff", "--quiet", "HEAD", "--"]).returncode:
    sys.exit("SDK has tracked modifications; refusing to reuse isolated checkout")
if not (path / "configure.sh").is_file(): sys.exit("pinned SDK checkout has no configure.sh")
print(path)
PY
else
  (($# == 0)) || { echo "usage: $0 [--ref SHA --destination PATH]" >&2; exit 2; }
  python3 - "$ROOT/sdk.lock" "$SDK_DIR" <<'PY'
import json, pathlib, subprocess, sys
lock = json.loads(pathlib.Path(sys.argv[1]).read_text())
path = pathlib.Path(sys.argv[2]).expanduser().resolve()
ref = lock["ref"]
if not path.exists():
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", lock["repository"], str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "checkout", "--detach", ref], check=True)
if not (path / ".git").exists(): sys.exit(f"SDK_DIR is not a git checkout: {path}")
head = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
if head != ref: sys.exit(f"SDK checkout mismatch: HEAD={head}, required {ref}")
dirty = subprocess.run(["git", "-C", str(path), "diff", "--quiet", "HEAD", "--"]).returncode
if dirty: sys.exit("SDK has tracked modifications; restore them before building")
if not (path / "configure.sh").is_file(): sys.exit("pinned SDK checkout has no configure.sh")
print(path)
PY
fi
