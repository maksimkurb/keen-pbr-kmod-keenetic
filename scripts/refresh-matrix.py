#!/usr/bin/env python3
"""Generate the deterministic all-tag Keenetic SDK matrix from Git repositories."""
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sdk_matrix import ROOT, generate_matrix, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", required=True, help="local SDK Git repo/bare cache or remote URL")
    parser.add_argument("--kernel-git", required=True, help="local kernel Git repo/cache or remote URL")
    parser.add_argument("--repository", help="SDK repository URL recorded in the matrix")
    parser.add_argument("--kernel-repository", help="canonical kernel repository URL recorded in the matrix")
    parser.add_argument("--output", default=str(ROOT / "kernel-matrix.json"))
    args = parser.parse_args()
    sdk = args.sdk
    tmp = None
    if not Path(sdk).exists():
        tmp = tempfile.TemporaryDirectory(prefix="keenetic-sdk-tags-")
        sdk = str(Path(tmp.name) / "sdk.git")
        subprocess.run(["git", "clone", "--bare", "--filter=blob:none", args.sdk, sdk], check=True)
    try:
        repository = args.repository or args.sdk
        matrix = generate_matrix(sdk, args.kernel_git, repository, args.kernel_repository)
        digest = write_json(args.output, matrix)
        print(f"Wrote {len(matrix['sdks'])} SDK tags, {len(matrix['configurations'])} input keys; sha256={digest}")
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    finally:
        if tmp:
            tmp.cleanup()


if __name__ == "__main__":
    main()
