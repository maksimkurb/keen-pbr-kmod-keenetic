#!/usr/bin/env python3
"""Run one bounded planner shard serially, with isolated SDK output per key."""
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def link_download_cache(sdk_dir, cache_dir):
    """Share downloaded archives, never configured SDK or kernel build state."""
    if cache_dir.is_symlink() or (cache_dir.exists() and not cache_dir.is_dir()):
        raise ValueError("download cache must be a regular directory")
    cache_dir.mkdir(parents=True, exist_ok=True)
    downloads = sdk_dir / "dl"
    if downloads.exists() or downloads.is_symlink():
        raise ValueError("fresh SDK unexpectedly already contains downloads")
    downloads.symlink_to(cache_dir, target_is_directory=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--descriptors", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "out")
    parser.add_argument("--download-cache", type=Path,
                        help="optional archives-only cache at /build/downloads")
    args = parser.parse_args()
    try:
        if args.plan.is_symlink() or args.descriptors.is_symlink():
            raise ValueError("plan and descriptor paths must not be symlinks")
        plan = json.loads(args.plan.read_text())
        shards = plan.get("shards")
        if plan.get("schema_version") != 1 or not isinstance(shards, list):
            raise ValueError("invalid build plan")
        shard = next((item for item in shards if item.get("shard") == args.shard), None)
        if shard is None or not isinstance(shard.get("build_keys"), list):
            raise ValueError(f"unknown shard: {args.shard}")
        env = os.environ.copy()
        env.update({"OUT_DIR": str(args.out.resolve()), "JOBS": env.get("JOBS", "4")})
        if args.download_cache is not None and args.download_cache != Path("/build/downloads"):
            raise ValueError("download cache must use /build/downloads")
        for key in shard["build_keys"]:
            if not isinstance(key, str) or len(key) != 64 or any(ch not in "0123456789abcdef" for ch in key):
                raise ValueError(f"unsafe build key: {key!r}")
            descriptor = args.descriptors / f"{key}.json"
            if descriptor.is_symlink() or not descriptor.is_file():
                raise ValueError(f"missing/unsafe build descriptor: {descriptor}")
            data = json.loads(descriptor.read_text())
            sdk_dir = Path(data.get("environment", {}).get("sdk_path", ""))
            if sdk_dir != Path("/build/sdk"):
                raise ValueError(f"build {key}: environment SDK path is not the pinned /build/sdk")
            build_dir = args.out / "builds" / key
            if build_dir.exists():
                if build_dir.is_symlink():
                    raise ValueError(f"build {key}: refusing symlink build output")
                existing = json.loads((build_dir / "metadata.json").read_text())
                if existing.get("build_key") == key and existing.get("reused_from_snapshot", {}).get("manifest_sha256"):
                    print(f"Reusing verified release build {key}", flush=True)
                    continue
                raise ValueError(f"build {key}: output already exists without trusted reuse provenance")
            if sdk_dir.is_symlink():
                raise ValueError(f"build {key}: refusing symlink SDK path")
            if sdk_dir.exists():
                shutil.rmtree(sdk_dir)
            if args.download_cache is not None:
                subprocess.run([str(ROOT / "scripts/prepare-sdk.sh"), "--ref",
                                data["configuration"]["sdk_ref"], "--tag",
                                data["configuration"]["sdk_tag"], "--destination", str(sdk_dir)],
                               cwd=ROOT, env=env, check=True)
                link_download_cache(sdk_dir, args.download_cache)
            print(f"Building {key}", flush=True)
            subprocess.run([str(ROOT / "scripts/build.sh"), "--descriptor", str(descriptor.resolve())],
                           cwd=ROOT, env=env, check=True)
            metadata_path = build_dir / "metadata.json"
            if build_dir.is_symlink() or metadata_path.is_symlink() or not metadata_path.is_file():
                raise ValueError(f"build {key}: successful command left missing or unsafe output")
            if json.loads(metadata_path.read_text()).get("build_key") != key:
                raise ValueError(f"build {key}: metadata key mismatch")
            if sdk_dir.is_symlink():
                raise ValueError(f"build {key}: refusing symlink SDK cleanup path")
            if sdk_dir.exists():
                shutil.rmtree(sdk_dir)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"shard build failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
