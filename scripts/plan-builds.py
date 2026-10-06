#!/usr/bin/env python3
"""Plan unique SDK builds from the committed all-tag matrix."""
import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from kmodlib import source_sha256

CONTRACT = {"version": (ROOT / "VERSION").read_text().strip(), "table_abi": 1,
            "priority_mode": "after-mangle", "priority": -149, "mips_calls": "long"}
ENV_PATH = ROOT / ".ci/build-environment.json"


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError(f"refusing symlink output: {path}")
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def plan(matrix_path, descriptor_dir, max_shards=256):
    from sdk_matrix import build_inputs_sha256, build_key

    matrix_path = Path(matrix_path)
    if matrix_path.is_symlink() or not matrix_path.is_file():
        raise ValueError(f"matrix is missing or unsafe: {matrix_path}")
    matrix = json.loads(matrix_path.read_text())
    if matrix.get("schema_version") != 1 or not isinstance(matrix.get("sdks"), dict) or not isinstance(matrix.get("configurations"), dict):
        raise ValueError("unsupported kernel matrix schema")
    environment = json.loads(ENV_PATH.read_text())
    inputs_hash = build_inputs_sha256(ROOT)
    source_hash = source_sha256(ROOT)
    version = CONTRACT["version"]
    configs = matrix["configurations"]
    supported = set()
    for tag, sdk in matrix["sdks"].items():
        if not isinstance(sdk, dict) or not isinstance(sdk.get("models"), dict):
            raise ValueError(f"{tag}: malformed SDK matrix entry")
        for model, item in sdk["models"].items():
            if item.get("status") == "supported":
                key = item.get("configuration")
                if key not in configs:
                    raise ValueError(f"{tag}/{model}: missing configuration {key!r}")
                supported.add(key)
            elif item.get("status") != "unsupported" or not item.get("reason"):
                raise ValueError(f"{tag}/{model}: malformed support outcome")
    descriptors = {}
    for sdk_input_key in sorted(supported):
        configuration = configs[sdk_input_key]
        if configuration.get("sdk_input_key") != sdk_input_key:
            raise ValueError(f"configuration key mismatch: {sdk_input_key}")
        build_configuration = {"sdk_input_key": sdk_input_key, **configuration}
        key = build_key(build_configuration, inputs_hash, source_hash, version, CONTRACT, environment)
        descriptor = {"schema_version": 1, "configuration": build_configuration,
                      "sdk_input_key": sdk_input_key, "build_key": key, "contract": CONTRACT,
                      "module_source_sha256": source_hash, "build_inputs_sha256": inputs_hash,
                      "environment": environment}
        old = descriptors.get(key)
        if old and old != descriptor:
            raise ValueError(f"build key collision: {key}")
        descriptors[key] = descriptor
    if not descriptors:
        raise ValueError("matrix contains no supported SDK configurations")
    descriptor_dir = Path(descriptor_dir)
    if descriptor_dir.is_symlink():
        raise ValueError(f"refusing symlink descriptor directory: {descriptor_dir}")
    descriptor_dir.mkdir(parents=True, exist_ok=True)
    for key, descriptor in descriptors.items():
        atomic_json(descriptor_dir / f"{key}.json", descriptor)
    # At most 256 GitHub matrix jobs per workflow run; each shard builds its keys serially.
    shard_count = min(max_shards, len(descriptors))
    keys = sorted(descriptors)
    shards = [{"shard": index, "build_keys": keys[index::shard_count]}
              for index in range(shard_count)]
    return {"schema_version": 1, "matrix_sha256": hashlib.sha256(matrix_path.read_bytes()).hexdigest(),
            "source_sha256": source_hash, "build_inputs_sha256": inputs_hash,
            "build_keys": keys, "shards": shards, "descriptors": descriptors}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--descriptors", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-shards", type=int, default=256)
    args = parser.parse_args()
    try:
        if not 1 <= args.max_shards <= 256:
            raise ValueError("--max-shards must be in 1..256")
        result = plan(args.matrix, args.descriptors, args.max_shards)
        atomic_json(args.output, result)
        print(f"Planned {len(result['build_keys'])} unique builds in {len(result['shards'])} shards")
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"build planning failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
