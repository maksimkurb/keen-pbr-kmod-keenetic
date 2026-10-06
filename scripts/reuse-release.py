#!/usr/bin/env python3
"""Seed build outputs only from checksummed, audited assets in a prior release."""
import argparse
import hashlib
import json
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from kmodlib import audit_module, fingerprint, sha256

MODULES = {"ipv4": "iptable_keenpbr.ko", "ipv6": "ip6table_keenpbr.ko"}
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def request_bytes(url, token, accept="application/vnd.github+json"):
    request = urllib.request.Request(url, headers={"Accept": accept, "Authorization": f"Bearer {token}",
                                                   "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def list_assets(url, token):
    result = []
    page = 1
    while True:
        separator = "&" if "?" in url else "?"
        items = json.loads(request_bytes(f"{url}{separator}per_page=100&page={page}", token))
        if not isinstance(items, list):
            raise ValueError("GitHub returned a malformed release asset page")
        result.extend(items)
        if len(items) < 100:
            return result
        page += 1


def download_index(repo, token, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    try:
        page = 1
        while True:
            items = json.loads(request_bytes(
                f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}", token))
            if not isinstance(items, list):
                raise ValueError("GitHub returned a malformed release page")
            release = next((item for item in items if not item.get("draft") and
                            item.get("tag_name", "").startswith("modules-v")), None)
            if release or len(items) < 100:
                break
            page += 1
        if release is None:
            raise LookupError("no published modules-v snapshot found")
        assets = {item["name"]: item for item in list_assets(release["assets_url"], token)}
        required = {name: assets[name] for name in ("manifest.json", "kernel-matrix.json", "SHA256SUMS")}
        for name, asset in required.items():
            (output / name).write_bytes(request_bytes(asset["url"], token, "application/octet-stream"))
        index = {"schema_version": 1, "repository": repo, "tag": release["tag_name"],
                 "assets": {name: {"url": item["url"], "browser_download_url": item["browser_download_url"]}
                            for name, item in assets.items()}}
        (output / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
        print(f"Reusable snapshot index: {release['tag_name']}")
    except (OSError, ValueError, KeyError, LookupError, urllib.error.URLError, json.JSONDecodeError) as exc:
        for name in ("manifest.json", "kernel-matrix.json", "SHA256SUMS"):
            (output / name).unlink(missing_ok=True)
        (output / "index.json").write_text(json.dumps({"schema_version": 1, "repository": repo,
            "tag": None, "assets": {}}) + "\n")
        print(f"No reusable snapshot: {exc}", file=sys.stderr)


def read_index(path):
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("reuse index is missing or unsafe")
    index_path = path / "index.json"
    if index_path.is_symlink() or not index_path.is_file():
        raise ValueError("reuse index descriptor is missing or unsafe")
    index = json.loads(index_path.read_text())
    if index.get("schema_version") != 1:
        raise ValueError("unsupported reuse index schema")
    return index


def checksums(index_dir):
    path = Path(index_dir) / "SHA256SUMS"
    if path.is_symlink() or not path.is_file():
        raise ValueError("reuse SHA256SUMS is missing or unsafe")
    result = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match.group(2) in result:
            raise ValueError("malformed or duplicate reusable release checksum")
        result[match.group(2)] = match.group(1)
    for name in ("manifest.json", "kernel-matrix.json"):
        if result.get(name) != sha256(Path(index_dir) / name):
            raise ValueError(f"reusable release checksum mismatch: {name}")
    return result


def stable_config(config):
    return {key: value for key, value in config.items() if key not in {"sdk_ref", "sdk_tag"}}


def metadata_for_build(key, record, descriptor, reuse):
    config = record["configuration"]
    metadata = {field: record[field] for field in (
        "sdk_input_key", "configuration", "descriptor_sha256", "module_source_sha256",
        "build_inputs_sha256", "source_sha256", "environment", "version", "sdk_ref", "kernel",
        "arch", "kernel_ref", "kernel_release", "contract", "mips_calls", "module_cflags",
        "kernel_source_version", "kernel_source_evidence", "toolchain_archive_sha256", "kernel_archive_sha256",
        "kernel_config_sha256", "module_symvers_sha256", "provider_export_evidence",
        "ipv6_supported", "ipv6_unavailable_reason")}
    metadata.update({"build_kind": "descriptor", "build_key": key, "model": config["model"],
                     "representative": config["model"], "priority_mode": record["contract"]["priority_mode"],
                     "priority": record["contract"]["priority"], "table_abi": record["contract"]["table_abi"],
                     "mips_calls": record["contract"]["mips_calls"], "sdk_config_sha256": config["config_sha256"],
                     "reused_from_snapshot": reuse, "modules": {}})
    for kind, item in record["modules"].items():
        metadata["modules"][kind] = {field: item[field] for field in (
            "sha256", "size", "vermagic", "version", "undefined_symbols", "elf",
            "keenpbr_priority", "keenpbr_table_abi", "fingerprint")}
        metadata["modules"][kind]["file"] = f"modules/{MODULES[kind]}"
    return metadata


def reuse(index_dir, plan_path, shard_index, output_dir, token):
    index_dir, output_dir = Path(index_dir), Path(output_dir)
    index = read_index(index_dir)
    if not index.get("tag"):
        return 0
    sums = checksums(index_dir)
    manifest = json.loads((index_dir / "manifest.json").read_text())
    matrix = json.loads((index_dir / "kernel-matrix.json").read_text())
    if manifest.get("schema_version") != 2 or hashlib.sha256((index_dir / "kernel-matrix.json").read_bytes()).hexdigest() != manifest.get("matrix_sha256"):
        raise ValueError("reusable release has invalid manifest/matrix provenance")
    if index["tag"] != f"modules-v{manifest.get('version')}-{manifest.get('snapshot')}":
        raise ValueError("reusable release tag does not match its snapshot digest")
    plan = json.loads(Path(plan_path).read_text())
    if plan.get("matrix_sha256") != hashlib.sha256(Path(ROOT / "kernel-matrix.json").read_bytes()).hexdigest():
        raise ValueError("current plan does not match checked out matrix")
    shard = next((item for item in plan.get("shards", []) if item.get("shard") == shard_index), None)
    if shard is None:
        raise ValueError(f"unknown shard {shard_index}")
    assets = index.get("assets", {})
    downloaded = {}
    reused_count = 0
    for key in shard["build_keys"]:
        descriptor = plan["descriptors"][key]
        old = manifest.get("builds", {}).get(key)
        if not isinstance(old, dict):
            continue
        model = descriptor["configuration"]["model"]
        if not any(sdk.get("models", {}).get(model, {}).get("status") == "supported" and
                   sdk["models"][model].get("configuration") == descriptor["sdk_input_key"]
                   for sdk in matrix.get("sdks", {}).values()):
            continue
        if not any(item.get("build_key") == key
                   for models in manifest.get("releases", {}).values() for item in models.values()):
            continue
        if (old.get("sdk_input_key") != descriptor["sdk_input_key"] or
                stable_config(old.get("configuration", {})) != stable_config(descriptor["configuration"]) or
                old.get("module_source_sha256") != descriptor["module_source_sha256"] or
                old.get("build_inputs_sha256") != descriptor["build_inputs_sha256"] or
                old.get("environment") != descriptor["environment"] or
                old.get("version") != descriptor["contract"]["version"] or
                old.get("contract") != descriptor["contract"]):
            continue
        if not HASH_RE.fullmatch(old.get("descriptor_sha256", "")) or not old.get("modules", {}).get("ipv4"):
            continue
        module_bytes = {}
        valid = True
        for kind, item in old["modules"].items():
            if kind not in MODULES or not isinstance(item, dict):
                valid = False
                break
            name = item.get("asset_file")
            expected_name = ("iptable_keenpbr" if kind == "ipv4" else "ip6table_keenpbr") + f"-{item.get('sha256')}.ko"
            if name != expected_name or not HASH_RE.fullmatch(item.get("sha256", "")):
                valid = False
                break
            if name not in downloaded:
                asset = assets.get(name)
                if not asset:
                    valid = False
                    break
                raw = request_bytes(asset["url"], token, "application/octet-stream")
                if hashlib.sha256(raw).hexdigest() != item["sha256"] or sums.get(name) != item["sha256"]:
                    valid = False
                    break
                downloaded[name] = raw
            raw = downloaded[name]
            with tempfile.TemporaryDirectory(prefix="keenpbr-reuse-audit-") as audit_dir, tempfile.NamedTemporaryFile(suffix=".ko") as module:
                module.write(raw)
                module.flush()
                actual = audit_module(module.name, Path(audit_dir), descriptor["configuration"]["arch"])
                actual["fingerprint"] = fingerprint(module.name)
            for field in ("sha256", "size", "vermagic", "version", "undefined_symbols", "elf",
                          "keenpbr_priority", "keenpbr_table_abi", "fingerprint"):
                if actual.get(field) != item.get(field):
                    valid = False
                    break
            if (actual.get("version") != descriptor["contract"]["version"] or
                    actual.get("keenpbr_priority") != str(descriptor["contract"]["priority"]) or
                    actual.get("keenpbr_table_abi") != str(descriptor["contract"]["table_abi"]) or
                    actual.get("vermagic", "").split()[0] != old.get("kernel_release")):
                valid = False
            if not valid:
                break
            module_bytes[kind] = raw
        if not valid:
            continue
        if output_dir.is_symlink():
            raise ValueError("build output directory is a symlink")
        folder = output_dir / key
        if folder.exists():
            raise ValueError(f"refusing to replace existing build output {folder}")
        (folder / "modules").mkdir(parents=True)
        metadata = metadata_for_build(key, old, descriptor, {"tag": index["tag"], "snapshot": manifest["snapshot"],
                                    "manifest_sha256": sums["manifest.json"]})
        (folder / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
        checks = []
        for kind, raw in module_bytes.items():
            filename = MODULES[kind]
            (folder / "modules" / filename).write_bytes(raw)
            checks.append(f"{hashlib.sha256(raw).hexdigest()}  modules/{filename}")
        checks.append(f"{sha256(folder / 'metadata.json')}  metadata.json")
        (folder / "SHA256SUMS").write_text("\n".join(checks) + "\n")
        reused_count += 1
    return reused_count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch-index", action="store_true")
    parser.add_argument("--repository", help="GitHub owner/repository")
    parser.add_argument("--token", default="")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--index", type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--shard", type=int)
    args = parser.parse_args()
    try:
        if args.fetch_index:
            if not args.repository or not args.token:
                raise ValueError("fetching a release index requires --repository and --token")
            download_index(args.repository, args.token, args.output)
        else:
            if not args.index or not args.plan or args.shard is None:
                raise ValueError("reuse requires --index, --plan, and --shard")
            count = reuse(args.index, args.plan, args.shard, args.output, args.token)
            print(f"Reused {count} verified builds")
    except (OSError, ValueError, KeyError, RuntimeError, urllib.error.URLError, json.JSONDecodeError) as exc:
        print(f"release reuse failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
