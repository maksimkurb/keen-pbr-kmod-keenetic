#!/usr/bin/env python3
"""Validate build provenance and create a flattened, checksummed release."""
import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kmodlib import ROOT, matrix, sha256, check_arch, fingerprint, PRIORITIES, run, tool, source_sha256


def fail(message):
    raise ValueError(message)


def read_group(group, cfg, out):
    folder = out / group
    if folder.is_symlink() or not folder.is_dir():
        fail(f"{group}: output group is not a regular directory")
    meta_path = folder / "metadata.json"
    if not meta_path.is_file() or meta_path.is_symlink():
        fail(f"{group}: metadata.json missing or not a regular file")
    meta = json.loads(meta_path.read_text())
    if meta.get("group") != group or meta.get("representative") != cfg["representative"]:
        fail(f"{group}: metadata group/representative mismatch")
    if (meta.get("arch") != cfg["arch"] or meta.get("kernel") != "4.9-ndm"
            or not meta.get("kernel_release") or type(meta.get("table_abi")) is not int or meta["table_abi"] != 1):
        fail(f"{group}: kernel/architecture/API metadata mismatch")
    if not re.fullmatch(r"[0-9a-f]{40}", meta.get("sdk_ref", "")):
        fail(f"{group}: unsafe or missing SDK revision")
    for key in ("kernel_config_sha256", "module_symvers_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", meta.get(key, "")):
            fail(f"{group}: invalid {key}")
    for relative, key in (("audit/kernel.config", "kernel_config_sha256"), ("audit/Module.symvers", "module_symvers_sha256")):
        evidence = folder / relative
        if (folder / "audit").is_symlink() or evidence.is_symlink() or not evidence.is_file() or sha256(evidence) != meta[key]:
            fail(f"{group}: missing or stale {relative} evidence")
    if not re.fullmatch(r"[0-9a-f]{64}", meta.get("source_sha256", "")):
        fail(f"{group}: invalid source provenance")
    if meta.get("priority_mode") not in PRIORITIES or type(meta.get("priority")) is not int or meta["priority"] != PRIORITIES[meta["priority_mode"]]:
        fail(f"{group}: invalid priority metadata")
    if meta.get("mips_calls") not in {"sdk", "long"}:
        fail(f"{group}: invalid MIPS call policy")
    expected_cflags = "-mlong-calls" if cfg["arch"] in {"mips", "mipsel"} and meta["mips_calls"] == "long" else ""
    if meta.get("module_cflags") != expected_cflags:
        fail(f"{group}: effective module CFLAGS do not match architecture/call policy")
    sums_path = folder / "SHA256SUMS"
    if not sums_path.is_file(): fail(f"{group}: SHA256SUMS missing")
    sums = {}
    for line in sums_path.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match.group(2) in sums: fail(f"{group}: malformed SHA256SUMS")
        sums[match.group(2)] = match.group(1)
    if sums.get("metadata.json") != sha256(meta_path): fail(f"{group}: stale metadata checksum")
    modules = meta.get("modules")
    if not isinstance(modules, dict) or "ipv4" not in modules:
        fail(f"{group}: IPv4 module metadata missing")
    expected = {"ipv4": "iptable_keenpbr.ko"}
    if cfg["ipv6"]: expected["ipv6"] = "ip6table_keenpbr.ko"
    elif "ipv6" in modules: fail(f"{group}: IPv6 module present although matrix disables it")
    elif not meta.get("ipv6_unavailable_reason"): fail(f"{group}: IPv6 absence needs an explicit reason")
    if set(modules) != set(expected): fail(f"{group}: modules do not match IPv6 support matrix")
    for key, basename in expected.items():
        item = modules[key]
        if not isinstance(item, dict) or item.get("file") != basename or Path(basename).name != basename:
            fail(f"{group}/{key}: unsafe or unexpected module filename")
        path = folder / basename
        if path.is_symlink() or not path.is_file(): fail(f"{group}/{key}: module missing or not regular")
        digest = sha256(path)
        if digest != item.get("sha256") or sums.get(basename) != digest:
            fail(f"{group}/{key}: stale/mismatched module checksum")
        if item.get("size") != path.stat().st_size or not item.get("vermagic") or item.get("version") != meta.get("version"):
            fail(f"{group}/{key}: module metadata mismatch")
        if not isinstance(item.get("undefined_symbols"), list) or any(not isinstance(symbol, str) for symbol in item["undefined_symbols"]):
            fail(f"{group}/{key}: undefined-symbol audit missing")
        if not re.fullmatch(r"[0-9a-f]{64}", item.get("fingerprint", "")) or fingerprint(path) != item["fingerprint"]:
            fail(f"{group}/{key}: stale/missing candidate fingerprint")
        actual_vermagic = run([tool("modinfo"), "-F", "vermagic", str(path)]).strip()
        actual_version = run([tool("modinfo"), "-F", "version", str(path)]).strip()
        actual_priority = run([tool("modinfo"), "-F", "keenpbr_priority", str(path)]).strip()
        actual_abi = run([tool("modinfo"), "-F", "keenpbr_table_abi", str(path)]).strip()
        if (actual_vermagic != item["vermagic"] or actual_version != item["version"]
                or actual_priority != str(meta["priority"]) or actual_abi != "1"
                or item.get("keenpbr_priority") != actual_priority or item.get("keenpbr_table_abi") != actual_abi
                or actual_vermagic.split()[0] != meta["kernel_release"]):
            fail(f"{group}/{key}: modinfo differs from metadata")
        check_arch(path, cfg["arch"])
    if set(sums) != {"metadata.json", *expected.values()}:
        fail(f"{group}: SHA256SUMS contains missing or stale entries")
    return meta


def build_release(out, release, partial):
    groups, models = matrix()
    unknown = []
    for path in out.iterdir() if out.exists() else ():
        if path.is_dir() and (path / "metadata.json").exists() and path.name not in groups:
            unknown.append(path.name)
    if unknown: fail("unknown output groups: " + ", ".join(sorted(unknown)))
    metadata = {}
    for group, cfg in groups.items():
        try:
            metadata[group] = read_group(group, cfg, out)
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            if not partial: raise
            print(f"partial: omit {group}: {exc}", file=sys.stderr)
    if not metadata: fail("no complete group outputs found")
    if not partial and set(metadata) != set(groups): fail("full release is missing one or more matrix groups")
    lock = json.loads((ROOT / "sdk.lock").read_text())
    repo_version = (ROOT / "VERSION").read_text().strip()
    common = ("sdk_ref", "kernel_ref", "kernel_release", "source_sha256", "version", "kernel", "priority_mode", "priority", "table_abi", "mips_calls")
    provenance = {key: metadata[next(iter(metadata))][key] for key in common}
    if provenance["sdk_ref"] != lock["ref"] or provenance["kernel_ref"] != lock["kernel_ref"]:
        fail("build metadata does not match pinned SDK/kernel revisions")
    if provenance["version"] != repo_version:
        fail("build metadata version does not match repository VERSION")
    if provenance["source_sha256"] != source_sha256(ROOT):
        fail("build metadata source hash does not match current module sources")
    for group, meta in metadata.items():
        for key, value in provenance.items():
            if meta.get(key) != value: fail(f"mixed provenance: {group} has different {key}")
    release_parent = release.parent.resolve()
    release_parent.mkdir(parents=True, exist_ok=True)
    # Never replace a build input directory or its parent as the release destination.
    resolved_release = (release_parent / release.name).resolve()
    input_dirs = [*((out / group).resolve() for group in groups)]
    if resolved_release in out.resolve().parents or resolved_release == out.resolve() or any(
        resolved_release == source or resolved_release in source.parents or source in resolved_release.parents
        for source in input_dirs
    ):
        fail("release directory overlaps build inputs")
    if release.is_symlink() or (release.exists() and not release.is_dir()): fail("release destination must be a real directory")
    stage = Path(tempfile.mkdtemp(prefix="." + release.name + ".tmp-", dir=release_parent))
    backup = None
    try:
        release_groups = {}
        for group, cfg in groups.items():
            if group not in metadata: continue
            meta = metadata[group]
            entries = {}
            for kind, source_name in (("ipv4", "iptable_keenpbr.ko"), ("ipv6", "ip6table_keenpbr.ko")):
                item = meta["modules"].get(kind)
                if not item: continue
                asset = f"{source_name[:-3]}-{group}.ko"
                shutil.copyfile(out / group / source_name, stage / asset)
                if sha256(stage / asset) != item["sha256"]:
                    fail(f"{group}/{kind}: artifact changed while copying")
                entries[kind] = {key: item[key] for key in ("sha256", "size", "vermagic", "version", "undefined_symbols", "fingerprint") if key in item}
                entries[kind]["file"] = asset
            release_groups[group] = {
                "representative": cfg["representative"], "arch": cfg["arch"],
                "kernel": meta["kernel"], "kernel_release": meta["kernel_release"],
                "kernel_config_sha256": meta["kernel_config_sha256"],
                "module_symvers_sha256": meta["module_symvers_sha256"],
                "source_sha256": meta["source_sha256"],
                "priority_mode": meta["priority_mode"], "priority": meta["priority"],
                "mips_calls": meta["mips_calls"], "module_cflags": meta["module_cflags"],
                "modules": entries,
            }
        release_models = {model: {**item, "artifact_available": item["group"] in release_groups} for model, item in models.items()}
        manifest = {
            "schema_version": 1,
            "version": provenance["version"],
            "sdk": {"repository": lock["repository"], "ref": provenance["sdk_ref"], "kernel_ref": provenance["kernel_ref"], "kernel": provenance["kernel"], "kernel_release": provenance["kernel_release"]},
            "contract": {"table_abi": provenance["table_abi"], "table": "keenpbr", "hook": "PREROUTING", "priority_mode": provenance["priority_mode"], "priority": provenance["priority"], "mips_calls": provenance["mips_calls"], "partial": partial},
            "groups": release_groups, "models": release_models,
        }
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        assets = sorted(path.name for path in stage.glob("*.ko"))
        with (stage / "SHA256SUMS").open("w") as sums:
            for name in assets + ["manifest.json"]:
                sums.write(f"{sha256(stage / name)}  {name}\n")
        if release.exists():
            backup = release_parent / ("." + release.name + ".old-" + str(os.getpid()))
            if backup.exists(): shutil.rmtree(backup)
            os.replace(release, backup)
        os.replace(stage, release)
        if backup: shutil.rmtree(backup, ignore_errors=True)
    except Exception:
        if stage.exists(): shutil.rmtree(stage)
        if backup and backup.exists() and not release.exists(): os.replace(backup, release)
        raise
    return len(metadata), len(groups)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "out")
    parser.add_argument("--release-dir", type=Path)
    parser.add_argument("--partial", action="store_true", help="write a preview manifest for complete groups found")
    args = parser.parse_args()
    release = args.release_dir or args.out / "release"
    try:
        count, total = build_release(args.out.resolve(), release.expanduser().absolute(), args.partial)
    except (ValueError, OSError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"manifest generation failed: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {'partial preview' if args.partial else 'release'} for {count}/{total} groups to {release}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
