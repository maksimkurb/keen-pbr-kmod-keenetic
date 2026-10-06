#!/usr/bin/env python3
"""Validate complete SDK build coverage and assemble a content-addressed snapshot."""
import argparse
import functools
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from kmodlib import MODEL_RE, audit_module, fingerprint, sha256, source_sha256
from sdk_matrix import build_inputs_sha256
from snapshotlib import BUILD_PROVENANCE_FIELDS, MODULE_AUDIT_FIELDS, snapshot_digest

CONTRACT = {"table": "keenpbr", "hook": "PREROUTING", "priority": -149, "table_abi": 1}
MODULES = {"ipv4": "iptable_keenpbr.ko", "ipv6": "ip6table_keenpbr.ko"}
UNSUPPORTED_MODEL_RE = re.compile(r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
def fail(message):
    raise ValueError(message)


def read_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        fail(f"missing or unsafe JSON file: {path}")
    return json.loads(path.read_text())


def verify_build_sums(folder, metadata, trusted_reuse=False):
    sums_path = folder / "SHA256SUMS"
    if sums_path.is_symlink() or not sums_path.is_file():
        fail(f"build {folder.name}: missing or unsafe SHA256SUMS")
    expected = {"metadata.json"}
    modules = metadata.get("modules", {})
    expected.update(item.get("file") for item in modules.values() if isinstance(item, dict))
    seen = set()
    for line in sums_path.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
        if not match:
            fail(f"build {folder.name}: malformed SHA256SUMS row")
        digest, name = match.groups()
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or name in seen:
            fail(f"build {folder.name}: unsafe/duplicate checksum path")
        seen.add(name)
        target = folder / path
        if target.is_symlink() or not target.is_file() or sha256(target) != digest:
            fail(f"build {folder.name}: SHA256 mismatch for {name}")
    if seen != expected:
        fail(f"build {folder.name}: SHA256SUMS coverage mismatch")
    if not trusted_reuse:
        for name, field in (("audit/kernel.config", "kernel_config_sha256"),
                            ("audit/Module.symvers", "module_symvers_sha256")):
            target = folder / name
            if target.is_symlink() or not target.is_file() or sha256(target) != metadata.get(field):
                fail(f"build {folder.name}: {name} does not match metadata {field}")


def verify_module(folder, kind, recorded, descriptor, metadata):
    filename = MODULES[kind]
    if recorded.get("file") not in {filename, f"modules/{filename}"}:
        fail(f"{folder.name}/{kind}: malformed module path")
    path = folder / "modules" / filename
    if path.is_symlink() or not path.is_file() or not path.stat().st_size:
        fail(f"{folder.name}/{kind}: module is missing or unsafe")
    actual_sha = sha256(path)
    if actual_sha != recorded.get("sha256"):
        fail(f"{folder.name}/{kind}: module SHA256 does not match audit")
    with tempfile.TemporaryDirectory(prefix="keenpbr-release-audit-") as audit_dir:
        actual = audit_module(path, Path(audit_dir), descriptor["configuration"]["arch"])
    actual["fingerprint"] = fingerprint(path)
    for field in ("sha256", "size", "vermagic", "version", "undefined_symbols", "keenpbr_priority", "keenpbr_table_abi", "elf", "fingerprint"):
        if actual.get(field) != recorded.get(field):
            fail(f"{folder.name}/{kind}: actual {field} differs from recorded audit")
    if actual.get("version") != descriptor["contract"]["version"]:
        fail(f"{folder.name}/{kind}: embedded module version mismatch")
    if actual.get("keenpbr_priority") != str(descriptor["contract"]["priority"]):
        fail(f"{folder.name}/{kind}: embedded priority mismatch")
    if actual.get("keenpbr_table_abi") != str(descriptor["contract"]["table_abi"]):
        fail(f"{folder.name}/{kind}: embedded table ABI mismatch")
    kernel_release = metadata.get("kernel_release")
    if not kernel_release or not actual.get("vermagic", "").split() or actual["vermagic"].split()[0] != kernel_release:
        fail(f"{folder.name}/{kind}: vermagic does not match the built kernel release")
    return path, actual


@functools.lru_cache(maxsize=1)
def load_trusted_index(index_dir):
    """Load the immutable index once; a large matrix must not be reparsed per build."""
    spec = importlib.util.spec_from_file_location("reuse_release", ROOT / "scripts/reuse-release.py")
    reuse_release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reuse_release)
    if index_dir is None:
        fail("reused output requires a trusted prior release index")
    index_dir = Path(index_dir)
    index = reuse_release.read_index(index_dir)
    sums = reuse_release.checksums(index_dir)
    manifest_path, matrix_path = index_dir / "manifest.json", index_dir / "kernel-matrix.json"
    manifest, matrix = read_json(manifest_path), read_json(matrix_path)
    return index, sums, manifest, matrix, reuse_release


def trusted_reuse_record(index_dir, key, metadata, descriptor, repository):
    """Match imported output against a checksummed, published snapshot index."""
    if index_dir is None:
        fail(f"build {key}: reused output requires a trusted prior release index")
    index, sums, manifest, matrix, reuse_release = load_trusted_index(str(Path(index_dir).absolute()))
    marker = metadata.get("reused_from_snapshot")
    if not isinstance(marker, dict):
        fail(f"build {key}: malformed reused snapshot marker")
    index_dir = Path(index_dir)
    manifest_path, matrix_path = index_dir / "manifest.json", index_dir / "kernel-matrix.json"
    if (index.get("repository") != repository or manifest.get("schema_version") != 2 or
            hashlib.sha256(matrix_path.read_bytes()).hexdigest() != manifest.get("matrix_sha256") or
            index.get("tag") != f"modules-v{manifest.get('version')}-{manifest.get('snapshot')}" or
            marker != {"tag": index["tag"], "snapshot": manifest["snapshot"],
                       "manifest_sha256": sums["manifest.json"]}):
        fail(f"build {key}: reuse marker does not match the trusted snapshot index")
    old = manifest.get("builds", {}).get(key)
    if not isinstance(old, dict):
        fail(f"build {key}: reused key is absent from trusted release provenance")
    for field in ("sdk_input_key", "configuration", "descriptor_sha256", "module_source_sha256",
                  "build_inputs_sha256", "source_sha256", "environment", "version", "sdk_ref", "kernel",
                  "arch", "kernel_ref", "kernel_release", "contract", "mips_calls", "module_cflags",
                  "kernel_source_version", "kernel_source_evidence", "toolchain_archive_sha256",
                  "kernel_archive_sha256", "kernel_config_sha256", "module_symvers_sha256",
                  "provider_export_evidence",
                  "ipv6_supported", "ipv6_unavailable_reason"):
        if metadata.get(field) != old.get(field):
            fail(f"build {key}: imported {field} differs from trusted release provenance")
    if (metadata.get("build_key") != key or metadata.get("sdk_input_key") != descriptor["sdk_input_key"] or
            reuse_release.stable_config(old.get("configuration", {})) != reuse_release.stable_config(descriptor["configuration"]) or
            not HASH_RE.fullmatch(old.get("descriptor_sha256", ""))):
        fail(f"build {key}: trusted release does not match current stable build identity")
    model = descriptor["configuration"].get("model")
    matrix_has_model = any(
        sdk.get("models", {}).get(model, {}).get("status") == "supported" and
        sdk["models"][model].get("configuration") == descriptor["sdk_input_key"]
        for sdk in matrix.get("sdks", {}).values())
    release_has_build = any(entry.get("build_key") == key
                            for models in manifest.get("releases", {}).values()
                            for entry in models.values())
    if not matrix_has_model or not release_has_build:
        fail(f"build {key}: trusted release does not map this build to supported coverage")
    for kind, record in old.get("modules", {}).items():
        if kind not in MODULES or not isinstance(record, dict):
            fail(f"build {key}: malformed trusted module record")
        name = record.get("asset_file")
        expected = ("iptable_keenpbr" if kind == "ipv4" else "ip6table_keenpbr") + f"-{record.get('sha256')}.ko"
        if name != expected or sums.get(name) != record.get("sha256") or name not in index.get("assets", {}):
            fail(f"build {key}: trusted module asset is not covered by release checksums")
    if "ipv4" not in old.get("modules", {}):
        fail(f"build {key}: trusted release lacks its required IPv4 module")
    return old


def verify_build(key, descriptor, builds_dir, expected_source, expected_inputs, version,
                 reuse_index=None, repository=None):
    if not re.fullmatch(r"[0-9a-f]{64}", key):
        fail(f"unsafe build key: {key!r}")
    folder = Path(builds_dir) / key
    if folder.is_symlink() or not folder.is_dir():
        fail(f"build {key}: output directory missing or unsafe")
    metadata = read_json(folder / "metadata.json")
    reused = metadata.get("reused_from_snapshot")
    exact = {"build_key": key, "sdk_input_key": descriptor["sdk_input_key"], "contract": descriptor["contract"],
             "module_source_sha256": expected_source, "build_inputs_sha256": expected_inputs,
             "environment": descriptor["environment"], "version": version}
    for field, value in exact.items():
        if metadata.get(field) != value:
            fail(f"build {key}: metadata {field} mismatch")
    if reused:
        trusted_old = trusted_reuse_record(reuse_index, key, metadata, descriptor, repository)
        old_config = {name: value for name, value in metadata.get("configuration", {}).items() if name not in {"sdk_ref", "sdk_tag"}}
        current_config = {name: value for name, value in descriptor["configuration"].items() if name not in {"sdk_ref", "sdk_tag"}}
        if (old_config != current_config or metadata.get("sdk_ref") != metadata["configuration"].get("sdk_ref") or
                metadata.get("descriptor_sha256") != trusted_old.get("descriptor_sha256")):
            fail(f"build {key}: reused SDK configuration identity mismatch")
        if (not HASH_RE.fullmatch(metadata.get("descriptor_sha256", "")) or
                not HASH_RE.fullmatch(reused.get("manifest_sha256", ""))):
            fail(f"build {key}: invalid trusted reuse provenance")
    else:
        if metadata.get("configuration") != descriptor["configuration"]:
            fail(f"build {key}: metadata configuration mismatch")
        descriptor_bytes = (json.dumps(descriptor, indent=2, sort_keys=True) + "\n").encode()
        if metadata.get("descriptor_sha256") != hashlib.sha256(descriptor_bytes).hexdigest():
            fail(f"build {key}: descriptor hash mismatch")
    verify_build_sums(folder, metadata, trusted_reuse=bool(reused))
    modules = metadata.get("modules")
    if not isinstance(modules, dict) or "ipv4" not in modules:
        fail(f"build {key}: IPv4 module audit is missing")
    config = descriptor["configuration"]
    if (metadata.get("arch") != config.get("arch") or metadata.get("kernel_ref") != config.get("kernel_ref")
            or metadata.get("kernel_source_version") != config.get("kernel_source_version")
            or metadata.get("source_sha256") != expected_source
            or metadata.get("sdk_ref") != metadata.get("configuration", {}).get("sdk_ref")
            or (not reused and metadata.get("sdk_ref") != config.get("sdk_ref"))
            or metadata.get("kernel_source_evidence") != "git-head-equals-resolved-sdk-source-tag"):
        fail(f"build {key}: architecture or kernel source mismatch")
    archives = metadata.get("toolchain_archive_sha256")
    if not isinstance(archives, dict) or not archives or any(
            not re.fullmatch(r"[0-9a-f]{64}", digest) for digest in archives.values()):
        fail(f"build {key}: missing/invalid pinned toolchain archive identities")
    if not HASH_RE.fullmatch(metadata.get("kernel_archive_sha256", "")):
        fail(f"build {key}: missing/invalid kernel source archive identity")
    verified = {}
    for kind, filename in MODULES.items():
        if kind not in modules:
            continue
        item = modules[kind]
        if not isinstance(item, dict) or item.get("file") not in {filename, f"modules/{filename}"}:
            fail(f"build {key}/{kind}: malformed module audit")
        path, actual = verify_module(folder, kind, item, descriptor, metadata)
        verified[kind] = (path, actual)
    if metadata.get("ipv6_supported") and "ipv6" not in verified:
        fail(f"build {key}: IPv6 is enabled but module is missing")
    if not metadata.get("ipv6_supported") and "ipv6" in verified:
        fail(f"build {key}: IPv6 module exists although metadata marks it unavailable")
    return folder, metadata, verified


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--builds-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--notes-file", type=Path, required=True)
    parser.add_argument("--repository", required=True, help="owning GitHub repository URL for asset links")
    parser.add_argument("--reuse-index", type=Path, help="checksummed published snapshot index for imported builds")
    args = parser.parse_args()
    try:
        matrix = read_json(args.matrix)
        matrix_bytes = args.matrix.read_bytes()
        plan = read_json(args.plan)
        if hashlib.sha256(matrix_bytes).hexdigest() != plan.get("matrix_sha256"):
            fail("plan was made from different kernel-matrix.json bytes")
        if matrix.get("schema_version") != 1 or plan.get("schema_version") != 1:
            fail("unsupported matrix or plan schema")
        if args.builds_dir.is_symlink() or args.output_dir.is_symlink():
            fail("build and output directories must not be symlinks")
        source_hash = source_sha256(ROOT)
        current_inputs = build_inputs_sha256(ROOT)
        version = (ROOT / "VERSION").read_text().strip()
        if plan.get("source_sha256") != source_hash:
            fail("plan source hash differs from current checkout")
        if plan.get("build_inputs_sha256") != current_inputs:
            fail("plan build inputs hash differs from current checkout")
        descriptors = plan.get("descriptors")
        if not isinstance(descriptors, dict) or set(descriptors) != set(plan.get("build_keys", [])):
            fail("plan descriptor coverage is incomplete")
        if len(plan.get("build_keys", [])) != len(set(plan["build_keys"])):
            fail("plan repeats a build key")
        for key, descriptor in descriptors.items():
            if descriptor.get("build_key") != key or descriptor.get("module_source_sha256") != source_hash or descriptor.get("build_inputs_sha256") != plan["build_inputs_sha256"]:
                fail(f"plan descriptor mismatch: {key}")

        built = {}
        for key in plan["build_keys"]:
            repository_name = args.repository.removeprefix("https://github.com/").rstrip("/")
            built[key] = verify_build(key, descriptors[key], args.builds_dir, source_hash,
                                      plan["build_inputs_sha256"], version, args.reuse_index, repository_name)

        releases = {}
        unique_assets = {}
        notes_rows = {}
        used_keys = set()
        for tag, sdk in sorted(matrix["sdks"].items()):
            series = sdk.get("series")
            if not isinstance(series, str) or not series:
                fail(f"{tag}: missing SDK series")
            models = sdk.get("models")
            if not isinstance(models, dict):
                fail(f"{tag}: malformed model mapping")
            release_models = {}
            for model, item in sorted(models.items()):
                if not UNSUPPORTED_MODEL_RE.fullmatch(model) or not isinstance(item, dict):
                    fail(f"{tag}: unsafe/malformed model {model!r}")
                if item.get("status") == "unsupported":
                    reason = item.get("reason")
                    if not isinstance(reason, str) or not reason.strip():
                        fail(f"{tag}/{model}: unsupported outcome lacks a reason")
                    release_models[model] = {"status": "unsupported", "reason": reason}
                    notekey = (model, series, "unsupported", reason)
                    notes_rows.setdefault(notekey, set()).add(tag)
                    continue
                if item.get("status") != "supported":
                    fail(f"{tag}/{model}: unknown support status")
                if not MODEL_RE.fullmatch(model):
                    fail(f"{tag}/{model}: supported entries must be exact KN model IDs")
                config_key = item.get("configuration")
                config = matrix["configurations"].get(config_key)
                if not config or config_key != config.get("sdk_input_key"):
                    fail(f"{tag}/{model}: missing exact configuration")
                matches = [key for key, descriptor in descriptors.items()
                           if descriptor["sdk_input_key"] == config_key]
                if len(matches) != 1:
                    fail(f"{tag}/{model}: expected one unique planned build for {config_key}")
                key = matches[0]
                if key not in built:
                    fail(f"{tag}/{model}: required build did not pass audit")
                folder, metadata, modules = built[key]
                if metadata["configuration"].get("model") != model:
                    fail(f"{tag}/{model}: configuration model mismatch")
                manifest_modules = {}
                for kind, (path, actual) in modules.items():
                    family_prefix = "iptable_keenpbr" if kind == "ipv4" else "ip6table_keenpbr"
                    asset = f"{family_prefix}-{actual['sha256']}.ko"
                    unique_assets[(kind, actual["sha256"])] = (path, asset)
                    manifest_modules[kind] = {"file": asset, **{
                        field: actual[field] for field in ("sha256", "size", "vermagic", "version", "undefined_symbols",
                                                           "elf", "keenpbr_priority", "keenpbr_table_abi", "fingerprint")
                    }}
                unavailable = metadata.get("ipv6_unavailable_reason")
                entry = {"status": "experimental", "build_key": key, "modules": manifest_modules}
                if "ipv6" not in modules:
                    if not unavailable:
                        fail(f"{tag}/{model}: IPv6 absent without an audited reason")
                    entry["ipv6_unavailable_reason"] = unavailable
                release_models[model] = entry
                used_keys.add(key)
                module_key = tuple((family, manifest_modules.get(family, {}).get("file")) for family in MODULES)
                notes_rows.setdefault((model, series, "experimental", module_key), set()).add(tag)
            releases[tag] = release_models

        if used_keys != set(plan["build_keys"]):
            fail("plan contains a successful build that is unused by accepted matrix coverage")
        provenance = {}
        for key in sorted(used_keys):
            _, metadata, modules = built[key]
            provenance[key] = {field: metadata[field] for field in BUILD_PROVENANCE_FIELDS}
            provenance[key]["modules"] = {
                kind: {"asset_file": unique_assets[(kind, item[1]["sha256"])][1],
                       **{field: item[1][field] for field in MODULE_AUDIT_FIELDS}}
                for kind, item in modules.items()}
        input_digest = snapshot_digest(plan["matrix_sha256"], used_keys,
                                       ((kind, digest) for kind, digest in unique_assets), provenance)
        snapshot_name = f"modules-{version}-{input_digest}"
        destination = args.output_dir / snapshot_name
        if destination.is_symlink():
            fail(f"refusing symlink snapshot destination: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix="." + snapshot_name + ".tmp-", dir=destination.parent))
        try:
            for (kind, digest), (path, filename) in sorted(unique_assets.items()):
                target = stage / filename
                shutil.copyfile(path, target)
                if sha256(target) != digest:
                    fail(f"artifact changed while copying: {filename}")
            shutil.copyfile(args.matrix, stage / "kernel-matrix.json")
            builds_manifest = {}
            for key in sorted(used_keys):
                folder, metadata, modules = built[key]
                builds_manifest[key] = {field: metadata[field] for field in BUILD_PROVENANCE_FIELDS}
                builds_manifest[key]["modules"] = {}
                for kind, item in modules.items():
                    actual = item[1]
                    asset = unique_assets[(kind, actual["sha256"])][1]
                    builds_manifest[key]["modules"][kind] = {
                        "file": f"modules/{MODULES[kind]}", "asset_file": asset,
                        **{field: actual[field] for field in (
                            "sha256", "size", "vermagic", "version", "undefined_symbols", "elf",
                            "keenpbr_priority", "keenpbr_table_abi", "fingerprint")}}
            manifest = {"schema_version": 2, "version": version,
                        "matrix_sha256": plan["matrix_sha256"], "snapshot": input_digest,
                        "contract": CONTRACT, "builds": builds_manifest, "releases": releases}
            (stage / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            repository = args.repository.rstrip("/")
            if not repository.startswith("https://github.com/"):
                fail("--repository must be an HTTPS GitHub repository URL")
            release_tag = f"modules-v{version}-{input_digest}"
            by_series = {}
            for (model, series, status, mapping), tags in notes_rows.items():
                versions = ", ".join(sorted(tags))
                if status == "unsupported":
                    ipv4 = ipv6 = "—"
                    status_text = "unsupported: " + mapping
                else:
                    by_family = dict(mapping)
                    family_links = []
                    for family in ("ipv4", "ipv6"):
                        filename = by_family.get(family)
                        if filename:
                            href = f"{repository}/releases/download/{release_tag}/{filename}"
                            family_links.append(f"[{filename}]({href})")
                        else:
                            family_links.append("—")
                    ipv4, ipv6 = family_links
                    status_text = "experimental"
                row = f"| {model} | {series} | {versions} | {ipv4} | {ipv6} | {status_text} |"
                by_series.setdefault(series, []).append(row)
            lines = [f"Build snapshot `{release_tag}` covers {len(releases)} exact SDK tags and {len(used_keys)} unique audited builds."]
            for series, rows in sorted(by_series.items()):
                lines.extend(["", f"<details><summary>SDK series {series}</summary>", "",
                              "| Model | SDK series | SDK versions | IPv4 | IPv6 | Status |",
                              "|---|---|---|---|---|---|"])
                lines.extend(sorted(rows))
                lines.extend(["", "</details>"])
            notes = "\n".join(lines) + "\n"
            if len(notes.encode()) > 100_000:
                (stage / "RELEASE_NOTES.md").write_text(notes)
                series_counts = {series: len(rows) for series, rows in by_series.items()}
                summary = ", ".join(f"{series}: {count} mappings" for series, count in sorted(series_counts.items()))
                notes = (f"The exact per-model SDK version table exceeds the release description limit.\n\n"
                         f"Full table: [RELEASE_NOTES.md]({repository}/releases/download/{release_tag}/RELEASE_NOTES.md).\n\n"
                         f"SDK series coverage: {summary}.\n")
            args.notes_file.parent.mkdir(parents=True, exist_ok=True)
            if args.notes_file.is_symlink():
                fail(f"refusing symlink notes file: {args.notes_file}")
            args.notes_file.write_text(notes)
            sums = sorted(path.name for path in stage.glob("*.ko")) + ["kernel-matrix.json", "manifest.json"]
            if (stage / "RELEASE_NOTES.md").exists():
                sums.append("RELEASE_NOTES.md")
            (stage / "SHA256SUMS").write_text("".join(f"{sha256(stage / name)}  {name}\n" for name in sums))
            if len(list(stage.iterdir())) > 1000:
                fail(f"snapshot has {len(list(stage.iterdir()))} assets; GitHub limit is 1000")
            if destination.exists():
                fail(f"immutable snapshot already exists: {destination}")
            os.replace(stage, destination)
        except Exception:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        print(destination)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, KeyError) as exc:
        print(f"release assembly failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
