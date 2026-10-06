"""Canonical snapshot provenance hashing shared by assembly and publication."""
import hashlib
import json

BUILD_PROVENANCE_FIELDS = (
    "sdk_input_key", "configuration", "descriptor_sha256", "module_source_sha256",
    "build_inputs_sha256", "source_sha256", "environment", "version", "sdk_ref", "kernel",
    "arch", "kernel_ref", "kernel_release", "contract", "mips_calls", "module_cflags",
    "kernel_source_version", "kernel_source_evidence", "toolchain_archive_sha256",
    "kernel_archive_sha256", "kernel_config_sha256", "module_symvers_sha256",
    "provider_export_evidence", "ipv6_supported", "ipv6_unavailable_reason")
MODULE_AUDIT_FIELDS = (
    "sha256", "size", "vermagic", "version", "undefined_symbols", "elf",
    "keenpbr_priority", "keenpbr_table_abi", "fingerprint")
MODULE_PREFIX = {"ipv4": "iptable_keenpbr", "ipv6": "ip6table_keenpbr"}


def snapshot_digest(matrix_sha256, build_keys, assets, provenance):
    payload = {"matrix_sha256": matrix_sha256, "build_keys": sorted(build_keys),
               "assets": sorted(assets), "build_provenance": provenance}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def manifest_snapshot_digest(manifest):
    """Recompute identity from published manifest records, rejecting malformed provenance."""
    builds = manifest.get("builds")
    if not isinstance(builds, dict) or not builds:
        raise ValueError("snapshot manifest has no build provenance")
    provenance, assets = {}, set()
    for key, record in sorted(builds.items()):
        if not isinstance(record, dict) or any(field not in record for field in BUILD_PROVENANCE_FIELDS):
            raise ValueError(f"snapshot build {key} has incomplete provenance")
        modules = record.get("modules")
        if not isinstance(modules, dict) or "ipv4" not in modules:
            raise ValueError(f"snapshot build {key} lacks IPv4 module provenance")
        provenance[key] = {field: record[field] for field in BUILD_PROVENANCE_FIELDS}
        provenance[key]["modules"] = {}
        for kind, item in sorted(modules.items()):
            if kind not in MODULE_PREFIX or not isinstance(item, dict):
                raise ValueError(f"snapshot build {key} has invalid module provenance")
            if any(field not in item for field in ("asset_file", *MODULE_AUDIT_FIELDS)):
                raise ValueError(f"snapshot build {key}/{kind} has incomplete module provenance")
            if item["asset_file"] != f"{MODULE_PREFIX[kind]}-{item['sha256']}.ko":
                raise ValueError(f"snapshot build {key}/{kind} has mismatched module asset name")
            provenance[key]["modules"][kind] = {
                "asset_file": item["asset_file"],
                **{field: item[field] for field in MODULE_AUDIT_FIELDS}}
            assets.add((kind, item["sha256"]))
    return snapshot_digest(manifest.get("matrix_sha256"), builds, assets, provenance)
