#!/usr/bin/env python3
"""Select and optionally preflight an exact Keenetic release module."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


MODEL_RE = re.compile(r"KN-[0-9]{4}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
FALLBACK = "custom -> raw -> mangle"
CONTRACT = {"table": "keenpbr", "hook": "PREROUTING", "priority": -149, "table_abi": 1}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def detect():
    result = subprocess.run(["ndmc", "-c", "show version"], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError(f"ndmc show version failed: {result.stderr.strip() or result.returncode}")
    fields = {}
    for line in result.stdout.splitlines():
        match = re.match(r"\s*(hw_id|release)\s*[:=]\s*(.*?)\s*\Z", line, re.I)
        if match:
            fields[match.group(1).lower()] = match.group(2)
    model = fields.get("hw_id", "")
    if re.fullmatch(r"KN[0-9]{4}", model):
        model = f"KN-{model[2:]}"
    release = fields.get("release", "")
    if not MODEL_RE.fullmatch(model) or not release:
        raise ValueError("could not parse exact hw_id and full release from ndmc output")
    kernel = subprocess.run(["uname", "-r"], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if kernel.returncode or not kernel.stdout.strip():
        raise ValueError(f"uname -r failed: {kernel.stderr.strip() or kernel.returncode}")
    return model, release, kernel.stdout.strip()


def _load_manifest(path, expected_sha):
    raw = path.read_bytes()
    if expected_sha:
        if not SHA_RE.fullmatch(expected_sha) or hashlib.sha256(raw).hexdigest() != expected_sha:
            raise ValueError("manifest SHA256 does not match --manifest-sha256")
    try:
        manifest = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version", manifest.get("schema")) != 2:
        raise ValueError("unsupported manifest schema; expected schema version 2")
    if manifest.get("contract") != CONTRACT:
        raise ValueError("manifest table contract mismatch")
    if not isinstance(manifest.get("releases"), dict):
        raise ValueError("manifest releases must be an object")
    return manifest, hashlib.sha256(raw).hexdigest()


def _select(manifest, release, model, family, allow_experimental):
    if family not in {"ipv4", "ipv6"}:
        raise ValueError("family must be ipv4 or ipv6")
    models = manifest["releases"].get(release)
    if not isinstance(models, dict):
        raise ValueError(f"unsupported exact release: {release}")
    entry = models.get(model)
    if not isinstance(entry, dict):
        raise ValueError(f"unsupported exact model/release: {model} / {release}")
    status = entry.get("status")
    if status not in {"experimental", "compatible", "verified", "unsupported"}:
        raise ValueError("manifest has an invalid support status")
    if status == "unsupported":
        raise ValueError(f"unsupported model/release: {entry.get('reason', 'no reason provided')}")
    if status == "experimental" and not allow_experimental:
        raise ValueError("experimental mapping requires --allow-experimental")
    modules = entry.get("modules")
    module = modules.get(family) if isinstance(modules, dict) else None
    if not isinstance(module, dict):
        raise ValueError(f"{family} is unavailable for this exact model/release")
    filename, digest = module.get("file"), module.get("sha256")
    expected_name = f"{'iptable' if family == 'ipv4' else 'ip6table'}_keenpbr-{digest}.ko"
    if not isinstance(digest, str) or not SHA_RE.fullmatch(digest) or filename != expected_name:
        raise ValueError(f"{family} manifest artifact name or SHA256 is invalid")
    build_key = entry.get("build_key")
    if not isinstance(build_key, str) or not SHA_RE.fullmatch(build_key):
        raise ValueError("manifest build_key must be a full SHA256")
    if not isinstance(module.get("vermagic"), str) or not module["vermagic"].split():
        raise ValueError(f"{family} manifest vermagic is missing")
    return entry, module, build_key


def _verify_provenance(manifest, build_key, family, module):
    builds = manifest.get("builds")
    build = builds.get(build_key) if isinstance(builds, dict) else None
    modules = build.get("modules") if isinstance(build, dict) else None
    audit = modules.get(family) if isinstance(modules, dict) else None
    if not isinstance(audit, dict):
        raise ValueError(f"build provenance is missing for {build_key}/{family}")
    for field in ("sha256", "vermagic"):
        if audit.get(field) != module.get(field):
            raise ValueError(f"build provenance {family} {field} mismatch")
    return build


def _verify_artifact(directory, filename, digest):
    name = Path(filename)
    if name.name != filename or filename in {".", ".."}:
        raise ValueError("unsafe artifact path in manifest")
    root = Path(directory)
    path = root / filename
    if root.is_symlink() or path.is_symlink() or not path.is_file() or path.resolve().parent != root.resolve():
        raise ValueError(f"artifact missing or unsafe: {filename}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != digest:
        raise ValueError(f"artifact SHA256 mismatch: {filename}")
    return str(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--model")
    parser.add_argument("--release")
    parser.add_argument("--kernel-release")
    parser.add_argument("--family", required=True)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--allow-experimental", action="store_true")
    parser.add_argument("--detect", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.detect:
            if args.model or args.release or args.kernel_release:
                raise ValueError("--detect cannot be combined with --model, --release, or --kernel-release")
            model, release, kernel_release = detect()
        else:
            if not args.model or not args.release:
                raise ValueError("provide both --model and --release, or use --detect")
            model, release = args.model, args.release
            kernel_release = args.kernel_release
        if not MODEL_RE.fullmatch(model):
            raise ValueError("model must be an exact KN-NNNN identifier")
        if args.artifacts and not args.manifest_sha256:
            raise ValueError("artifact preflight requires trusted --manifest-sha256")
        if args.artifacts and not kernel_release:
            raise ValueError("artifact preflight requires --kernel-release or --detect")
        manifest, manifest_sha = _load_manifest(args.manifest, args.manifest_sha256)
        entry, module, build_key = _select(manifest, release, model, args.family,
                                           args.allow_experimental)
        build_provenance = _verify_provenance(manifest, build_key, args.family, module)
        vermagic_release = module["vermagic"].split()[0]
        if kernel_release and vermagic_release != kernel_release:
            raise ValueError(f"module kernel release mismatch: {vermagic_release} != {kernel_release}")
        file = module["file"]
        if args.artifacts:
            file = _verify_artifact(args.artifacts, file, module["sha256"])
        print(json.dumps({
            "ok": True, "fallback": FALLBACK, "model": model, "release": release,
            "family": args.family, "file": file, "sha256": module["sha256"],
            "kernel_release": kernel_release,
            "build_key": build_key, "status": entry["status"],
            "reason": entry.get("reason"), "contract": CONTRACT,
            "provenance": {"manifest_sha256": manifest_sha,
                           "release": release, "model": model,
                           "family": args.family, "build": build_provenance},
            "trusted_manifest": bool(args.manifest_sha256),
        }, sort_keys=True))
        return 0
    except (OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "status": "unavailable", "fallback": FALLBACK,
                          "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
