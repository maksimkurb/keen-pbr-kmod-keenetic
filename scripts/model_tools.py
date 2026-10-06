"""Pinned SDK discovery, exact-model artifact validation and pair grouping."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

from kmodlib import (ARCHES, MODEL_RE, PRIORITIES, ROOT, check_arch, fingerprint,
                     run, sha256, source_sha256, tool, undefined_symbols)

MODEL_LINE = re.compile(r"^\s*(KN-[0-9]{4})(?:\s|_|$)")
ASSIGNMENT = re.compile(r"^\s*([A-Z0-9_]+)\s*:?=\s*([^#\s]+)")
CONFIG_LINE = re.compile(r"^(?:CONFIG_)([A-Z0-9_]+)=(.*)$")
MIPS_ARCHES = {"mips", "mipsel"}


def validate_sdk_checkout(sdk_dir):
    sdk = Path(sdk_dir).expanduser().resolve()
    lock = json.loads((ROOT / "sdk.lock").read_text())
    if not (sdk / ".git").exists():
        raise ValueError(f"SDK_DIR is not a git checkout: {sdk}")
    head = run(["git", "-C", str(sdk), "rev-parse", "HEAD"]).strip()
    if head != lock["ref"]:
        raise ValueError(f"SDK checkout mismatch: HEAD={head}, required {lock['ref']}")
    diff = subprocess.run(["git", "-C", str(sdk), "diff", "--quiet", "HEAD", "--"])
    if diff.returncode:
        raise ValueError("SDK has tracked modifications; restore them before discovery/build")
    if not (sdk / "configure.sh").is_file():
        raise ValueError(f"pinned SDK has no configure.sh: {sdk}")
    return sdk, lock


def parse_configure_list(text):
    """Extract the exact KN models shown in `configure.sh -l`'s first column."""
    models = []
    for line in text.splitlines():
        match = MODEL_LINE.match(line)
        if match:
            models.append(match.group(1))
    if not models:
        raise ValueError("configure.sh -l contained no KN model rows")
    if len(models) != len(set(models)):
        raise ValueError("configure.sh -l listed a KN model more than once")
    return sorted(models)


def _config_values(path):
    values = {}
    for line in path.read_text().splitlines():
        if line.startswith("#"):
            continue
        match = CONFIG_LINE.match(line)
        if not match:
            continue
        key, value = match.groups()
        if value.startswith('"'):
            try:
                value = json.loads(value)
            except ValueError as exc:
                raise ValueError(f"unsupported config string {key} in {path}") from exc
        if key in values:
            raise ValueError(f"duplicate CONFIG_{key} in {path}")
        values[key] = value
    return values


def _board_fields(path):
    fields = {}
    for line in path.read_text().splitlines():
        match = ASSIGNMENT.match(line)
        if match and match.group(1) in {"ARCH", "KERNEL_PATCHVER"}:
            key, value = match.groups()
            if "$" in value or value.startswith("$("):
                raise ValueError(f"unsupported dynamic {key} assignment in {path}")
            if key in fields:
                raise ValueError(f"duplicate {key} assignment in {path}")
            fields[key] = value
    if set(fields) != {"ARCH", "KERNEL_PATCHVER"}:
        raise ValueError(f"{path} must declare ARCH and KERNEL_PATCHVER")
    return fields


def parse_inventory_config(sdk, config_path, tracked):
    sdk = Path(sdk).resolve()
    config = Path(config_path)
    relative = config.relative_to(sdk).as_posix()
    parts = config.relative_to(sdk / "target/linux").parts
    if len(parts) != 3 or parts[0] in {"", ".", ".."} or parts[2] != "ndwrt.config":
        raise ValueError(f"unsupported SDK model config path: {relative}")
    board, model = parts[:2]
    if not MODEL_RE.fullmatch(model):
        raise ValueError(f"model directory is not an exact KN ID: {relative}")
    board_file = sdk / "target/linux" / board / "Makefile"
    if board_file.is_symlink() or not board_file.is_file() or board_file.resolve().parent != (sdk / "target/linux" / board).resolve():
        raise ValueError(f"unsafe or missing board Makefile: {board_file}")
    config_resolved = config.resolve()
    if config.is_symlink() or sdk not in config_resolved.parents or relative not in tracked:
        raise ValueError(f"model config is untracked or escapes the pinned SDK: {relative}")
    fields = _board_fields(board_file)
    values = _config_values(config)
    arch = fields["ARCH"]
    if arch not in ARCHES or fields["KERNEL_PATCHVER"] != "4.9":
        raise ValueError(f"unsupported SDK target {board}: {arch}/{fields['KERNEL_PATCHVER']}")
    if values.get("TARGET_BOARD") != board or values.get("ARCH") != arch or values.get("TARGET_ARCH_PACKAGES") != model:
        raise ValueError(f"board/model/architecture config mismatch: {relative}")
    item = {"board": board, "arch": arch, "kernel_patchver": fields["KERNEL_PATCHVER"],
            "config": relative, "config_sha256": sha256(config)}
    if values.get("TARGET_DESCRIPTION"):
        item["description"] = values["TARGET_DESCRIPTION"]
    return model, item, board_file


def discover_inventory(sdk_dir):
    sdk, lock = validate_sdk_checkout(sdk_dir)
    tracked_lines = run(["git", "-C", str(sdk), "ls-files", "--", "target/linux"]).splitlines()
    tracked = set(tracked_lines)
    if not tracked:
        raise ValueError("SDK git index contains no target/linux files")
    root = sdk / "target/linux"
    actual_configs = sorted(root.rglob("ndwrt.config"))
    tracked_configs = sorted(sdk / path for path in tracked_lines if path.endswith("/ndwrt.config"))
    extra = sorted(path.relative_to(sdk).as_posix() for path in actual_configs
                   if path.relative_to(sdk).as_posix() not in tracked)
    if extra:
        raise ValueError("untracked SDK model configs are not part of the pinned catalog: " + ", ".join(extra))
    models = {}
    for config in tracked_configs:
        if not config.exists():
            raise ValueError(f"tracked SDK model config is missing: {config}")
        model, item, board_file = parse_inventory_config(sdk, config, tracked)
        board_rel = board_file.relative_to(sdk).as_posix()
        if board_rel not in tracked:
            raise ValueError(f"untracked SDK board Makefile: {board_rel}")
        if model in models:
            raise ValueError(f"duplicate model ID in SDK: {model}")
        models[model] = item
    if not models:
        raise ValueError("pinned SDK contains no supported KN model configs")
    listing = run([str(sdk / "configure.sh"), "-l"], cwd=sdk)
    listed = parse_configure_list(listing)
    if listed != sorted(models):
        missing = sorted(set(listed) - set(models))
        unlisted = sorted(set(models) - set(listed))
        raise ValueError(f"configure.sh -l/catalog mismatch; untracked-inventory={missing}, not-listed={unlisted}")
    return {"schema_version": 1, "sdk_ref": lock["ref"], "kernel_ref": lock["kernel_ref"],
            "models": {key: models[key] for key in sorted(models)}}


def atomic_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise ValueError(f"refusing symlink output: {target}")
    fd, name = tempfile.mkstemp(prefix="." + target.name + ".tmp-", dir=target.parent)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(value, out, indent=2, sort_keys=True)
            out.write("\n")
        os.replace(name, target)
    except Exception:
        Path(name).unlink(missing_ok=True)
        raise


def read_inventory(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"discovery inventory is missing or unsafe: {path}")
    data = json.loads(path.read_text())
    models = data.get("models")
    if data.get("schema_version") != 1 or not isinstance(models, dict) or not models:
        raise ValueError(f"invalid discovery inventory: {path}")
    if len(models) != len(set(models)) or any(not MODEL_RE.fullmatch(model) for model in models):
        raise ValueError("inventory has duplicate or unsafe model IDs")
    for model, item in models.items():
        if item.get("arch") not in ARCHES or not re.fullmatch(r"[0-9a-f]{64}", item.get("config_sha256", "")):
            raise ValueError(f"invalid inventory item: {model}")
    return data


def _module_audit(folder, kind, item, arch):
    expected_file = "iptable_keenpbr.ko" if kind == "ipv4" else "ip6table_keenpbr.ko"
    if item.get("file") != expected_file:
        raise ValueError(f"{kind}: unsafe/unexpected module filename")
    path = folder / expected_file
    if path.is_symlink() or not path.is_file() or sha256(path) != item.get("sha256"):
        raise ValueError(f"{kind}: missing/stale module bytes")
    check_arch(path, arch)
    if fingerprint(path) != item.get("fingerprint"):
        raise ValueError(f"{kind}: stale fingerprint")
    actual = {"sha256": sha256(path), "size": path.stat().st_size,
              "undefined_symbols": sorted(line.split()[-1] for line in undefined_symbols(path).splitlines() if line.split())}
    for key in ("vermagic", "version", "keenpbr_priority", "keenpbr_table_abi"):
        actual[key] = run([tool("modinfo"), "-F", key, str(path)], check=False).strip() or None
    for key in ("sha256", "size", "vermagic", "version", "undefined_symbols", "keenpbr_priority", "keenpbr_table_abi"):
        if actual.get(key) != item.get(key):
            raise ValueError(f"{kind}: stale {key} audit")
    return path


def validate_model_output(folder, inventory_model, expected=None):
    """Return validated model metadata; reject stale hashes, audit or incomplete v6."""
    folder = Path(folder)
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError(f"not a model output directory: {folder}")
    meta_path = folder / "metadata.json"
    if meta_path.is_symlink() or not meta_path.is_file():
        raise ValueError(f"metadata missing for {folder.name}")
    meta = json.loads(meta_path.read_text())
    model = inventory_model.get("model") or folder.name
    if (meta.get("build_kind") != "sdk-model" or meta.get("model") != model or
            meta.get("representative") != model or meta.get("arch") != inventory_model.get("arch") or
            meta.get("sdk_config_sha256") != inventory_model.get("config_sha256")):
        raise ValueError(f"{model}: exact SDK model/config metadata mismatch")
    required_hashes = ("sdk_ref", "kernel_ref", "source_sha256", "sdk_config_sha256",
                       "kernel_config_sha256", "module_symvers_sha256")
    for key in required_hashes:
        if not re.fullmatch(r"[0-9a-f]{64}" if key.endswith("sha256") else r"[0-9a-f]{40}", meta.get(key, "")):
            raise ValueError(f"{model}: invalid/missing {key}")
    lock = json.loads((ROOT / "sdk.lock").read_text())
    if meta["sdk_ref"] != lock["ref"] or meta["kernel_ref"] != lock["kernel_ref"]:
        raise ValueError(f"{model}: SDK/kernel pin mismatch")
    if meta["source_sha256"] != source_sha256(ROOT) or meta.get("version") != (ROOT / "VERSION").read_text().strip():
        raise ValueError(f"{model}: module source/version differs from current checkout")
    if (meta.get("priority_mode") not in PRIORITIES or type(meta.get("priority")) is not int
            or meta["priority"] != PRIORITIES[meta["priority_mode"]] or type(meta.get("table_abi")) is not int
            or meta["table_abi"] != 1 or meta.get("mips_calls") not in {"sdk", "long"}):
        raise ValueError(f"{model}: invalid build policy metadata")
    expected_flags = "-mlong-calls" if inventory_model["arch"] in MIPS_ARCHES and meta["mips_calls"] == "long" else ""
    if meta.get("module_cflags") != expected_flags:
        raise ValueError(f"{model}: effective module CFLAGS do not match call policy/architecture")
    if not meta.get("kernel_release"):
        raise ValueError(f"{model}: missing exact kernel release")
    if expected:
        for key, value in expected.items():
            if meta.get(key) != value:
                raise ValueError(f"{model}: output provenance differs for {key}")
    sums_path = folder / "SHA256SUMS"
    if sums_path.is_symlink() or not sums_path.is_file():
        raise ValueError(f"{model}: SHA256SUMS missing")
    sums = {}
    for line in sums_path.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match.group(2) in sums:
            raise ValueError(f"{model}: malformed SHA256SUMS")
        sums[match.group(2)] = match.group(1)
    if sums.get("metadata.json") != sha256(meta_path):
        raise ValueError(f"{model}: stale metadata checksum")
    evidence = folder / "audit"
    if evidence.is_symlink():
        raise ValueError(f"{model}: audit path is a symlink")
    config_path, symvers_path = evidence / "kernel.config", evidence / "Module.symvers"
    if (config_path.is_symlink() or symvers_path.is_symlink() or not config_path.is_file() or not symvers_path.is_file() or
            sha256(config_path) != meta["kernel_config_sha256"] or sha256(symvers_path) != meta["module_symvers_sha256"]):
        raise ValueError(f"{model}: kernel config/Symvers evidence is missing or stale")
    config_text = config_path.read_text()
    ipv6 = bool(re.search(r"^CONFIG_IP6_NF_IPTABLES=[ym]$", config_text, re.M))
    if ipv6 != meta.get("ipv6_supported"):
        raise ValueError(f"{model}: IPv6 support does not match effective kernel config")
    modules = meta.get("modules")
    expected_modules = {"ipv4"} | ({"ipv6"} if ipv6 else set())
    if not isinstance(modules, dict) or set(modules) != expected_modules:
        raise ValueError(f"{model}: incomplete module pair for IPv6={ipv6}")
    arch = inventory_model["arch"]
    for kind, item in modules.items():
        if not isinstance(item, dict):
            raise ValueError(f"{model}: malformed {kind} metadata")
        if sums.get(item.get("file")) != item.get("sha256"):
            raise ValueError(f"{model}: stale {kind} SHA256SUMS entry")
        if (item.get("version") != meta["version"] or item.get("keenpbr_priority") != str(meta["priority"])
                or item.get("keenpbr_table_abi") != str(meta["table_abi"])
                or not item.get("vermagic") or item["vermagic"].split()[0] != meta["kernel_release"]):
            raise ValueError(f"{model}: {kind} module policy/version/vermagic mismatch")
        _module_audit(folder, kind, item, arch)
    expected_sum_names = {"metadata.json", *(item["file"] for item in modules.values())}
    if set(sums) != expected_sum_names:
        raise ValueError(f"{model}: SHA256SUMS contains stale/unexpected entries")
    if not ipv6 and not meta.get("ipv6_unavailable_reason"):
        raise ValueError(f"{model}: IPv6 absence has no explicit reason")
    if expected and "sdk_ref" in expected:
        if meta["sdk_ref"] != expected["sdk_ref"] or meta["kernel_ref"] != expected["kernel_ref"]:
            raise ValueError(f"{model}: SDK/kernel pin mismatch")
    return meta


def candidate_report(out_dir):
    out = Path(out_dir).resolve()
    discovery = out / "discovery"
    inventory = read_inventory(discovery / "inventory.json")
    lock = json.loads((ROOT / "sdk.lock").read_text())
    if inventory["sdk_ref"] != lock["ref"] or inventory["kernel_ref"] != lock["kernel_ref"]:
        raise ValueError("discovery inventory does not match pinned SDK/kernel")
    report_path = discovery / "build-report.json"
    if report_path.is_symlink():
        raise ValueError("build report must not be a symlink")
    run_report = json.loads(report_path.read_text()) if report_path.is_file() else None
    expected = {"sdk_ref": lock["ref"], "kernel_ref": lock["kernel_ref"],
                "source_sha256": source_sha256(ROOT), "version": (ROOT / "VERSION").read_text().strip()}
    if run_report:
        if run_report.get("sdk_ref") != inventory["sdk_ref"] or run_report.get("kernel_ref") != inventory["kernel_ref"]:
            raise ValueError("build report SDK/kernel provenance mismatch")
        requested = run_report.get("requested")
        if (not isinstance(requested, list) or any(not isinstance(model, str) for model in requested)
                or len(requested) != len(set(requested))
                or any(model not in inventory["models"] for model in requested)):
            raise ValueError("build report has invalid requested model IDs")
        failures = run_report.get("failures", {})
        if not isinstance(failures, dict):
            raise ValueError("build report failures must be an object")
        failed = sorted(failures)
        if not set(failed).issubset(requested):
            raise ValueError("build report has failures for unrequested models")
        for key in ("priority_mode", "priority", "table_abi", "mips_calls"):
            expected[key] = run_report.get(key)
        if (expected["priority_mode"] not in PRIORITIES or type(expected["priority"]) is not int
                or expected["priority"] != PRIORITIES[expected["priority_mode"]]):
            raise ValueError("build report priority policy is invalid")
        if type(expected["table_abi"]) is not int or expected["table_abi"] != 1 or expected["mips_calls"] not in {"sdk", "long"}:
            raise ValueError("build report ABI/call policy is invalid")
    else:
        requested, failed = [], []
    built = {}
    common_keys = ("sdk_ref", "kernel_ref", "source_sha256", "version", "priority_mode", "priority", "table_abi", "mips_calls")
    common = None
    for model, inventory_model in inventory["models"].items():
        folder = discovery / model
        if not folder.exists() and not folder.is_symlink():
            continue
        meta = validate_model_output(folder, {**inventory_model, "model": model}, expected)
        if model in failed:
            raise ValueError(f"{model}: build report says failed but an output remains")
        values = {key: meta.get(key) for key in common_keys}
        if common is None:
            common = values
        elif values != common:
            differing = next(key for key in common_keys if values[key] != common[key])
            raise ValueError(f"mixed model build provenance: {model} differs in {differing}")
        built[model] = meta
    failure_map = run_report.get("failures", {}) if run_report else {}
    for model in failure_map:
        if model not in inventory["models"]:
            raise ValueError(f"build report has unknown failed model: {model}")
    missing = sorted(set(inventory["models"]) - set(built))
    groups = defaultdict(list)
    model_result = {}
    for model, meta in built.items():
        modules = meta["modules"]
        pair = {"ipv4": {"fingerprint": modules["ipv4"]["fingerprint"], "vermagic": modules["ipv4"]["vermagic"]}}
        if meta["ipv6_supported"]:
            pair["ipv6"] = {"supported": True, "fingerprint": modules["ipv6"]["fingerprint"], "vermagic": modules["ipv6"]["vermagic"]}
        else:
            pair["ipv6"] = {"supported": False, "fingerprint": None, "vermagic": None}
        signature = {"arch": meta["arch"], "kernel_release": meta["kernel_release"],
                     "module_cflags": meta["module_cflags"], "modules": pair}
        encoded = json.dumps(signature, sort_keys=True, separators=(",", ":"))
        candidate_id = "candidate-" + hashlib.sha256(encoded.encode()).hexdigest()[:12]
        groups[candidate_id].append(model)
        model_result[model] = {"candidate_id": candidate_id, "status": "experimental",
            "evidence": "matching keenpbr module pair fingerprint; kernel ABI and hardware compatibility still require verification",
            "kernel_config_sha256": meta["kernel_config_sha256"],
            "module_symvers_sha256": meta["module_symvers_sha256"],
            "sdk_config_sha256": meta["sdk_config_sha256"],
            "module_sha256": {key: item["sha256"] for key, item in modules.items()}}
    candidate_groups = []
    for candidate_id, models in sorted(groups.items()):
        sample = built[models[0]]
        modules = sample["modules"]
        candidate_groups.append({"id": candidate_id, "models": sorted(models), "arch": sample["arch"],
            "kernel_release": sample["kernel_release"],
            "ipv4": {"fingerprint": modules["ipv4"]["fingerprint"], "vermagic": modules["ipv4"]["vermagic"]},
            "ipv6": {"supported": sample["ipv6_supported"],
                     "fingerprint": modules["ipv6"]["fingerprint"] if sample["ipv6_supported"] else None,
                     "vermagic": modules["ipv6"]["vermagic"] if sample["ipv6_supported"] else None}})
    provenance = common or {key: expected.get(key) for key in common_keys}
    return {"schema_version": 1, "kind": "candidate-only", "provenance": provenance,
            "coverage": {"inventory_total": len(inventory["models"]), "requested": requested,
                         "built": sorted(built), "missing": missing, "failed": failed},
            "candidate_groups": candidate_groups, "models": model_result}
