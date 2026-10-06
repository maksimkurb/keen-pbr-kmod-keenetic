#!/usr/bin/env python3
"""Serial exact-model SDK sweep with validated resume and coverage reports."""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kmodlib import PRIORITIES, ROOT, source_sha256
from model_tools import atomic_json, discover_inventory, validate_model_output


def atomic_text(path, text):
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"refusing symlink report: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix="." + path.name + ".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
        os.replace(temp, path)
    except Exception:
        Path(temp).unlink(missing_ok=True)
        raise


def report_text(report):
    lines = [f"SDK model sweep: {len(report['succeeded'])} built, {len(report['skipped'])} resumed, {len(report['failures'])} failed",
             f"Inventory: {report['inventory_total']} models; requested: {len(report['requested'])}; missing: {len(report['missing'])}",
             f"SDK={report['sdk_ref']} kernel={report['kernel_ref']} version={report['version']} priority={report['priority']} mips_calls={report['mips_calls']}"]
    for model in report["requested"]:
        item = report["models"][model]
        lines.append(f"{item['state']:4} {model}: {item.get('result', item.get('reason', ''))}")
    if report["missing"]:
        lines.append("Missing coverage: " + " ".join(report["missing"]))
    return "\n".join(lines) + "\n"


def write_reports(discovery, report):
    atomic_json(discovery / "build-report.json", report)
    atomic_text(discovery / "build-report.txt", report_text(report))


def remove_model_output(folder):
    if folder.is_symlink():
        raise ValueError(f"refusing to remove symlink model output: {folder}")
    if folder.exists():
        if not folder.is_dir():
            raise ValueError(f"model output is not a directory: {folder}")
        shutil.rmtree(folder)


def run_sweep(sdk_dir, out_dir, requested, resume, priority_mode, mips_calls):
    out = Path(out_dir).expanduser().resolve()
    discovery = out / "discovery"
    inventory = discover_inventory(sdk_dir)
    atomic_json(discovery / "inventory.json", inventory)
    known = inventory["models"]
    if len(requested) != len(set(requested)):
        raise ValueError("--models contains a duplicate model ID")
    unknown = sorted(set(requested) - set(known))
    if unknown:
        raise ValueError("unknown SDK model IDs: " + ", ".join(unknown))
    if priority_mode not in PRIORITIES:
        raise ValueError(f"invalid priority mode: {priority_mode}")
    if mips_calls not in {"sdk", "long"}:
        raise ValueError("KEENPBR_MIPS_CALLS must be sdk or long")
    version = (ROOT / "VERSION").read_text().strip()
    source = source_sha256(ROOT)
    expected = {"build_kind": "sdk-model", "sdk_ref": inventory["sdk_ref"],
                "kernel_ref": inventory["kernel_ref"], "source_sha256": source,
                "version": version, "priority_mode": priority_mode,
                "priority": PRIORITIES[priority_mode], "table_abi": 1, "mips_calls": mips_calls}
    available = set()
    for model, inventory_model in known.items():
        output = discovery / model
        if not output.exists() or output.is_symlink():
            continue
        flags = "-mlong-calls" if inventory_model["arch"] in {"mips", "mipsel"} and mips_calls == "long" else ""
        try:
            validate_model_output(output, {**inventory_model, "model": model},
                                  {**expected, "model": model, "representative": model,
                                   "arch": inventory_model["arch"], "module_cflags": flags,
                                   "sdk_config_sha256": inventory_model["config_sha256"]})
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
            continue
        available.add(model)
    report_path = discovery / "build-report.json"
    if report_path.is_symlink():
        raise ValueError("build-report.json must not be a symlink")
    report = {"schema_version": 1, **{k: expected[k] for k in ("sdk_ref", "kernel_ref", "source_sha256", "version", "priority_mode", "priority", "table_abi", "mips_calls")},
              "inventory_total": len(known), "requested": requested, "succeeded": [],
              "failures": {}, "skipped": [], "built": sorted(available),
              "missing": sorted(set(known) - available), "models": {}}
    total = len(requested)
    for model in requested:
        report["models"][model] = {"state": "ToDo"}
    write_reports(discovery, report)
    env = os.environ.copy()
    env.update({"SDK_DIR": str(Path(sdk_dir).resolve()), "OUT_DIR": str(out),
                "KEENPBR_PRIORITY_MODE": priority_mode, "KEENPBR_MIPS_CALLS": mips_calls})
    for index, model in enumerate(requested, 1):
        output = discovery / model
        item = {**known[model], "model": model}
        model_expected = {**expected, "model": model, "representative": model,
                          "arch": item["arch"], "sdk_config_sha256": item["config_sha256"]}
        if resume and output.exists():
            try:
                validate_model_output(output, item, model_expected)
            except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
                pass
            else:
                report["skipped"].append(model)
                available.add(model)
                report["built"] = sorted(available)
                report["models"][model] = {"state": "Done", "result": "resumed after checksum/provenance validation"}
                report["missing"] = sorted(set(known) - available)
                write_reports(discovery, report)
                print(f"[{index}/{total}] {model}: resumed (validated)", flush=True)
                continue
        try:
            remove_model_output(output)
            available.discard(model)
        except ValueError as exc:
            report["failures"][model] = {"exit_code": None, "log": None, "reason": str(exc)}
            report["models"][model] = {"state": "ToDo", "reason": str(exc)}
            report["built"] = sorted(available)
            report["missing"] = sorted(set(known) - available)
            write_reports(discovery, report)
            continue
        log_path = discovery / f"{model}.build.log"
        if log_path.is_symlink():
            report["failures"][model] = {"exit_code": None, "log": None, "reason": "refusing symlink build log"}
            report["models"][model] = {"state": "ToDo", "reason": "refusing symlink build log"}
            report["built"] = sorted(available)
            report["missing"] = sorted(set(known) - available)
            write_reports(discovery, report)
            continue
        report["models"][model] = {"state": "WIP", "log": log_path.relative_to(out).as_posix()}
        report["built"] = sorted(available)
        report["missing"] = sorted(set(known) - available)
        write_reports(discovery, report)
        print(f"[{index}/{total}] {model}: building; log={log_path.relative_to(out).as_posix()}", flush=True)
        with log_path.open("w") as log:
            result = subprocess.run([str(ROOT / "scripts/build.sh"), "--sdk-model", model],
                                    cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        reason = None
        if result.returncode == 0:
            try:
                validate_model_output(output, item, model_expected)
            except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
                reason = f"output validation failed: {exc}"
                remove_model_output(output)
        else:
            reason = f"build exited {result.returncode}"
            remove_model_output(output)
        if reason:
            report["failures"][model] = {"exit_code": result.returncode, "log": log_path.relative_to(out).as_posix(), "reason": reason}
            report["models"][model] = {"state": "ToDo", "reason": reason, "log": log_path.relative_to(out).as_posix()}
        else:
            report["succeeded"].append(model)
            available.add(model)
            report["models"][model] = {"state": "Done", "result": "built and validated", "log": log_path.relative_to(out).as_posix()}
        report["built"] = sorted(available)
        report["missing"] = sorted(set(known) - available)
        write_reports(discovery, report)
        if reason:
            print(f"[{index}/{total}] {model}: failed ({reason})", flush=True)
        else:
            print(f"[{index}/{total}] {model}: built and validated", flush=True)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "out")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--all", action="store_true")
    selection.add_argument("--models", nargs="+", metavar="KN-####")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    try:
        inventory = discover_inventory(args.sdk)
        requested = sorted(inventory["models"]) if args.all else args.models
        if args.models and (len(args.models) != len(set(args.models)) or any(model not in inventory["models"] for model in args.models)):
            raise ValueError("--models must contain unique exact model IDs from the pinned SDK inventory")
        mode = os.environ.get("KEENPBR_PRIORITY_MODE", "after-mangle")
        calls = os.environ.get("KEENPBR_MIPS_CALLS", "long")
        report = run_sweep(args.sdk, args.out, requested, args.resume, mode, calls)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"model sweep failed: {exc}", file=sys.stderr)
        return 1
    print(f"Model sweep: {len(report['succeeded'])} built, {len(report['skipped'])} resumed, {len(report['failures'])} failed; missing coverage {len(report['missing'])}/{report['inventory_total']}")
    return int(bool(report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
