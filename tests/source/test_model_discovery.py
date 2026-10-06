"""Focused tests for pinned-model discovery and candidate-only grouping."""
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import model_tools
import kmodlib

spec = importlib.util.spec_from_file_location("build_models", ROOT / "scripts/build-models.py")
build_models = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_models)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ModelDiscoveryTests(unittest.TestCase):
    def test_configure_list_extracts_models_and_rejects_empty_or_duplicate_rows(self):
        self.assertEqual(model_tools.parse_configure_list("KN-1810 board\nother row\nKN-1812 board\n"),
                         ["KN-1810", "KN-1812"])
        with self.assertRaisesRegex(ValueError, "no KN model"):
            model_tools.parse_configure_list("not a model\n")
        with self.assertRaisesRegex(ValueError, "more than once"):
            model_tools.parse_configure_list("KN-1810 one\nKN-1810 two\n")

    def make_sdk_fixture(self, sdk, *, injected=False):
        board = sdk / "target/linux/testboard"
        board.mkdir(parents=True)
        (board / "Makefile").write_text("ARCH:=mipsel\nKERNEL_PATCHVER:=4.9\n")
        model = board / "KN-1810"
        model.mkdir()
        (model / "ndwrt.config").write_text(
            'CONFIG_TARGET_BOARD="testboard"\nCONFIG_ARCH="mipsel"\n'
            'CONFIG_TARGET_ARCH_PACKAGES="KN-1810"\n'
        )
        tracked = {"target/linux/testboard/Makefile", "target/linux/testboard/KN-1810/ndwrt.config"}
        if injected:
            extra = board / "KN-9999"
            extra.mkdir()
            (extra / "ndwrt.config").write_text(
                'CONFIG_TARGET_BOARD="testboard"\nCONFIG_ARCH="mipsel"\n'
                'CONFIG_TARGET_ARCH_PACKAGES="KN-9999"\n'
            )
        return tracked

    def test_inventory_rejects_untracked_model_injected_into_sdk_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            sdk = Path(temp)
            tracked = self.make_sdk_fixture(sdk, injected=True)
            with patch.object(model_tools, "validate_sdk_checkout", return_value=(sdk, {"ref": "a" * 40, "kernel_ref": "b" * 40})), \
                 patch.object(model_tools, "run", side_effect=lambda args, **kwargs: "\n".join(sorted(tracked))):
                with self.assertRaisesRegex(ValueError, "untracked SDK model configs"):
                    model_tools.discover_inventory(sdk)

    def test_inventory_config_rejects_untracked_and_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            sdk = Path(temp)
            tracked = self.make_sdk_fixture(sdk)
            config = sdk / "target/linux/testboard/KN-1810/ndwrt.config"
            model, item, _ = model_tools.parse_inventory_config(sdk, config, tracked)
            self.assertEqual(model, "KN-1810")
            self.assertEqual(item["arch"], "mipsel")
            with self.assertRaisesRegex(ValueError, "untracked or escapes"):
                model_tools.parse_inventory_config(sdk, config, set())
            with self.assertRaisesRegex(ValueError, "unsupported SDK model config path"):
                model_tools.parse_inventory_config(sdk, sdk / "target/linux/testboard/KN-1810/sub/ndwrt.config", tracked)

    def model_output(self, out, model, arch, *, ipv6=True, v4="v4", v6="v6", source=None):
        discovery = Path(out) / "discovery"
        folder = discovery / model
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir(parents=True)
        lock = json.loads((ROOT / "sdk.lock").read_text())
        version = (ROOT / "VERSION").read_text().strip()
        config_bytes = hashlib.sha256((model + " config").encode()).hexdigest()
        config_file = f"target/linux/test/{model}/ndwrt.config"
        modules = {}
        for kind, fingerprint in (("ipv4", v4), ("ipv6", v6)):
            if kind == "ipv6" and not ipv6:
                continue
            name = "iptable_keenpbr.ko" if kind == "ipv4" else "ip6table_keenpbr.ko"
            path = folder / name
            path.write_bytes((model + kind).encode())
            modules[kind] = {
                "file": name, "sha256": digest(path), "size": path.stat().st_size,
                "fingerprint": hashlib.sha256(fingerprint.encode()).hexdigest(),
                "vermagic": "4.9-test SMP", "version": version,
                "undefined_symbols": [], "keenpbr_priority": "-149", "keenpbr_table_abi": "1",
            }
        audit = folder / "audit"
        audit.mkdir()
        (audit / "kernel.config").write_text("CONFIG_IP6_NF_IPTABLES=m\n" if ipv6 else "# CONFIG_IP6_NF_IPTABLES is not set\n")
        (audit / "Module.symvers").write_text("test symvers\n")
        meta = {
            "build_kind": "sdk-model", "model": model, "representative": model, "arch": arch,
            "sdk_config_sha256": config_bytes, "sdk_ref": lock["ref"], "kernel_ref": lock["kernel_ref"],
            "source_sha256": source or kmodlib.source_sha256(ROOT), "version": version,
            "kernel_config_sha256": digest(audit / "kernel.config"), "module_symvers_sha256": digest(audit / "Module.symvers"),
            "priority_mode": "after-mangle", "priority": -149, "table_abi": 1,
            "mips_calls": "long", "module_cflags": "-mlong-calls" if arch in {"mips", "mipsel"} else "",
            "kernel_release": "4.9-test", "ipv6_supported": ipv6,
            "modules": modules,
        }
        if not ipv6:
            meta["ipv6_unavailable_reason"] = "disabled in exact SDK config"
        (folder / "metadata.json").write_text(json.dumps(meta, sort_keys=True) + "\n")
        sums = [f"{item['sha256']}  {item['file']}" for item in modules.values()]
        sums.append(f"{digest(folder / 'metadata.json')}  metadata.json")
        (folder / "SHA256SUMS").write_text("\n".join(sorted(sums)) + "\n")
        return meta

    def prepare_discovery(self, out, models):
        discovery = Path(out) / "discovery"
        discovery.mkdir(parents=True)
        lock = json.loads((ROOT / "sdk.lock").read_text())
        inventory_models = {}
        for model, arch, *_ in models:
            inventory_models[model] = {"board": "test", "arch": arch, "kernel_patchver": "4.9",
                "config": f"target/linux/test/{model}/ndwrt.config",
                "config_sha256": hashlib.sha256((model + " config").encode()).hexdigest()}
        (discovery / "inventory.json").write_text(json.dumps({"schema_version": 1, "sdk_ref": lock["ref"],
            "kernel_ref": lock["kernel_ref"], "models": inventory_models}))
        (discovery / "build-report.json").write_text(json.dumps({
            "sdk_ref": lock["ref"], "kernel_ref": lock["kernel_ref"],
            "requested": sorted(inventory_models), "failures": {}, "priority_mode": "after-mangle",
            "priority": -149, "table_abi": 1, "mips_calls": "long"}))

    def candidate(self, out):
        with patch.object(model_tools, "_module_audit"):
            return model_tools.candidate_report(out)

    def rewrite_metadata_hash(self, folder):
        sums = folder / "SHA256SUMS"
        rows = []
        for line in sums.read_text().splitlines():
            name = line.split("  ", 1)[1]
            rows.append(f"{digest(folder / name)}  {name}" if name == "metadata.json" else line)
        sums.write_text("\n".join(sorted(rows)) + "\n")

    def test_candidate_requires_matching_ipv4_ipv6_pair_and_separates_flags(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "out"
            definitions = [("KN-1810", "mipsel", True, "same4", "same6"),
                           ("KN-1812", "aarch64", True, "same4", "same6"),
                           ("KN-3811", "aarch64", True, "same4", "different6"),
                           ("KN-1212", "mipsel", False, "same4", "unused")]
            self.prepare_discovery(out, definitions)
            for model, arch, ipv6, v4, v6 in definitions:
                self.model_output(out, model, arch, ipv6=ipv6, v4=v4, v6=v6)
            report = self.candidate(out)
            ids = {model: item["candidate_id"] for model, item in report["models"].items()}
            self.assertNotEqual(ids["KN-1810"], ids["KN-1812"], "architecture and effective MIPS flags differ")
            self.assertNotEqual(ids["KN-1812"], ids["KN-3811"], "IPv6 fingerprint is part of the pair")
            self.assertNotEqual(ids["KN-1810"], ids["KN-1212"], "IPv6 unavailable differs from an incomplete/available pair")
            self.assertTrue(all(item["status"] == "experimental" for item in report["models"].values()))

    def test_candidate_rejects_incomplete_stale_mixed_source_and_policy_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "out"
            definitions = [("KN-1810", "mipsel", True, "v4", "v6")]
            self.prepare_discovery(out, definitions)
            meta = self.model_output(out, "KN-1810", "mipsel")
            folder = out / "discovery/KN-1810"
            del meta["modules"]["ipv6"]
            (folder / "metadata.json").write_text(json.dumps(meta))
            self.rewrite_metadata_hash(folder)
            with self.assertRaisesRegex(ValueError, "incomplete module pair"):
                self.candidate(out)

            meta = self.model_output(out, "KN-1810", "mipsel")
            sums = folder / "SHA256SUMS"
            sums.write_text(sums.read_text().replace("  metadata.json", "  old-metadata.json"))
            with self.assertRaisesRegex(ValueError, "stale metadata checksum"):
                self.candidate(out)

            meta = self.model_output(out, "KN-1810", "mipsel", source="f" * 64)
            with self.assertRaisesRegex(ValueError, "source/version differs"):
                self.candidate(out)

            meta = self.model_output(out, "KN-1810", "mipsel")
            meta["priority"] = -300
            (folder / "metadata.json").write_text(json.dumps(meta))
            self.rewrite_metadata_hash(folder)
            with self.assertRaisesRegex(ValueError, "invalid build policy metadata"):
                self.candidate(out)

            meta = self.model_output(out, "KN-1810", "mipsel")
            meta["mips_calls"] = "sdk"
            meta["module_cflags"] = ""
            (folder / "metadata.json").write_text(json.dumps(meta))
            self.rewrite_metadata_hash(folder)
            with self.assertRaisesRegex(ValueError, "differs for mips_calls"):
                self.candidate(out)

    def test_resume_rebuilds_output_with_missing_checksum_and_uses_exact_model_route(self):
        with tempfile.TemporaryDirectory() as temp:
            out, sdk = Path(temp) / "out", Path(temp) / "sdk"
            item = {"board": "test", "arch": "mipsel", "kernel_patchver": "4.9",
                    "config": "target/linux/test/KN-1810/ndwrt.config",
                    "config_sha256": hashlib.sha256(b"KN-1810 config").hexdigest()}
            lock = json.loads((ROOT / "sdk.lock").read_text())
            inventory = {"schema_version": 1, "sdk_ref": lock["ref"], "kernel_ref": lock["kernel_ref"],
                         "models": {"KN-1810": item}}
            self.model_output(out, "KN-1810", "mipsel")
            (out / "discovery/KN-1810/SHA256SUMS").unlink()
            calls = []

            def rebuild(args, **kwargs):
                calls.append(args)
                self.model_output(out, "KN-1810", "mipsel")
                return SimpleNamespace(returncode=0)

            with patch.object(build_models, "discover_inventory", return_value=inventory), \
                 patch.object(model_tools, "_module_audit"), \
                 patch.object(build_models.subprocess, "run", side_effect=rebuild):
                report = build_models.run_sweep(sdk, out, ["KN-1810"], True, "after-mangle", "long")

            self.assertEqual(calls, [[str(ROOT / "scripts/build.sh"), "--sdk-model", "KN-1810"]])
            self.assertEqual(report["succeeded"], ["KN-1810"])
            self.assertEqual(report["skipped"], [])
            self.assertTrue((out / "discovery/KN-1810/SHA256SUMS").is_file())

    def test_mips_abi_header_changes_fingerprint_while_debug_and_build_id_do_not(self):
        def fingerprint(flags, debug="cafebabe", build_id="a1b2c3d4"):
            sections = f"""  [ 1] .text PROGBITS 00000000 000040 00000003 00 AX 0 0 1
  [ 2] .debug_info PROGBITS 00000000 000043 00000004 00     0 0 1
  [ 3] .note.gnu.build-id NOTE 00000000 000047 00000004 00 A 0 0 1
"""
            header = f"""  Class:                             ELF32
  Data:                              2's complement, little endian
  Type:                              REL (Relocatable file)
  Machine:                           MIPS R3000
  Flags:                             {flags}
"""
            def fake_run(args, **kwargs):
                if args[1:] and args[1] == "-h": return header
                if "-SW" in args: return sections
                if "-sW" in args: return ""
                if "-rW" in args: return ""
                if "-x" in args:
                    section = args[args.index("-x") + 1]
                    if section == ".text": return "Hex dump of section '.text':\n  0x00000000 010203\n"
                    if section == ".debug_info": return f"Hex dump of section '.debug_info':\n  0x00000000 {debug}\n"
                    if section == ".note.gnu.build-id": return f"Hex dump of section '.note.gnu.build-id':\n  0x00000000 {build_id}\n"
                    return ""
                if args[1:3] == ["-u", args[-1]]: return "                 U kernel_symbol\n"
                if "-F" in args: return {"vermagic": "4.9-test", "version": "0.1", "license": "GPL", "description": "table", "depends": "", "keenpbr_priority": "-149", "keenpbr_table_abi": "1"}[args[args.index("-F") + 1]]
                return ""
            with tempfile.NamedTemporaryFile() as module, patch.object(kmodlib, "tool", side_effect=lambda name, required=True: name), patch.object(kmodlib, "run", side_effect=fake_run):
                return kmodlib.fingerprint(module.name)
        baseline = fingerprint("noreorder, o32, mips32r2")
        self.assertEqual(baseline, fingerprint("noreorder, o32, mips32r2", debug="11223344", build_id="99887766"))
        self.assertNotEqual(baseline, fingerprint("noreorder, o32, mips32r1"))


if __name__ == "__main__":
    unittest.main()
