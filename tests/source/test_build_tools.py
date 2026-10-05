import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import kmodlib

spec = importlib.util.spec_from_file_location("manifest", ROOT / "scripts/generate-manifest.py")
manifest_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest_module)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class BuildToolTests(unittest.TestCase):
    def test_model_routing_uses_declared_group_and_rejects_unknown(self):
        self.assertEqual(kmodlib.resolve_target("KN-1011")[0], "mt7621-highmem")
        with self.assertRaises(ValueError):
            kmodlib.resolve_target("KN-9999")

    def fingerprint_fixture(self, *, tail="cc", bss="00000004", debug="cafebabe", reloc="target"):
        section_table = f"""  [ 1] .text PROGBITS 00000000 000040 00000003 00 AX 0 0 1
  [ 2] .bss NOBITS 00000000 000050 {bss} 00 WA 0 0 4
  [ 3] .debug_info PROGBITS 00000000 000050 00000004 00 0 0 0 1
  [ 4] .rela.text RELA 00000000 000060 00000018 0 0 1 8
  [ 5] .rela.debug_info RELA 00000000 000078 00000018 0 0 3 8"""
        header = "  Class: ELF64\n  Data: 2's complement, little endian\n  Type: REL (Relocatable file)\n  Machine: Advanced Micro Devices X86-64\n  Flags: 0x0\n"
        relocations = f"""Relocation section '.rela.text' at offset 0x60 contains 1 entry:
0000000000000001  0000000100000001 R_X86_64_64 0000000000000000 {reloc} + 0
Relocation section '.rela.debug_info' at offset 0x78 contains 1 entry:
0000000000000000  0000000300000001 R_X86_64_64 0000000000000000 {debug} + 0"""
        def fake_run(args, **kwargs):
            if "-h" in args: return header
            if "-SW" in args: return section_table
            if "-sW" in args: return "   1: 0000000000000000 0 FUNC GLOBAL DEFAULT 1 public_symbol\n"
            if "-rW" in args: return relocations
            if "-x" in args:
                name = args[args.index("-x") + 1]
                return f"Hex dump of section '{name}':\n  0x00000000 aabb{tail}\n" if name == ".text" else ""
            if args[0] == "nm": return "                 U kernel_symbol\n"
            if "-F" in args: return {"vermagic": "4.9-test SMP", "version": "0.1.0", "license": "GPL", "description": "table", "depends": "", "keenpbr_priority": "-149", "keenpbr_table_abi": "1"}[args[args.index("-F") + 1]]
            return ""
        return fake_run

    def fingerprint(self, **options):
        with tempfile.NamedTemporaryFile() as module, patch.object(kmodlib, "tool", side_effect=lambda name, required=True: name), patch.object(kmodlib, "run", side_effect=self.fingerprint_fixture(**options)):
            return kmodlib.fingerprint(module.name)

    def test_fingerprint_ignores_debug_but_sees_tail_bss_and_relocations(self):
        original = self.fingerprint()
        self.assertEqual(original, self.fingerprint(debug="different_debug_symbol"))
        self.assertNotEqual(original, self.fingerprint(tail="cd"))
        self.assertNotEqual(original, self.fingerprint(bss="00000008"))
        self.assertNotEqual(original, self.fingerprint(reloc="another_target"))

    def make_group(self, out, group, representative, version="0.1.0"):
        folder = Path(out) / group
        folder.mkdir(parents=True)
        module = folder / "iptable_keenpbr.ko"
        module.write_bytes((group + " module").encode())
        lock = json.loads((ROOT / "sdk.lock").read_text())
        metadata = {
            "group": group, "representative": representative, "arch": "mipsel", "kernel": "4.9-ndm", "kernel_release": "4.9-test",
            "kernel_ref": lock["kernel_ref"], "sdk_ref": lock["ref"], "version": version,
            "priority_mode": "after-mangle", "priority": -149, "table_abi": 1,
            "source_sha256": kmodlib.source_sha256(ROOT),
            "modules": {"ipv4": {"file": module.name, "sha256": digest(module), "size": module.stat().st_size,
                "vermagic": "4.9-test SMP", "version": version, "undefined_symbols": ["kernel_symbol"], "fingerprint": "c" * 64,
                "keenpbr_priority": "-149", "keenpbr_table_abi": "1"}},
            "ipv6_unavailable_reason": "test config disables IPv6",
        }
        evidence = folder / "audit"
        evidence.mkdir()
        (evidence / "kernel.config").write_text("CONFIG_TEST=y\n")
        (evidence / "Module.symvers").write_text("0x0 symbol vmlinux EXPORT_SYMBOL\n")
        metadata["kernel_config_sha256"] = digest(evidence / "kernel.config")
        metadata["module_symvers_sha256"] = digest(evidence / "Module.symvers")
        (folder / "metadata.json").write_text(json.dumps(metadata))
        (folder / "SHA256SUMS").write_text(f"{digest(module)}  {module.name}\n{digest(folder / 'metadata.json')}  metadata.json\n")
        return metadata

    def release(self, out, release, matrix):
        with patch.object(manifest_module, "matrix", return_value=matrix), \
             patch.object(manifest_module, "check_arch"), \
             patch.object(manifest_module, "fingerprint", return_value="c" * 64), \
             patch.object(manifest_module, "tool", return_value="modinfo"), \
             patch.object(manifest_module, "run", side_effect=lambda args, **kwargs: (
                 "4.9-test SMP" if "vermagic" in args else "-149" if "keenpbr_priority" in args
                 else "1" if "keenpbr_table_abi" in args else ("0.2.0" if "group2" in args[-1] else "0.1.0"))):
            return manifest_module.build_release(Path(out), Path(release), False)

    def test_manifest_rejects_mixed_provenance_without_replacing_previous_release(self):
        group_map = {"group1": {"representative": "KN-1001", "arch": "mipsel", "ipv6": False},
                     "group2": {"representative": "KN-1002", "arch": "mipsel", "ipv6": False}}
        model_map = {model: {"group": group, "status": "experimental", "evidence": "test"}
                     for group, cfg in group_map.items() for model in (cfg["representative"],)}
        with tempfile.TemporaryDirectory() as temp:
            out, release = Path(temp) / "out", Path(temp) / "release"
            self.make_group(out, "group1", "KN-1001")
            self.make_group(out, "group2", "KN-1002", version="0.2.0")
            release.mkdir(); (release / "keep").write_text("old")
            with self.assertRaisesRegex(ValueError, "mixed provenance"):
                self.release(out, release, (group_map, model_map))
            self.assertEqual((release / "keep").read_text(), "old")

    def test_manifest_hashes_success_and_rejects_stale_module_hash(self):
        group_map = {"group1": {"representative": "KN-1001", "arch": "mipsel", "ipv6": False}}
        model_map = {"KN-1001": {"group": "group1", "status": "experimental", "evidence": "test"}}
        with tempfile.TemporaryDirectory() as temp:
            out, release = Path(temp) / "out", Path(temp) / "release"
            self.make_group(out, "group1", "KN-1001")
            self.release(out, release, (group_map, model_map))
            manifest = release / "manifest.json"
            self.assertEqual(json.loads(manifest.read_text())["groups"]["group1"]["modules"]["ipv4"]["file"], "iptable_keenpbr-group1.ko")
            rows = (release / "SHA256SUMS").read_text().splitlines()
            self.assertEqual(rows[0].split()[0], digest(release / rows[0].split()[1]))
            self.release(out, out / "release", (group_map, model_map))
            module = out / "group1/iptable_keenpbr.ko"
            module.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "stale/mismatched module checksum"):
                self.release(out, Path(temp) / "release2", (group_map, model_map))

    def test_manifest_rejects_release_destination_inside_build_inputs(self):
        group_map = {"group1": {"representative": "KN-1001", "arch": "mipsel", "ipv6": False}}
        model_map = {"KN-1001": {"group": "group1", "status": "experimental", "evidence": "test"}}
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "out"
            self.make_group(out, "group1", "KN-1001")
            with self.assertRaisesRegex(ValueError, "overlaps build inputs"):
                self.release(out, out / "group1/release", (group_map, model_map))


if __name__ == "__main__":
    unittest.main()
