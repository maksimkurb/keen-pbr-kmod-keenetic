"""Planner shard bounds and release artifact trust-boundary checks."""
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

plan_spec = importlib.util.spec_from_file_location("plan_builds", ROOT / "scripts/plan-builds.py")
plan_builds = importlib.util.module_from_spec(plan_spec)
plan_spec.loader.exec_module(plan_builds)

spec = importlib.util.spec_from_file_location("assemble_release", ROOT / "scripts/assemble-release.py")
assemble_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assemble_release)

build_spec = importlib.util.spec_from_file_location("build_snapshot", ROOT / "scripts/build-snapshot.py")
build_snapshot = importlib.util.module_from_spec(build_spec)
build_spec.loader.exec_module(build_snapshot)


class SnapshotReleaseTests(unittest.TestCase):
    def test_download_cache_survives_sdk_cleanup_without_sharing_build_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sdk, cache = root / "sdk", root / "downloads"
            sdk.mkdir()
            build_snapshot.link_download_cache(sdk, cache)
            (sdk / "dl/kernel.tar.zst").write_bytes(b"downloaded archive")
            (sdk / ".config").write_text("first model")
            shutil.rmtree(sdk)
            self.assertEqual((cache / "kernel.tar.zst").read_bytes(), b"downloaded archive")
            sdk.mkdir()
            build_snapshot.link_download_cache(sdk, cache)
            self.assertFalse((sdk / ".config").exists())
            self.assertEqual((sdk / "dl/kernel.tar.zst").read_bytes(), b"downloaded archive")
            unsafe = root / "unsafe"
            unsafe.symlink_to(cache, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "regular directory"):
                build_snapshot.link_download_cache(sdk, unsafe)

    def test_plan_deduplicates_config_and_bounds_shards(self):
        key = "a" * 64
        matrix = {"schema_version": 1, "repository": "https://example.invalid/sdk.git",
                  "configurations": {key: {"sdk_input_key": key, "sdk_ref": "b" * 40,
                                            "sdk_tag": "5.0.0", "model": "KN-1810",
                                            "arch": "mipsel", "config": "target/linux/b/KN-1810/ndwrt.config"}},
                  "sdks": {tag: {"models": {"KN-1810": {"configuration": key, "status": "supported"},
                                              "KAP-630": {"status": "unsupported", "reason": "unsupported model family"}}}
                           for tag in ("5.0.0-0", "5.0.0-1")}}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.json"
            matrix_path.write_text(json.dumps(matrix))
            with patch.object(plan_builds, "source_sha256", return_value="c" * 64), \
                 patch("sdk_matrix.build_inputs_sha256", return_value="d" * 64), \
                 patch("sdk_matrix.build_key", return_value="e" * 64):
                result = plan_builds.plan(matrix_path, root / "descriptors", max_shards=256)
            self.assertEqual(result["build_keys"], ["e" * 64])
            self.assertEqual(len(result["shards"]), 1)
            self.assertEqual(result["shards"][0]["build_keys"], ["e" * 64])
            self.assertTrue((root / "descriptors" / f"{'e' * 64}.json").is_file())

    def test_assembler_rejects_a_module_whose_bytes_disagree_with_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / ("a" * 64)
            (folder / "modules").mkdir(parents=True)
            path = folder / "modules/iptable_keenpbr.ko"
            path.write_bytes(b"not an ELF module")
            descriptor = {"configuration": {"arch": "mipsel"},
                          "contract": {"version": "0.1.0", "priority": -149, "table_abi": 1}}
            metadata = {"kernel_release": "4.9-test"}
            recorded = {"file": "modules/iptable_keenpbr.ko", "sha256": "0" * 64}
            with self.assertRaisesRegex(ValueError, "SHA256 does not match"):
                assemble_release.verify_module(folder, "ipv4", recorded, descriptor, metadata)

    def test_snapshot_identity_changes_when_observed_archive_provenance_changes(self):
        common = ("1" * 64, ["a" * 64], [("ipv4", "b" * 64)])
        first = {"a" * 64: {"kernel_archive_sha256": "c" * 64}}
        second = {"a" * 64: {"kernel_archive_sha256": "d" * 64}}
        self.assertNotEqual(assemble_release.snapshot_digest(*common, first),
                            assemble_release.snapshot_digest(*common, second))

    def test_assembler_rejects_unsafe_or_missing_build_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            descriptor = {"sdk_input_key": "a" * 64, "configuration": {}, "contract": {},
                          "environment": {}}
            with self.assertRaisesRegex(ValueError, "unsafe build key"):
                assemble_release.verify_build("../escape", descriptor, Path(temp), "b" * 64, "c" * 64, "0.1.0")
            with self.assertRaisesRegex(ValueError, "output directory missing"):
                assemble_release.verify_build("d" * 64, descriptor, Path(temp), "b" * 64, "c" * 64, "0.1.0")

    def test_reuse_requires_trusted_release_provenance_and_allows_tag_only_change(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            index_dir = root / "index"
            index_dir.mkdir()
            key, sdk_key, source, inputs = "a" * 64, "b" * 64, "c" * 64, "d" * 64
            old_config = {"sdk_input_key": sdk_key, "sdk_ref": "e" * 40, "sdk_tag": "5.0.0-0",
                          "model": "KN-1810", "arch": "mipsel", "kernel_ref": "f" * 40}
            current_config = {**old_config, "sdk_ref": "1" * 40, "sdk_tag": "5.0.0-1"}
            module_name = "iptable_keenpbr-" + "9" * 64 + ".ko"
            record = {"sdk_input_key": sdk_key, "configuration": old_config,
                      "descriptor_sha256": "2" * 64, "module_source_sha256": source,
                      "build_inputs_sha256": inputs, "source_sha256": source,
                      "environment": {"id": "pinned"}, "version": "0.1.0",
                      "sdk_ref": old_config["sdk_ref"], "kernel": "4.9-ndm", "arch": "mipsel",
                      "kernel_ref": old_config["kernel_ref"], "kernel_release": "4.9-test",
                      "contract": {"version": "0.1.0", "table_abi": 1, "priority_mode": "after-mangle",
                                   "priority": -149, "mips_calls": "long"},
                      "mips_calls": "long", "module_cflags": "-mlong-calls",
                      "kernel_source_version": "4.9.337", "kernel_source_evidence": "git-head-equals-resolved-sdk-source-tag",
                      "toolchain_archive_sha256": {"tc.tar": "3" * 64},
                      "kernel_archive_sha256": "4" * 64, "kernel_config_sha256": "5" * 64,
                      "module_symvers_sha256": "6" * 64,
                      "provider_export_evidence": {"ipv4": {"supported": True, "evidence": "Module.symvers"}},
                      "ipv6_supported": False,
                      "ipv6_unavailable_reason": "not enabled", "modules": {"ipv4": {
                          "file": "modules/iptable_keenpbr.ko", "asset_file": module_name,
                          "sha256": "9" * 64, "size": 10, "vermagic": "4.9-test SMP",
                          "version": "0.1.0", "undefined_symbols": [], "elf": {},
                          "keenpbr_priority": "-149", "keenpbr_table_abi": "1", "fingerprint": "7" * 64}}}
            manifest = {"schema_version": 2, "version": "0.1.0", "snapshot": "8" * 64,
                        "matrix_sha256": "", "builds": {key: record},
                        "releases": {"5.0.0-0": {"KN-1810": {"status": "experimental", "build_key": key}}}}
            matrix = {"sdks": {"5.0.0-0": {"models": {"KN-1810": {
                "status": "supported", "configuration": sdk_key}}}}}
            matrix_bytes = (json.dumps(matrix, sort_keys=True) + "\n").encode()
            manifest["matrix_sha256"] = hashlib.sha256(matrix_bytes).hexdigest()
            (index_dir / "kernel-matrix.json").write_bytes(matrix_bytes)
            (index_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
            (index_dir / "SHA256SUMS").write_text(
                f"{hashlib.sha256((index_dir / 'kernel-matrix.json').read_bytes()).hexdigest()}  kernel-matrix.json\n"
                f"{hashlib.sha256((index_dir / 'manifest.json').read_bytes()).hexdigest()}  manifest.json\n"
                f"{'9' * 64}  {module_name}\n")
            (index_dir / "index.json").write_text(json.dumps({"schema_version": 1, "repository": "example/keen-pbr-kmod",
                "tag": f"modules-v0.1.0-{manifest['snapshot']}", "assets": {module_name: {"url": "asset"}}}))
            metadata = {**record, "build_key": key, "reused_from_snapshot": {
                "tag": f"modules-v0.1.0-{manifest['snapshot']}", "snapshot": manifest["snapshot"],
                "manifest_sha256": hashlib.sha256((index_dir / "manifest.json").read_bytes()).hexdigest()}}
            descriptor = {"sdk_input_key": sdk_key, "configuration": current_config}
            trusted = assemble_release.trusted_reuse_record(index_dir, key, metadata, descriptor, "example/keen-pbr-kmod")
            self.assertEqual(trusted["configuration"]["sdk_tag"], "5.0.0-0")
            metadata["reused_from_snapshot"]["manifest_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "reuse marker"):
                assemble_release.trusted_reuse_record(index_dir, key, metadata, descriptor, "example/keen-pbr-kmod")

    def test_assembly_covers_exact_tags_and_deduplicates_identical_family_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path, plan_path = root / "kernel-matrix.json", root / "plan.json"
            builds_dir, output_dir = root / "builds", root / "snapshots"
            key, config_key = "a" * 64, "b" * 64
            source, inputs = "c" * 64, "d" * 64
            version = (ROOT / "VERSION").read_text().strip()
            config = {"sdk_input_key": config_key, "sdk_ref": "e" * 40, "sdk_tag": "5.0.0-0",
                      "kernel_repository": "https://example.invalid/kernel.git", "kernel_ref": "f" * 40,
                      "kernel_source_version": "4.9.337-1", "kernel_patchver": "4.9", "model": "KN-1810",
                      "board": "testboard", "arch": "mipsel", "config": "target/linux/test/KN-1810/ndwrt.config",
                      "config_sha256": "1" * 64, "input_identity": {"sdk_build_tree_sha256": "2" * 64}}
            matrix = {"schema_version": 1, "repository": "https://example.invalid/sdk.git",
                      "configurations": {config_key: config}, "sdks": {
                          tag: {"series": "5.0", "ref": config["sdk_ref"], "kernel_ref": config["kernel_ref"],
                                "kernel_source_version": config["kernel_source_version"], "models": {
                                    "KN-1810": {"configuration": config_key, "status": "supported"},
                                    "KAP-630": {"status": "unsupported", "reason": "unsupported model family"}}}
                          for tag in ("5.0.0-0", "5.0.0-1")}}
            matrix_bytes = (json.dumps(matrix, sort_keys=True) + "\n").encode()
            matrix_path.write_bytes(matrix_bytes)
            contract = {"version": version, "table_abi": 1, "priority_mode": "after-mangle",
                        "priority": -149, "mips_calls": "long"}
            environment = {"id": "test", "sdk_path": "/build/sdk"}
            descriptor = {"schema_version": 1, "configuration": {"sdk_input_key": config_key, **config},
                          "sdk_input_key": config_key, "build_key": key, "contract": contract,
                          "module_source_sha256": source, "build_inputs_sha256": inputs, "environment": environment}
            descriptor_sha = __import__("hashlib").sha256(
                (json.dumps(descriptor, indent=2, sort_keys=True) + "\n").encode()).hexdigest()
            plan_path.write_text(json.dumps({"schema_version": 1,
                "matrix_sha256": __import__("hashlib").sha256(matrix_bytes).hexdigest(),
                "source_sha256": source, "build_inputs_sha256": inputs, "build_keys": [key],
                "descriptors": {key: descriptor}}))

            build = builds_dir / key
            module_dir, audit_dir = build / "modules", build / "audit"
            module_dir.mkdir(parents=True)
            audit_dir.mkdir()
            payload = b"test module bytes"
            module_path = module_dir / "iptable_keenpbr.ko"
            module_path.write_bytes(payload)
            digest = __import__("hashlib").sha256(payload).hexdigest()
            kernel_config, symvers = b"CONFIG_TEST=y\n", b"symvers\n"
            (audit_dir / "kernel.config").write_bytes(kernel_config)
            (audit_dir / "Module.symvers").write_bytes(symvers)
            details = {"file": "modules/iptable_keenpbr.ko", "sha256": digest, "size": len(payload),
                       "vermagic": "4.9-test SMP", "version": version, "undefined_symbols": [],
                       "keenpbr_priority": "-149", "keenpbr_table_abi": "1",
                       "elf": {"Class": "ELF32", "Data": "2's complement, little endian", "Machine": "MIPS"},
                       "fingerprint": "7" * 64}
            metadata = {"build_key": key, "sdk_input_key": config_key, "configuration": descriptor["configuration"],
                        "contract": contract, "module_source_sha256": source, "build_inputs_sha256": inputs,
                        "environment": environment, "version": version, "descriptor_sha256": descriptor_sha,
                        "arch": "mipsel", "kernel_ref": config["kernel_ref"],
                        "kernel_source_version": config["kernel_source_version"],
                        "kernel_source_evidence": "git-head-equals-resolved-sdk-source-tag", "source_sha256": source,
                        "sdk_ref": config["sdk_ref"], "kernel": "4.9-ndm", "kernel_release": "4.9-test",
                        "mips_calls": "long", "module_cflags": "-mlong-calls",
                        "kernel_archive_sha256": "9" * 64,
                        "toolchain_archive_sha256": {"toolchain.tar.gz": "8" * 64},
                        "kernel_config_sha256": __import__("hashlib").sha256(kernel_config).hexdigest(),
                        "module_symvers_sha256": __import__("hashlib").sha256(symvers).hexdigest(),
                        "provider_export_evidence": {"ipv4": {"supported": True, "evidence": "Module.symvers"}},
                        "ipv6_supported": False, "ipv6_unavailable_reason": "disabled in test config",
                        "modules": {"ipv4": details}}
            metadata_path = build / "metadata.json"
            metadata_path.write_text(json.dumps(metadata, sort_keys=True) + "\n")
            sums = [f"{__import__('hashlib').sha256(module_path.read_bytes()).hexdigest()}  modules/iptable_keenpbr.ko",
                    f"{__import__('hashlib').sha256(metadata_path.read_bytes()).hexdigest()}  metadata.json"]
            (build / "SHA256SUMS").write_text("\n".join(sums) + "\n")
            elf_details = {field: details[field] for field in
                           ("sha256", "size", "vermagic", "version", "undefined_symbols", "keenpbr_priority", "keenpbr_table_abi", "elf")}
            with patch.object(assemble_release, "source_sha256", return_value=source), \
                 patch.object(assemble_release, "build_inputs_sha256", return_value=inputs), \
                 patch.object(assemble_release, "audit_module", return_value=elf_details), \
                 patch.object(assemble_release, "fingerprint", return_value=details["fingerprint"]), \
                 patch.object(sys, "argv", ["assemble-release.py", "--matrix", str(matrix_path), "--plan", str(plan_path),
                     "--builds-dir", str(builds_dir), "--output-dir", str(output_dir), "--notes-file", str(root / "notes.md"),
                     "--repository", "https://github.com/example/keen-pbr-kmod"]):
                self.assertEqual(assemble_release.main(), 0)

            snapshot = next(output_dir.iterdir())
            manifest = json.loads((snapshot / "manifest.json").read_text())
            self.assertEqual((snapshot / "kernel-matrix.json").read_bytes(), matrix_bytes)
            first = manifest["releases"]["5.0.0-0"]["KN-1810"]
            second = manifest["releases"]["5.0.0-1"]["KN-1810"]
            self.assertEqual(first["status"], "experimental")
            self.assertEqual(first["modules"]["ipv4"]["file"], second["modules"]["ipv4"]["file"])
            self.assertEqual(len(list(snapshot.glob("*.ko"))), 1)
            self.assertEqual(manifest["releases"]["5.0.0-0"]["KAP-630"]["status"], "unsupported")
            for line in (snapshot / "SHA256SUMS").read_text().splitlines():
                digest, name = line.split("  ", 1)
                self.assertEqual(__import__("hashlib").sha256((snapshot / name).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
