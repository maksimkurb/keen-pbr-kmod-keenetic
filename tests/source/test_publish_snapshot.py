"""Publication must preserve existing releases and clean up only its own drafts."""
import hashlib
import io
import importlib.util
import json
import shutil
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
from snapshotlib import BUILD_PROVENANCE_FIELDS, MODULE_AUDIT_FIELDS, manifest_snapshot_digest, snapshot_digest
spec = importlib.util.spec_from_file_location("publish_snapshot", ROOT / "scripts/publish-snapshot.py")
publish_snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish_snapshot)


class PublishSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        matrix = b"{}\n"
        module = b"module fixture"
        module_sha = hashlib.sha256(module).hexdigest()
        record = {"sdk_input_key": "b" * 64, "configuration": {"model": "KN-1810"},
                  "descriptor_sha256": "c" * 64, "module_source_sha256": "d" * 64,
                  "build_inputs_sha256": "e" * 64, "source_sha256": "f" * 64,
                  "environment": {"id": "pinned"}, "version": "0.1.0", "sdk_ref": "1" * 40,
                  "kernel": "4.9-ndm", "arch": "mipsel", "kernel_ref": "2" * 40,
                  "kernel_release": "4.9-test", "contract": {"version": "0.1.0"},
                  "mips_calls": "long", "module_cflags": "-mlong-calls",
                  "kernel_source_version": "4.9.337", "kernel_source_evidence": "git-head-equals-resolved-sdk-source-tag",
                  "toolchain_archive_sha256": {"tc": "3" * 64}, "kernel_archive_sha256": "4" * 64,
                  "kernel_config_sha256": "5" * 64, "module_symvers_sha256": "6" * 64,
                  "provider_export_evidence": {"ipv4": {"supported": True}},
                  "ipv6_supported": False, "ipv6_unavailable_reason": "disabled", "modules": {}}
        module_name = f"iptable_keenpbr-{module_sha}.ko"
        record["modules"]["ipv4"] = {"file": "modules/iptable_keenpbr.ko", "asset_file": module_name,
            "sha256": module_sha, "size": len(module), "vermagic": "4.9-test SMP", "version": "0.1.0",
            "undefined_symbols": [], "elf": {}, "keenpbr_priority": "-149", "keenpbr_table_abi": "1",
            "fingerprint": "7" * 64}
        provenance = {field: record[field] for field in BUILD_PROVENANCE_FIELDS}
        provenance["modules"] = {"ipv4": {"asset_file": module_name,
            **{field: record["modules"]["ipv4"][field] for field in MODULE_AUDIT_FIELDS}}}
        manifest = {"schema_version": 2, "version": "0.1.0",
                    "matrix_sha256": hashlib.sha256(matrix).hexdigest(),
                    "builds": {"a" * 64: record}, "releases": {}}
        manifest["snapshot"] = snapshot_digest(manifest["matrix_sha256"], manifest["builds"],
                                               [("ipv4", module_sha)], {"a" * 64: provenance})
        self.snapshot = self.root / ("modules-0.1.0-" + manifest["snapshot"])
        self.snapshot.mkdir()
        (self.snapshot / "kernel-matrix.json").write_bytes(matrix)
        (self.snapshot / module_name).write_bytes(module)
        (self.snapshot / "manifest.json").write_text(json.dumps(manifest) + "\n")
        names = ("kernel-matrix.json", "manifest.json", module_name)
        (self.snapshot / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256((self.snapshot / name).read_bytes()).hexdigest()}  {name}\n"
            for name in names))
        self.notes = self.root / "notes.md"
        self.notes.write_text("validated release\n")
        self.argv = ["publish-snapshot.py", "--snapshot", str(self.snapshot), "--notes", str(self.notes),
                     "--repository", "example/keen-pbr-kmod", "--target-commit", "b" * 40, "--token", "test"]

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def rewrite_sums(folder):
        names = sorted(path.name for path in folder.iterdir() if path.is_file() and path.name != "SHA256SUMS")
        (folder / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256((folder / name).read_bytes()).hexdigest()}  {name}\n" for name in names))

    def test_snapshot_rejects_matrix_provenance_and_module_tampering(self):
        publish_snapshot.verify_snapshot(self.snapshot)
        for target in ("matrix", "build", "module"):
            candidate = self.root / ("tampered-" + target)
            shutil.copytree(self.snapshot, candidate)
            manifest_path = candidate / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            if target == "matrix":
                (candidate / "kernel-matrix.json").write_text("{\"changed\":true}\n")
            elif target == "build":
                manifest["builds"]["a" * 64]["kernel_archive_sha256"] = "8" * 64
                manifest_path.write_text(json.dumps(manifest) + "\n")
            else:
                module_name = manifest["builds"]["a" * 64]["modules"]["ipv4"]["asset_file"]
                (candidate / module_name).write_bytes(b"changed module bytes")
            self.rewrite_sums(candidate)
            with self.subTest(target=target), self.assertRaises(ValueError):
                publish_snapshot.verify_snapshot(candidate)

    def test_existing_published_release_with_bad_asset_is_never_deleted_or_mutated(self):
        calls = []
        names = {path.name for path in self.snapshot.iterdir() if path.is_file()}

        def api(url, token, method="GET", data=None, content_type="application/vnd.github+json", accept="application/vnd.github+json"):
            calls.append((method, url))
            if url.endswith("/releases/tags/modules-v0.1.0-" + json.loads((self.snapshot / "manifest.json").read_text())["snapshot"]):
                return 200, json.dumps({"id": 17, "draft": False, "assets_url": "https://api.invalid/assets"}).encode()
            if url.startswith("https://api.invalid/assets?"):
                assets = [{"name": name, "url": "https://api.invalid/download/" + name,
                           "digest": "sha256:" + "0" * 64} for name in sorted(names)]
                return 200, json.dumps(assets).encode()
            raise AssertionError(url)

        with patch.object(publish_snapshot, "api", side_effect=api), patch("sys.argv", self.argv):
            self.assertEqual(publish_snapshot.main(), 1)
        self.assertFalse(any(method in {"PATCH", "DELETE", "POST"} for method, _ in calls))

    def test_failed_upload_only_deletes_the_new_draft(self):
        calls = []
        missing_release = []
        created = {"id": 19, "draft": True, "assets_url": "https://api.invalid/assets",
                   "upload_url": "https://api.invalid/upload{?name}", "assets": []}

        def api(url, token, method="GET", data=None, content_type="application/vnd.github+json", accept="application/vnd.github+json"):
            calls.append((method, url))
            if url.endswith("/releases/tags/modules-v0.1.0-" + self.snapshot.name.rsplit("-", 1)[-1]):
                error = urllib.error.HTTPError(url, 404, "missing", {}, io.BytesIO())
                missing_release.append(error)
                raise error
            if url.endswith("/releases") and method == "POST":
                return 201, json.dumps(created).encode()
            if url.startswith("https://api.invalid/assets?"):
                return 200, b"[]"
            if url.startswith("https://api.invalid/upload") and method == "POST":
                raise urllib.error.URLError("simulated upload failure")
            if url.endswith("/releases/19") and method == "GET":
                return 200, json.dumps(created).encode()
            if url.endswith("/releases/19") and method == "DELETE":
                return 204, b""
            raise AssertionError((method, url))

        with patch.object(publish_snapshot, "api", side_effect=api), patch("sys.argv", self.argv):
            self.assertEqual(publish_snapshot.main(), 1)
        for error in missing_release:
            error.close()
        self.assertIn(("DELETE", "https://api.github.com/repos/example/keen-pbr-kmod/releases/19"), calls)


if __name__ == "__main__":
    unittest.main()
