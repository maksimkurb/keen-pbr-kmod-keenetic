import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts/select-module.py"
RELEASE = "4.03.C.2.0-1"
MODEL = "KN-1810"
KERNEL_RELEASE = "4.9-ndm-5"


class RuntimeSelectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        payload = b"example module bytes"
        self.digest = hashlib.sha256(payload).hexdigest()
        self.filename = f"iptable_keenpbr-{self.digest}.ko"
        (self.artifacts / self.filename).write_bytes(payload)
        self.manifest = {
            "schema_version": 2,
            "contract": {"table": "keenpbr", "hook": "PREROUTING",
                         "priority": -149, "table_abi": 1},
            "releases": {RELEASE: {MODEL: {
                "status": "compatible", "build_key": "a" * 64,
                "modules": {"ipv4": {"file": self.filename, "sha256": self.digest,
                                      "vermagic": KERNEL_RELEASE + " SMP"}},
            }}},
            "builds": {"a" * 64: {"modules": {
                "ipv4": {"sha256": self.digest, "vermagic": KERNEL_RELEASE + " SMP"},
            }}},
        }
        self.manifest_path = self.root / "manifest.json"
        self.write_manifest()
        self.manifest_sha = hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest))

    def run_cli(self, *args, env=None):
        return subprocess.run([sys.executable, str(CLI), "--manifest", str(self.manifest_path),
                               *args], text=True, capture_output=True, env=env)

    def test_exact_release_and_artifact_bytes(self):
        result = self.run_cli("--model", MODEL, "--release", RELEASE, "--family", "ipv4",
                              "--kernel-release", KERNEL_RELEASE,
                              "--artifacts", str(self.artifacts), "--manifest-sha256", self.manifest_sha)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        selected = json.loads(result.stdout)
        self.assertEqual(selected["build_key"], "a" * 64)
        self.assertEqual(selected["sha256"], self.digest)
        self.assertEqual(selected["kernel_release"], KERNEL_RELEASE)
        self.assertTrue(selected["trusted_manifest"])

    def test_unknown_exact_release_fails(self):
        result = self.run_cli("--model", MODEL, "--release", "4.03.C.2.0", "--family", "ipv4")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported exact release", json.loads(result.stdout)["error"])

    def test_manifest_digest_and_artifact_bytes_are_checked(self):
        result = self.run_cli("--model", MODEL, "--release", RELEASE, "--family", "ipv4",
                              "--kernel-release", KERNEL_RELEASE, "--artifacts", str(self.artifacts),
                              "--manifest-sha256", "0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest SHA256", json.loads(result.stdout)["error"])
        (self.artifacts / self.filename).write_bytes(b"changed")
        result = self.run_cli("--model", MODEL, "--release", RELEASE, "--family", "ipv4",
                              "--kernel-release", KERNEL_RELEASE,
                              "--artifacts", str(self.artifacts), "--manifest-sha256", self.manifest_sha)
        self.assertIn("artifact SHA256 mismatch", json.loads(result.stdout)["error"])

    def test_wrong_or_missing_kernel_release_fails_preflight(self):
        args = ("--model", MODEL, "--release", RELEASE, "--family", "ipv4",
                "--artifacts", str(self.artifacts), "--manifest-sha256", self.manifest_sha)
        result = self.run_cli(*args)
        self.assertIn("requires --kernel-release or --detect", json.loads(result.stdout)["error"])
        result = self.run_cli(*args, "--kernel-release", "4.9-ndm-4")
        self.assertIn("kernel release mismatch", json.loads(result.stdout)["error"])

    def test_missing_build_provenance_fails(self):
        del self.manifest["builds"]["a" * 64]
        self.write_manifest()
        result = self.run_cli("--model", MODEL, "--release", RELEASE, "--family", "ipv4")
        self.assertIn("build provenance is missing", json.loads(result.stdout)["error"])
        self.manifest["builds"]["a" * 64] = {"modules": {
            "ipv4": {"sha256": self.digest, "vermagic": "4.9-ndm-4 SMP"},
        }}
        self.write_manifest()
        result = self.run_cli("--model", MODEL, "--release", RELEASE, "--family", "ipv4")
        self.assertIn("build provenance ipv4 vermagic mismatch", json.loads(result.stdout)["error"])

    def test_unsafe_artifact_path_and_unknown_family_fail(self):
        self.manifest["releases"][RELEASE][MODEL]["modules"]["ipv4"]["file"] = "../escape.ko"
        self.write_manifest()
        result = self.run_cli("--model", MODEL, "--release", RELEASE, "--family", "ipv4")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("artifact name", json.loads(result.stdout)["error"])
        result = self.run_cli("--model", MODEL, "--release", RELEASE, "--family", "ipv5")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("family must be", json.loads(result.stdout)["error"])

    def test_experimental_requires_opt_in(self):
        self.manifest["releases"][RELEASE][MODEL]["status"] = "experimental"
        self.write_manifest()
        result = self.run_cli("--model", MODEL, "--release", RELEASE, "--family", "ipv4")
        self.assertIn("requires --allow-experimental", json.loads(result.stdout)["error"])
        result = self.run_cli("--model", MODEL, "--release", RELEASE, "--family", "ipv4",
                              "--allow-experimental")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_detect_parses_exact_hw_id_and_release(self):
        ndmc = self.root / "ndmc"
        ndmc.write_text("#!/bin/sh\nprintf 'hw_id: KN1810\\nrelease: 4.03.C.2.0-1\\n'\n")
        ndmc.chmod(0o755)
        uname = self.root / "uname"
        uname.write_text(f"#!/bin/sh\nprintf '{KERNEL_RELEASE}\\n'\n")
        uname.chmod(0o755)
        env = {**os.environ, "PATH": f"{self.root}:{os.environ['PATH']}"}
        result = self.run_cli("--detect", "--family", "ipv4", "--artifacts", str(self.artifacts),
                              "--manifest-sha256", self.manifest_sha, env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        selected = json.loads(result.stdout)
        self.assertEqual((selected["model"], selected["release"]), (MODEL, RELEASE))
        self.assertEqual(selected["kernel_release"], KERNEL_RELEASE)


if __name__ == "__main__":
    unittest.main()
