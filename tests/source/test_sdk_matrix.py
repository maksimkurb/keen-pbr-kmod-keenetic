import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from sdk_matrix import build_key, generate_matrix, verify_configuration, verify_kernel_providers


def git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


class SdkMatrixTest(unittest.TestCase):
    def test_fresh_sdk_clone_checks_out_files_when_tag_already_equals_head(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            remote = root / "remote"
            remote.mkdir()
            git(remote, "init", "-q")
            git(remote, "config", "user.name", "test")
            git(remote, "config", "user.email", "test@example.invalid")
            (remote / "configure.sh").write_text("#!/bin/sh\nexit 0\n")
            git(remote, "add", ".")
            git(remote, "commit", "-qm", "SDK fixture")
            ref = git(remote, "rev-parse", "HEAD")
            tag = "5.00.C.1.0-0"
            git(remote, "-c", "tag.gpgSign=false", "tag", tag)
            project = root / "project"
            (project / "scripts").mkdir(parents=True)
            script = project / "scripts/prepare-sdk.sh"
            shutil.copy2(Path(__file__).resolve().parents[2] / "scripts/prepare-sdk.sh", script)
            (project / "sdk.lock").write_text(json.dumps({"repository": str(remote)}))
            destination = root / "checkout"
            subprocess.run([str(script), "--ref", ref, "--tag", tag,
                            "--destination", str(destination)], check=True, capture_output=True)
            self.assertEqual(git(destination, "rev-parse", "HEAD"), ref)
            self.assertEqual(git(destination, "diff", "--name-only", "HEAD"), "")
            self.assertTrue((destination / "configure.sh").is_file())

    def repositories(self, root):
        sdk, kernel = root / "sdk", root / "kernel"
        for repo in (sdk, kernel):
            repo.mkdir()
            git(repo, "init", "-q")
            git(repo, "config", "user.email", "test@example.invalid")
            git(repo, "config", "user.name", "test")
        (kernel / "source.txt").write_text("kernel source")
        git(kernel, "add", ".")
        git(kernel, "commit", "-qm", "kernel")
        git(kernel, "tag", "4.9.337-1", "-a", "-m", "kernel tag")
        board = sdk / "target/linux/testboard"
        model = board / "KN-1810"
        model.mkdir(parents=True)
        (sdk / "include").mkdir()
        (sdk / "include/kernel-defaults.mk").write_text("KERNEL_49_SOURCE_VERSION:=4.9.337-1\n")
        (board / "Makefile").write_text("ARCH:=mipsel\nKERNEL_PATCHVER:=4.9\n")
        (model / "ndwrt.config").write_text(
            'CONFIG_TARGET_BOARD="testboard"\nCONFIG_ARCH="mipsel"\n'
            'CONFIG_TARGET_ARCH_PACKAGES="KN-1810"\n')
        (sdk / "README.md").write_text("one")
        git(sdk, "add", ".")
        git(sdk, "commit", "-qm", "first")
        first = git(sdk, "rev-parse", "HEAD")
        git(sdk, "tag", "5.00.C.1.0-0", "-a", "-m", "sdk first")
        (sdk / "README.md").write_text("two")
        git(sdk, "commit", "-qam", "docs only")
        git(sdk, "tag", "5.00.C.1.0-1", "-a", "-m", "sdk second")
        return sdk, kernel, first

    def test_tags_peel_and_docs_only_tags_reuse_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            sdk, kernel, first = self.repositories(Path(tmp))
            result = generate_matrix(sdk, kernel, "https://example.invalid/sdk.git",
                                     "https://example.invalid/kernel.git")
            self.assertEqual(result["sdks"]["5.00.C.1.0-0"]["ref"], first)
            self.assertNotEqual(result["sdks"]["5.00.C.1.0-1"]["ref"], first)
            entries = [result["sdks"][tag]["models"]["KN-1810"]["configuration"]
                       for tag in ("5.00.C.1.0-0", "5.00.C.1.0-1")]
            self.assertEqual(entries[0], entries[1])
            self.assertEqual(len(result["configurations"]), 1)
            configuration = result["configurations"][entries[0]]
            git(sdk, "checkout", "--detach", configuration["sdk_ref"])
            self.assertEqual(verify_configuration(sdk, configuration), entries[0])
            changed = {**configuration, "arch": "aarch64"}
            with self.assertRaisesRegex(ValueError, "descriptor arch"):
                verify_configuration(sdk, changed)

    def test_build_key_ignores_sdk_tag_provenance(self):
        common = ("a" * 64, "b" * 64, "1.0.0", {"priority": -149}, {"image": "pinned"})
        first = build_key({"sdk_input_key": "c" * 64, "sdk_tag": "tag-a"}, *common)
        second = build_key({"sdk_input_key": "c" * 64, "sdk_tag": "tag-b"}, *common)
        self.assertEqual(first, second)

    def test_builtin_providers_use_pinned_source_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            kernel = Path(tmp)
            source = kernel / "net/ipv4/netfilter/ip_tables.c"
            source.parent.mkdir(parents=True)
            source.write_text("\n".join(f"EXPORT_SYMBOL({symbol});" for symbol in (
                "ipt_do_table", "ipt_alloc_initial_table", "ipt_register_table", "ipt_unregister_table")))
            evidence = verify_kernel_providers("CONFIG_IP_NF_IPTABLES=y\n", "", kernel)
            self.assertEqual(evidence["ipv4"]["evidence"], "pinned-kernel-source-export-declarations")

    def test_module_provider_requires_symvers_exports(self):
        with self.assertRaisesRegex(ValueError, "Module.symvers missing exports"):
            verify_kernel_providers("CONFIG_IP_NF_IPTABLES=m\n", "", Path("/missing"))

    def test_ipv4_provider_disabled_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "IPv4 iptables provider is disabled"):
            verify_kernel_providers("# CONFIG_IP_NF_IPTABLES is not set\n", "", Path("/missing"))


if __name__ == "__main__":
    unittest.main()
