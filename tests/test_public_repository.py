import hashlib
import json
import pathlib
import subprocess
import tarfile
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "scan-public.py"
INSTALLER = ROOT / "scripts" / "setup-ci-tools.sh"


class PublicRepositoryTest(unittest.TestCase):
    def scan(self, files: dict[str, str]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            return subprocess.run(
                ["python3", SCANNER, "--path", root],
                text=True,
                capture_output=True,
            )

    def test_accepts_reserved_examples(self):
        result = self.scan(
            {
                "examples/main.tf": 'domain = "docs.example.com"\n',
                "examples/values.json": '{"zone_id":"00000000000000000000000000000000"}',
                "README.md": "owner@example.com\n",
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_non_example_metadata_without_echoing_it(self):
        value = "private.invalid"
        result = self.scan({"examples/main.tf": f'domain = "{value}"\n'})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_state_plan_and_credentials(self):
        result = self.scan(
            {
                "terraform.tfstate": "{}",
                "saved.tfplan": "binary",
                "credentials.json": "{}",
            }
        )
        self.assertEqual(result.returncode, 1)

    def test_rejects_provider_and_backend_blocks_in_child_modules(self):
        result = self.scan(
            {
                "modules/bad/main.tf": 'provider "cloudflare" {}\n',
                "modules/bad/backend.tf": 'terraform { backend "s3" {} }\n',
            }
        )
        self.assertEqual(result.returncode, 1)

    def test_allows_required_providers_in_child_modules(self):
        result = self.scan(
            {
                "modules/good/versions.tf": (
                    'terraform { required_providers { cloudflare = { source = "cloudflare/cloudflare" } } }\n'
                )
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_never_echoes_secret_values(self):
        value = "ghp_" + ("0" * 36)
        result = self.scan({"notes.txt": f"token = {value}\n"})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_accepts_security_pattern_source_without_a_secret_value(self):
        result = self.scan(
            {"scripts/patterns.py": 'GITHUB_TOKEN = re.compile("pattern")\n'}
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_remote_is_absent_or_the_expected_public_repository(self):
        remotes = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        if remotes.returncode == 0:
            self.assertEqual(
                remotes.stdout.strip(),
                "https://github.com/Bafff/terraform-cloudflare-modules.git",
            )

    def test_repository_contract_has_no_remote_and_public_placeholders(self):
        remote = subprocess.run(
            ["git", "remote"], cwd=ROOT, text=True, capture_output=True, check=True
        )
        self.assertEqual(remote.stdout, "")
        self.assertEqual((ROOT / ".terraform-version").read_text(encoding="utf-8").strip(), "1.16.0")
        self.assertIn("example.com", (ROOT / "README.md").read_text(encoding="utf-8"))


class SetupCiToolsTest(unittest.TestCase):
    def create_lock(self, directory: pathlib.Path, url: str, sha256: str) -> pathlib.Path:
        lock = {
            "schema": 1,
            "platforms": ["linux_amd64"],
            "tools": {
                "terraform": {
                    "version": "1.16.0",
                    "archives": {
                        "linux_amd64": {
                            "asset": "terraform_1.16.0_linux_amd64.zip",
                            "sha256": sha256,
                            "url": url,
                        }
                    },
                }
            },
        }
        path = directory / "lock.json"
        path.write_text(json.dumps(lock), encoding="utf-8")
        return path

    def test_installs_only_verified_linux_asset_from_local_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            archive = root / "terraform_1.16.0_linux_amd64.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("terraform", "#!/bin/sh\necho test\n")
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            lock = self.create_lock(root, archive.as_uri(), checksum)
            install_dir = root / "bin"
            result = subprocess.run(
                ["bash", INSTALLER, "--lock-file", lock, "--install-dir", install_dir],
                env={"PATH": "/usr/bin:/bin", "SETUP_CI_TOOLS_PLATFORM": "linux_amd64"},
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((install_dir / "terraform").is_file())

    def test_rejects_archive_with_wrong_checksum_before_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            archive = root / "terraform_1.16.0_linux_amd64.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("terraform", "unexpected")
            lock = self.create_lock(root, archive.as_uri(), "0" * 64)
            install_dir = root / "bin"
            result = subprocess.run(
                ["bash", INSTALLER, "--lock-file", lock, "--install-dir", install_dir],
                env={"PATH": "/usr/bin:/bin", "SETUP_CI_TOOLS_PLATFORM": "linux_amd64"},
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(install_dir.exists())

    def test_rejects_unknown_platform_without_downloading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            lock = self.create_lock(root, "file:///does/not/matter", "0" * 64)
            result = subprocess.run(
                ["bash", INSTALLER, "--lock-file", lock, "--install-dir", root / "bin"],
                env={"PATH": "/usr/bin:/bin", "SETUP_CI_TOOLS_PLATFORM": "darwin_arm64"},
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "bin").exists())


if __name__ == "__main__":
    unittest.main()
