import hashlib
import json
import pathlib
import re
import subprocess
import tarfile
import tempfile
import unittest
import urllib.parse
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "scan-public.py"
INSTALLER = ROOT / "scripts" / "setup-ci-tools.sh"
MARKDOWN_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
MARKDOWN_HOSTNAME = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
MARKDOWN_URL = re.compile(r"(?:https?:)?//[^\s<>\"'`]+", re.IGNORECASE)


def is_example_domain(domain: str) -> bool:
    domain = domain.lower()
    return domain == "example.com" or domain.endswith(".example.com")


def markdown_uses_only_example_domains(text: str) -> bool:
    for match in MARKDOWN_URL.finditer(text):
        hostname = urllib.parse.urlsplit(match.group(0)).hostname
        if hostname is None or not is_example_domain(hostname):
            return False
    without_urls = MARKDOWN_URL.sub("", text)

    for match in MARKDOWN_EMAIL.finditer(without_urls):
        if not is_example_domain(match.group(1)):
            return False
    without_emails = MARKDOWN_EMAIL.sub("", without_urls)

    return all(is_example_domain(match.group(0)) for match in MARKDOWN_HOSTNAME.finditer(without_emails))


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

    def test_accepts_terraform_traversals_in_examples(self):
        result = self.scan(
            {
                "examples/main.tf": (
                    'target = module.cloudflare_tunnel.cloudflare_zero_trust_tunnel_cloudflared.this\n'
                    'domain = "docs.${var.domain}"\n'
                    'content = "${module.cloudflare_tunnel.tunnel_id}.tunnel.example.com"\n'
                )
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_non_example_metadata_without_echoing_it(self):
        value = ".".join(("private", "invalid"))
        result = self.scan({"examples/main.tf": f'domain = "{value}"\n'})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_non_example_hostname_in_hcl_heredoc(self):
        value = ".".join(("private", "invalid"))
        result = self.scan({"examples/main.tf": f"value = <<EOT\n{value}\nEOT\n"})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_non_example_hostname_in_hcl_comment(self):
        value = ".".join(("private", "invalid"))
        result = self.scan({"examples/main.tf": f"# {value}\n"})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_non_example_hostname_in_hcl_block_comment(self):
        value = ".".join(("private", "invalid"))
        result = self.scan({"examples/main.tf": f"/* {value} */\n"})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_non_example_hostname_in_nested_multiline_hcl_block_comment(self):
        value = ".".join(("private", "invalid"))
        result = self.scan(
            {"examples/main.tf": f"/* outer\n/* nested */\n{value}\n*/\n"}
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_non_example_hostname_in_nested_hcl_template_string(self):
        value = ".".join(("private", "invalid"))
        result = self.scan(
            {"examples/main.tf": f'domain = "${{lower("{value}")}}"\n'}
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_non_example_hostname_in_escaped_hcl_interpolation(self):
        value = ".".join(("private", "invalid"))
        result = self.scan({"examples/main.tf": f'value = "$${{{value}}}"\n'})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_non_example_hostname_in_hcl_expression_comment(self):
        value = ".".join(("private", "invalid"))
        result = self.scan(
            {
                "examples/main.tf": (
                    f'value = "${{lower(/* {value} */ "EXAMPLE.COM")}}"\n'
                )
            }
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_accepts_hcl_template_directive_traversals(self):
        result = self.scan(
            {"examples/main.tf": "value = <<EOT\n%{ if var.enabled }\nexample.com\n%{ endif }\nEOT\n"}
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_aws_secret_access_key_assignment_without_echoing_it(self):
        name = "_".join(("AWS", "SECRET", "ACCESS", "KEY"))
        value = "x" * 32
        result = self.scan({"values.env": f"{name}={value}\n"})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_test_fixtures_do_not_commit_non_example_hostnames(self):
        fixture_source = pathlib.Path(__file__).read_text(encoding="utf-8")
        forbidden = ".".join(("private", "invalid"))
        self.assertNotIn(forbidden, fixture_source)

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

    def test_ignores_generated_child_module_lockfiles(self):
        result = self.scan(
            {
                "modules/example/.terraform.lock.hcl": (
                    'provider "registry.terraform.io/cloudflare/cloudflare" {\n'
                    '  version = "5.24.0"\n'
                    "}\n"
                )
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

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
                remotes.stdout.strip().removesuffix(".git"),
                "https://github.com/Bafff/terraform-cloudflare-modules",
            )

    def test_repository_contract_has_public_placeholders(self):
        self.assertEqual((ROOT / ".terraform-version").read_text(encoding="utf-8").strip(), "1.16.0")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("example.com", readme)
        self.assertIn("macOS ARM64 is for local operator work; Linux AMD64 is for CI.", readme)
        self.assertIn(
            "Native Windows support is explicitly deferred because it adds maintenance work without a current use case.",
            readme,
        )

    def test_module_documentation_is_public_and_credential_free(self):
        module_names = (
            "access-applications",
            "cloudflare-tunnel",
            "dns-records",
            "google-workspace-mail",
        )
        for module_name in module_names:
            readme = ROOT / "modules" / module_name / "README.md"
            self.assertTrue(readme.is_file(), readme)

        provider_or_backend = re.compile(r'(?m)^\s*(?:provider|backend)\s+"')
        for path in (ROOT / "modules").rglob("*.tf"):
            self.assertIsNone(
                provider_or_backend.search(path.read_text(encoding="utf-8")),
                path,
            )

        private_repository_name = "-".join(("cloudflare", "infrastructure"))
        cloudflare_id = re.compile(r"\b[0-9a-fA-F]{32}\b")
        for path in ROOT.rglob("*.md"):
            if ".superpowers" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(private_repository_name, text.lower(), path)
            self.assertTrue(markdown_uses_only_example_domains(text), path)
            self.assertTrue(
                all(set(match.group(0)) == {"0"} for match in cloudflare_id.finditer(text)),
                path,
            )

        result = subprocess.run(
            ["python3", SCANNER, "--path", ROOT],
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_complete_example_is_documented_and_credential_free(self):
        example = ROOT / "examples" / "complete"
        self.assertTrue((example / "README.md").is_file())
        self.assertTrue((example / "tests" / "basic.tftest.hcl").is_file())

        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in example.rglob("*.*")
            if path.is_file()
            and ".terraform" not in path.parts
            and path.name != ".terraform.lock.hcl"
        )
        self.assertNotRegex(text, r'(?m)^\s*(?:provider|backend)\s+"')
        self.assertNotIn("cfargotunnel.com", text.lower())

    def test_markdown_domain_check_rejects_suffix_spoof(self):
        self.assertFalse(markdown_uses_only_example_domains("customerexample.com"))

    def test_markdown_domain_check_rejects_non_example_url_authority(self):
        forbidden = ".".join(("private", "invalid"))
        self.assertFalse(
            markdown_uses_only_example_domains(f"https://{forbidden}/logo.svg")
        )

    def test_markdown_domain_check_rejects_uppercase_non_example_url_authority(self):
        forbidden = ".".join(("private", "invalid"))
        self.assertFalse(
            markdown_uses_only_example_domains(f"HTTPS://{forbidden}/logo.svg")
        )

    def test_markdown_domain_check_rejects_scheme_relative_non_example_url_authority(self):
        forbidden = ".".join(("private", "invalid"))
        self.assertFalse(
            markdown_uses_only_example_domains(f"//{forbidden}/logo.svg")
        )

    def test_markdown_domain_check_accepts_uppercase_and_scheme_relative_example_urls(self):
        self.assertTrue(
            markdown_uses_only_example_domains(
                "HTTPS://example.com/logo.svg //docs.example.com/logo.svg"
            )
        )

    def test_markdown_domain_check_accepts_example_email_and_url(self):
        self.assertTrue(
            markdown_uses_only_example_domains(
                "owner@example.com https://example.com/logo.svg"
            )
        )

    def test_markdown_domain_check_rejects_non_example_email(self):
        forbidden = ".".join(("private", "invalid"))
        self.assertFalse(markdown_uses_only_example_domains(f"owner@{forbidden}"))


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

    def test_rejects_unlocked_lock_before_download(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            lock = self.create_lock(root, "file:///does/not/matter", "0" * 64)
            lock_data = json.loads(lock.read_text(encoding="utf-8"))
            del lock_data["tools"]["terraform"]["archives"]["linux_amd64"]["url"]
            lock.write_text(json.dumps(lock_data), encoding="utf-8")
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
