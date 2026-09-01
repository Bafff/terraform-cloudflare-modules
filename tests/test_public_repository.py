import hashlib
import json
import os
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
MARKDOWN_URL = re.compile(r"(?:https?:)?//[^\s<>\"'`)\]]+", re.IGNORECASE)
MARKDOWN_ASSET_EXTENSION = re.compile(
    r"(?i)\.(?:gif|ico|jpe?g|png|svg|webp)(?=/|$)"
)


def is_example_domain(domain: str) -> bool:
    domain = domain.lower()
    return domain == "example.com" or domain.endswith(".example.com")


def markdown_uses_only_example_domains(text: str) -> bool:
    url_residues = []
    for match in MARKDOWN_URL.finditer(text):
        url = match.group(0).rstrip(".,;:!?")
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        if hostname is None or not is_example_domain(hostname):
            return False
        path = MARKDOWN_ASSET_EXTENSION.sub(
            "", urllib.parse.unquote(parsed.path)
        )
        url_residues.append(
            " ".join(
                filter(
                    None,
                    (
                        urllib.parse.unquote(parsed.username or ""),
                        urllib.parse.unquote(parsed.password or ""),
                        path,
                        urllib.parse.unquote_plus(parsed.query),
                        urllib.parse.unquote(parsed.fragment),
                    ),
                )
            )
        )
    without_urls = MARKDOWN_URL.sub("", text)
    text_to_check = "\n".join((without_urls, *url_residues))

    for match in MARKDOWN_EMAIL.finditer(text_to_check):
        if not is_example_domain(match.group(1)):
            return False
    without_emails = MARKDOWN_EMAIL.sub("", text_to_check)

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

    def run_make_with_fake_terraform(
        self, *targets: str, fail_command: str | None = None
    ):
        with tempfile.TemporaryDirectory() as directory:
            temporary_path = pathlib.Path(directory)
            fake_bin = temporary_path / "bin"
            fake_bin.mkdir()
            log = temporary_path / "terraform.log"
            terraform = fake_bin / "terraform"
            terraform.write_text(
                "#!/bin/bash\nset -eu\nprintf '%s\\n' \"$*\" >> \"$FAKE_TERRAFORM_LOG\"\n[ \"${FAKE_TERRAFORM_FAIL_COMMAND:-}\" != \"$*\" ] || exit 41\n",
                encoding="utf-8",
            )
            terraform.chmod(0o700)
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
            environment["FAKE_TERRAFORM_LOG"] = str(log)
            if fail_command is not None:
                environment["FAKE_TERRAFORM_FAIL_COMMAND"] = fail_command

            result = subprocess.run(
                ["make", *targets],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
            )
            calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
            return result, calls

    def test_native_terraform_target_initializes_and_tests_every_module(self):
        result, calls = self.run_make_with_fake_terraform("test-terraform")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        roots = [
            "modules/access-applications",
            "modules/cloudflare-tunnel",
            "modules/dns-records",
            "modules/google-workspace-mail",
            "examples/complete",
        ]
        expected_calls = []
        for root in roots:
            expected_calls.extend(
                [
                    f"-chdir={root} init -backend=false -input=false",
                    f"-chdir={root} test",
                ]
            )
        self.assertEqual(calls, expected_calls)

    def test_native_terraform_target_stops_after_failed_init(self):
        failed_command = "-chdir=modules/access-applications init -backend=false -input=false"
        result, calls = self.run_make_with_fake_terraform(
            "test-terraform", fail_command=failed_command
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [failed_command])

    def test_native_terraform_target_stops_after_failed_suite(self):
        failed_command = "-chdir=modules/access-applications test"
        result, calls = self.run_make_with_fake_terraform(
            "test-terraform", fail_command=failed_command
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            calls,
            [
                "-chdir=modules/access-applications init -backend=false -input=false",
                failed_command,
            ],
        )

    def test_validate_target_stops_after_failed_module(self):
        failed_command = "-chdir=modules/access-applications validate"
        result, calls = self.run_make_with_fake_terraform(
            "validate", fail_command=failed_command
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            calls,
            [
                "-chdir=modules/access-applications init -backend=false -input=false",
                failed_command,
            ],
        )

    def test_check_includes_native_terraform_suites(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        check_line = next(
            line for line in makefile.splitlines() if line.startswith("check:")
        )

        self.assertIn("test-terraform", check_line)

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

    def test_non_indented_hcl_heredoc_requires_unindented_terminator(self):
        value = ".".join(("private", "invalid"))
        result = self.scan(
            {
                "examples/main.tf": (
                    "value = <<EOT\n"
                    "  EOT\n"
                    f"{value}\n"
                    "EOT\n"
                )
            }
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_hcl_comment_cannot_open_heredoc_mode(self):
        result = self.scan(
            {
                "examples/main.tf": (
                    "# Use <<EOT for a heredoc.\n"
                    "value = local.settings\n"
                )
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepts_multiline_hcl_expression_in_heredoc(self):
        result = self.scan(
            {
                "examples/main.tf": (
                    "value = <<EOT\n"
                    "${jsonencode(\n"
                    "local.settings\n"
                    ")}\n"
                    "EOT\n"
                )
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepts_nested_template_expression_traversals(self):
        for path, content in {
            "examples/quoted.tf": 'value = "${format("${local.settings}")}"\n',
            "modules/example/heredoc.tf": (
                "value = <<EOT\n"
                '${format("${local.settings}")}\n'
                "EOT\n"
            ),
        }.items():
            with self.subTest(path=path):
                result = self.scan({path: content})
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_hostname_in_heredoc_opened_inside_template_expression(self):
        value = ".".join(("private", "invalid"))
        for path in ("examples/main.tf", "modules/example/main.tf"):
            with self.subTest(path=path):
                result = self.scan(
                    {
                        path: (
                            'value = "prefix-${jsonencode(<<EOT\n'
                            f"{value}\n"
                            "EOT\n"
                            ')}"\n'
                        )
                    }
                )
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_hostname_in_nested_expression_heredocs(self):
        value = ".".join(("private", "invalid"))
        inner_heredocs = {
            "ordinary": f"<<INNER\n{value}\nINNER",
            "indented": f"<<-INNER\n  {value}\n  INNER",
        }
        for path in ("examples/main.tf", "modules/example/main.tf"):
            for style, inner_heredoc in inner_heredocs.items():
                with self.subTest(path=path, style=style):
                    result = self.scan(
                        {
                            path: (
                                "value = <<OUTER\n"
                                f"${{jsonencode({inner_heredoc}\n)}}\n"
                                "OUTER\n"
                            )
                        }
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn(value, result.stdout + result.stderr)

    def test_hcl_metadata_context_matrix_covers_examples_and_modules(self):
        value = ".".join(("private", "invalid"))
        contexts = {
            "string": f'value = "{value}"\n',
            "line-comment": f"# {value}\n",
            "block-comment": f"/* {value} */\n",
            "heredoc": f"value = <<EOT\n{value}\nEOT\n",
            "expression-string": f'value = "${{lower("{value}")}}"\n',
            "expression-comment": f'value = "${{lower(/* {value} */ "EXAMPLE.COM")}}"\n',
        }
        for root in ("examples", "modules/example"):
            for context, content in contexts.items():
                with self.subTest(root=root, context=context):
                    result = self.scan({f"{root}/main.tf": content})
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn(value, result.stdout + result.stderr)

    def test_hcl_comment_and_string_boundaries_do_not_merge_hostnames(self):
        prefix = "private."
        suffix = "invalid"
        for label, content in {
            "ordinary": f'/*{prefix}*/value = "{suffix}"\n',
            "ordinary-nested-comment": (
                f"/*{prefix}/**/{suffix}*/\n"
            ),
            "expression": (
                f'value = "${{lower(/*{prefix}*/"{suffix}")}}"\n'
            ),
            "expression-nested-comment": (
                f'value = "${{lower(/*{prefix}/**/{suffix}*/ var.x)}}"\n'
            ),
        }.items():
            with self.subTest(label=label):
                result = self.scan(
                    {"modules/example/main.tf": content}
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_non_example_hostname_in_module_hcl(self):
        value = ".".join(("private", "invalid"))
        result = self.scan(
            {"modules/example/main.tf": f'domain = "{value}"\n'}
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_metadata_in_all_terraform_module_formats(self):
        hostname = ".".join(("private", "invalid"))
        image_like_hostname = ".".join(("private", "svg"))
        cloudflare_id = "1" * 32
        cases = {
            "modules/example/main.tf.json": json.dumps(
                {"hostname": hostname}
            ),
            "modules/example/tests/basic.tftest.hcl": (
                f'hostname = "{hostname}"\n'
            ),
            "modules/example/terraform.tfvars": (
                f'hostname = "{hostname}"\n'
            ),
            "modules/example/terraform.auto.tfvars": (
                f'hostname = "{hostname}"\n'
            ),
            "modules/example/terraform.tfvars.json": json.dumps(
                {"hostname": hostname}
            ),
            "modules/example/terraform.auto.tfvars.json": json.dumps(
                {"hostname": hostname}
            ),
            "modules/example/tests/basic.tftest.json": json.dumps(
                {"hostname": hostname}
            ),
            "modules/example/tests/defaults.tfmock.json": json.dumps(
                {"hostname": hostname}
            ),
            "modules/example/tests/id.tftest.hcl": (
                f'id = "{cloudflare_id}"\n'
            ),
            "modules/example/image-like.tf": (
                f'hostname = "{image_like_hostname}"\n'
            ),
            "modules/example/url-authority.tf": (
                f'url = "https://{image_like_hostname}"\n'
            ),
            "modules/example/scheme-relative-authority.tf": (
                f'url = "//{image_like_hostname}"\n'
            ),
        }
        for path, content in cases.items():
            with self.subTest(path=path):
                result = self.scan({path: content})
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(
                    hostname, result.stdout + result.stderr
                )
                self.assertNotIn(
                    cloudflare_id, result.stdout + result.stderr
                )
                self.assertNotIn(
                    image_like_hostname, result.stdout + result.stderr
                )

    def test_rejects_decoded_metadata_in_terraform_json(self):
        hostname = ".".join(("private", "invalid"))
        escaped_hostname = "private\\u002einvalid"
        escaped_email = "owner\\u0040private\\u002einvalid"
        cloudflare_id = "1" * 32
        escaped_cloudflare_id = "\\u0031" * 32
        cases = {
            "modules/example/main.tf.json": (
                f'{{"hostname":"{escaped_hostname}"}}'
            ),
            "modules/example/terraform.tfvars.json": (
                f'{{"hostname":"{escaped_hostname}"}}'
            ),
            "modules/example/terraform.auto.tfvars.json": (
                f'{{"hostname":"{escaped_hostname}"}}'
            ),
            "modules/example/tests/basic.tftest.json": (
                f'{{"hostname":"{escaped_hostname}"}}'
            ),
            "modules/example/tests/defaults.tfmock.json": (
                f'{{"hostname":"{escaped_hostname}"}}'
            ),
            "modules/example/tests/key.tftest.json": (
                f'{{"{escaped_hostname}":true}}'
            ),
            "modules/example/tests/email.tftest.json": (
                f'{{"email":"{escaped_email}"}}'
            ),
            "modules/example/tests/id.tftest.json": (
                f'{{"id":"{escaped_cloudflare_id}"}}'
            ),
        }
        for path, content in cases.items():
            with self.subTest(path=path):
                result = self.scan({path: content})
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(
                    hostname, result.stdout + result.stderr
                )
                self.assertNotIn(
                    cloudflare_id, result.stdout + result.stderr
                )

    def test_dynamic_template_boundaries_do_not_merge_metadata(self):
        hostname_template = 'private${format(".invalid")}'
        email_template = 'owner@private${format(".invalid")}'
        id_template = ("1" * 16) + '${format("' + ("1" * 16) + '")}'
        github_template = 'ghp_${format("' + ("A" * 24) + '")}'
        aws_template = 'AKIA${format("' + ("A" * 16) + '")}'
        age_template = (
            'AGE-SECRET-KEY-1${format("' + ("A" * 24) + '")}'
        )
        private_key_template = (
            '-----BEGIN ${format("PRIVATE KEY-----")}'
        )
        cases = {
            "modules/example/main.tf": (
                f'hostname = "{hostname_template}"\n'
                f'email = "{email_template}"\n'
                f'id = "{id_template}"\n'
            ),
            "modules/example/main.tf.json": json.dumps(
                {
                    "hostname": hostname_template,
                    "email": email_template,
                    "id": id_template,
                    "github": github_template,
                    "aws": aws_template,
                    "age": age_template,
                    "private_key": private_key_template,
                }
            ),
        }
        for path, content in cases.items():
            with self.subTest(path=path):
                result = self.scan({path: content})
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepts_quoted_arguments_in_terraform_json_templates(self):
        traversal = ".".join(("var", "private", "invalid"))
        value = f'${{format("%s", {traversal})}}'
        paths = (
            "modules/example/main.tf.json",
            "modules/example/terraform.tfvars.json",
            "modules/example/terraform.auto.tfvars.json",
            "modules/example/tests/basic.tftest.json",
            "modules/example/tests/defaults.tfmock.json",
        )
        for path in paths:
            with self.subTest(path=path):
                result = self.scan(
                    {path: json.dumps({"value": value})}
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_decoded_secret_signatures_in_json(self):
        values = {
            "github": "ghp_" + ("A" * 24),
            "aws": "AKIA" + ("A" * 16),
            "age": "AGE-SECRET-KEY-1" + ("A" * 24),
            "private-key": ("-" * 5) + "BEGIN PRIVATE KEY" + ("-" * 5),
        }
        for label, value in values.items():
            with self.subTest(label=label):
                escaped = f"\\u{ord(value[0]):04x}{value[1:]}"
                result = self.scan(
                    {
                        "modules/example/main.tf.json": (
                            f'{{"value":"{escaped}"}}'
                        )
                    }
                )
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_decoded_email_in_general_json(self):
        email = "owner@" + ".".join(("private", "invalid"))
        escaped = "owner\\u0040private\\u002einvalid"
        result = self.scan(
            {"config.json": f'{{"contact":"{escaped}"}}'}
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(email, result.stdout + result.stderr)

    def test_scans_valid_json_metadata_once(self):
        hostname = ".".join(("private", "invalid"))
        result = self.scan(
            {
                "modules/example/main.tf.json": json.dumps(
                    {"hostname": hostname}
                )
            }
        )
        self.assertEqual(result.returncode, 1)
        findings = [
            line
            for line in result.stdout.splitlines()
            if line.endswith(":non-example-hostname")
        ]
        self.assertEqual(len(findings), 1, findings)
        self.assertNotIn(hostname, result.stdout + result.stderr)

    def test_rejects_non_sentinel_cloudflare_id_in_module_hcl(self):
        value = "1" * 32
        result = self.scan(
            {"modules/example/main.tf": f'account_id = "{value}"\n'}
        )
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

    def test_rejects_non_example_hostname_in_multiline_hcl_expression_comment(self):
        value = ".".join(("private", "invalid"))
        result = self.scan(
            {
                "examples/main.tf": (
                    'value = "${lower(/*\n'
                    f"{value}\n"
                    '*/ "EXAMPLE.COM")}"\n'
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

    def test_accepts_named_secret_hcl_references_and_null(self):
        assignments = (
            (("cloudflare", "api", "token"), "var.token"),
            (("github", "token"), "null"),
            (("github", "api", "key"), "local.api_key"),
            (("aws", "secret"), "data.sops_file.secrets.data"),
            (("github", "token"), "token"),
            (("cloudflare", "token"), "sensitive(var.token)"),
            (("aws", "api", "key"), "try(local.api_key, null)"),
            (("github", "secret"), "[for value in var.values : value]"),
            (("cloudflare", "secret"), '"${var.token}"'),
        )
        body = "".join(
            f"  {'_'.join(name_parts)} = {value}\n"
            for name_parts, value in assignments
        )
        result = self.scan(
            {
                "modules/example/main.tf": f"locals {{\n{body}}}\n"
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepts_dynamic_named_secret_lookups_with_string_keys(self):
        name = "_".join(("cloudflare", "api", "token"))
        for label, value in {
            "index": 'var.tokens["cloudflare"]',
            "lookup": 'lookup(var.tokens, "cloudflare")',
            "wrapped-lookup": 'sensitive(lookup(var.tokens, "cloudflare"))',
            "object-key": 'lookup({ "cloudflare" = var.token }, "cloudflare")',
            "index-after-block-comment": (
                'var.tokens /* selector */ ["cloudflare"]'
            ),
            "function-before-block-comment": (
                'lookup /* call */ (var.tokens, "cloudflare")'
            ),
            "object-key-before-block-comment": (
                '{ "cloudflare" /* key */ = var.token }'
            ),
            "index-after-hash-comment": (
                "sensitive(var.tokens # selector!\n"
                '["cloudflare"])'
            ),
            "index-after-slash-comment": (
                "sensitive(var.tokens // selector!\n"
                '["cloudflare"])'
            ),
            "function-before-hash-comment": (
                "sensitive(lookup # call\n"
                '(var.tokens, "cloudflare"))'
            ),
            "function-before-slash-comment": (
                "sensitive(lookup // call\n"
                '(var.tokens, "cloudflare"))'
            ),
            "newline-object-keys": (
                "{\n"
                '  "first" = var.first # dynamic\n'
                '  "second" = var.second\n'
                "}"
            ),
            "newline-object-keys-inline-block-comment": (
                "{\n"
                '  "first" = var.first /* dynamic */\n'
                '  "second" = var.second\n'
                "}"
            ),
            "newline-object-keys-multiline-block-comment": (
                "{\n"
                '  "first" = var.first /* dynamic\n'
                "  value */\n"
                '  "second" = var.second\n'
                "}"
            ),
        }.items():
            with self.subTest(label=label):
                result = self.scan(
                    {
                        "modules/example/main.tf": (
                            f"{name} = {value}\n"
                        )
                    }
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepts_asset_url_query_and_fragment_in_module_hcl(self):
        for suffix in ("?version=1", "#logo"):
            with self.subTest(suffix=suffix):
                result = self.scan(
                    {
                        "modules/example/main.tf": (
                            'url = "https://example.com/logo.svg'
                            f'{suffix}"\n'
                        )
                    }
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepts_dynamic_named_secret_after_url_string(self):
        name = "_".join(("github", "token"))
        result = self.scan(
            {
                "modules/example/main.tf": (
                    'value = { url = "https://example.com", '
                    f"{name} = var.token }}\n"
                )
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_literal_named_secret_assignment(self):
        name = "_".join(("cloudflare", "api", "token"))
        value = "literal-" + ("x" * 24)
        result = self.scan(
            {"modules/example/main.tf": f'{name} = "{value}"\n'}
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_static_hcl_named_secret_forms(self):
        name = "_".join(("cloudflare", "token"))
        github_name = "_".join(("github", "token"))
        aws_name = "_".join(("AWS", "SECRET", "ACCESS", "KEY"))
        value = "literal-" + ("x" * 24)
        cases = {
            "named-heredoc.tf": f"{name} = <<EOT\n{value}\nEOT\n",
            "aws-heredoc.tf": f"{aws_name} = <<EOT\n{value}\nEOT\n",
            "wrapped-heredoc.tf": f"{name} = sensitive(<<EOT\n{value}\nEOT\n)\n",
            "multiline-wrapped-heredoc.tf": f"{name} = sensitive(\n<<EOT\n{value}\nEOT\n)\n",
            "escaped-template.tf": f'{name} = "$${{literal-placeholder}}"\n',
            "comment-after-literal.tf": f'{name} = "{value}" # ${{token}}\n',
            "commented-assignment.tf": f'# {name} = "{value}"\n',
            "commented-bare-assignment.tf": f"# {name} = token\n",
            "commented-aws-assignment.tf": f"# {aws_name} = token\n",
            "inline-comment-before-equals.tf": f'{name} /* note */ = "{value}"\n',
            "multiline-comment-before-equals.tf": f'{name} /*\nnote\n*/ = "{value}"\n',
            "nested-comment-before-equals.tf": f'{name} /* outer /* nested */ note */ = "{value}"\n',
            "inline-object-heredoc.tf": f"value = {{ {name} = sensitive(<<EOT\n{value}\nEOT\n) }}\n",
            "mixed-template.tf": f'{name} = "${{var.prefix}}{value}"\n',
            "object-ternary.tf": f'{name} = {{ value = var.enabled ? "{value}" : var.token }}\n',
            "multiline-object-ternary.tf": (
                f"{name} = {{\n"
                "  value = (\n"
                "    var.enabled\n"
                f'    ? "{value}"\n'
                "    : var.token\n"
                "  )\n"
                "}\n"
            ),
            "malformed-multiline-ternary.tf": (
                f"{name} = var.enabled\n"
                f'? "{value}"\n'
                ": var.token\n"
            ),
            "malformed-object-multiline-ternary.tf": (
                f"{name} = {{\n"
                "  value = var.enabled\n"
                f'  ? "{value}"\n'
                "  : var.token\n"
                "}\n"
            ),
            "malformed-commented-multiline-ternary.tf": (
                f"{name} = var.enabled\n"
                "# continuation\n"
                f'? "{value}"\n'
                ": var.token\n"
            ),
            "malformed-commented-object-ternary.tf": (
                f"{name} = {{\n"
                "  value = var.enabled\n"
                "  # continuation\n"
                f'  ? "{value}"\n'
                "  : var.token\n"
                "}\n"
            ),
            "object-equality.tf": f'{name} = {{ value = "{value}" == var.token }}\n',
            "wrapped-literal.tf": f'{name} = sensitive("{value}")\n',
            "wrapped-literal-after-hash-comment.tf": (
                f"{name} = sensitive # call\n"
                f'("{value}")\n'
            ),
            "wrapped-literal-after-slash-comment.tf": (
                f"{name} = sensitive // call\n"
                f'("{value}")\n'
            ),
            "wrapped-mixed-template.tf": f'{name} = sensitive("${{var.prefix}}{value}")\n',
            "comment-after-equals.tf": f'{name} = /* note */ "{value}"\n',
            "multiline-comment-after-equals.tf": f'{name} = /*\nnote\n*/ "{value}"\n',
            "nested-comment-after-equals.tf": f'{name} = /* outer /* nested */ note */ "{value}"\n',
            "line-comment-after-equals.tf": f'{name} = # note\n"{value}"\n',
            "comment-before-inline-key.tf": f'value = {{ /* note */ {name} = "{value}" }}\n',
            "prefixed-comment.tf": f'# TODO: {name} = var.token\n',
            "nested-block-comment.tf": f'/* outer /* nested */ {name} = var.token */\n',
            "multiple-inline-assignments.tf": f'value = {{ {name} = var.token, {github_name} = "{value}" }}\n',
        }
        for filename, content in cases.items():
            with self.subTest(filename=filename):
                result = self.scan({f"modules/example/{filename}": content})
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_prefixed_non_hcl_secret_assignments(self):
        aws_name = "_".join(("AWS", "SECRET", "ACCESS", "KEY"))
        value = "literal-" + ("x" * 24)
        for filename, content in {
            "environment.sh": f"export {aws_name}={value}\n",
            "values.yaml": f"- {aws_name}: {value}\n",
        }.items():
            with self.subTest(filename=filename):
                result = self.scan({filename: content})
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_static_named_secret_in_terraform_json(self):
        name = "_".join(("cloudflare", "token"))
        value = "literal-" + ("x" * 24)
        for label, secret_value in {
            "static": value,
            "mixed-template": "${var.prefix}" + value,
        }.items():
            with self.subTest(label=label):
                result = self.scan(
                    {"modules/example/main.tf.json": json.dumps({name: secret_value})}
                )
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_static_collection_under_terraform_json_secret_key(self):
        name = "_".join(("github", "token"))
        value = "literal-" + ("x" * 24)
        for label, secret_value in {
            "list": [value],
            "object": {"value": value},
        }.items():
            with self.subTest(label=label):
                result = self.scan(
                    {
                        "modules/example/main.tf.json": json.dumps(
                            {name: secret_value}
                        )
                    }
                )
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(value, result.stdout + result.stderr)

    def test_accepts_dynamic_and_null_terraform_json_secret_values(self):
        first_name = "_".join(("github", "token"))
        second_name = "_".join(("cloudflare", "token"))
        third_name = "_".join(("cloudflare", "api", "key"))
        result = self.scan(
            {
                "modules/example/main.tf.json": json.dumps(
                    {
                        first_name: "${var.token}",
                        second_name: None,
                        third_name: (
                            '${lookup(var.tokens, "cloudflare")}'
                        ),
                    }
                )
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_named_secret_in_malformed_json(self):
        name = "_".join(("github", "token"))
        value = "literal-" + ("x" * 24)
        result = self.scan(
            {"config.json": f'{{"{name}": "{value}",}}\n'}
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_static_duplicate_named_secret_in_json(self):
        name = "_".join(("github", "token"))
        value = "literal-" + ("x" * 24)
        for label, static_value in {
            "string": f'"{value}"',
            "number": "12345",
            "boolean": "true",
        }.items():
            with self.subTest(label=label):
                result = self.scan(
                    {
                        "config.json": (
                            f'{{"{name}": {static_value}, '
                            f'"{name}": "${{var.token}}"}}\n'
                        )
                    }
                )
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(value, result.stdout + result.stderr)

    def test_rejects_named_secret_assignment_inside_hcl_heredoc(self):
        name = "_".join(("github", "token"))
        value = "literal_value"
        result = self.scan(
            {
                "modules/example/main.tf": (
                    "value = <<EOT\n"
                    f"{name} = {value}\n"
                    "EOT\n"
                )
            }
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("named-secret-format", result.stdout)
        self.assertNotIn(value, result.stdout + result.stderr)

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

    def test_markdown_domain_check_rejects_non_example_url_userinfo(self):
        forbidden = ".".join(("private", "invalid"))
        self.assertFalse(
            markdown_uses_only_example_domains(
                f"https://{forbidden}@example.com/logo.svg"
            )
        )

    def test_markdown_domain_check_rejects_non_example_url_path(self):
        forbidden = ".".join(("private", "invalid"))
        self.assertFalse(
            markdown_uses_only_example_domains(
                f"https://example.com/customers/{forbidden}/logo.svg"
            )
        )

    def test_markdown_domain_check_rejects_non_example_url_query(self):
        forbidden = ".".join(("private", "invalid"))
        self.assertFalse(
            markdown_uses_only_example_domains(
                f"https://example.com/logo.svg?origin={forbidden}"
            )
        )

    def test_markdown_domain_check_rejects_encoded_non_example_url_path(self):
        forbidden = "%2E".join(("private", "invalid"))
        self.assertFalse(
            markdown_uses_only_example_domains(
                f"https://example.com/customers/{forbidden}/logo.svg"
            )
        )

    def test_markdown_domain_check_rejects_domain_hidden_in_asset_filename(self):
        forbidden = ".".join(("private", "invalid"))
        self.assertFalse(
            markdown_uses_only_example_domains(
                f"https://example.com/{forbidden}.png"
            )
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

    def test_markdown_domain_check_accepts_inline_example_asset_link(self):
        self.assertTrue(
            markdown_uses_only_example_domains(
                "[logo](https://example.com/logo.svg)"
            )
        )

    def test_markdown_domain_check_accepts_asset_url_before_prose_punctuation(self):
        self.assertTrue(
            markdown_uses_only_example_domains(
                "See https://example.com/logo.svg, for details."
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
