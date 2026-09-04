import pathlib
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULES = ROOT / "modules"


class ModuleContractTest(unittest.TestCase):
    def test_child_modules_do_not_configure_provider_or_backend(self):
        for path in MODULES.rglob("*.tf"):
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"(?m)^\s*provider\s+\"", text), path)
            self.assertIsNone(re.search(r"(?m)^\s*backend\s+\"", text), path)

    def test_mail_record_resource_has_prevent_destroy(self):
        text = (MODULES / "google-workspace-mail" / "main.tf").read_text(encoding="utf-8")
        resource = re.search(
            r'^resource\s+"cloudflare_dns_record"\s+"this"\s*\{(?P<body>.*?)^\}',
            text,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(resource)
        self.assertRegex(resource.group("body"), r"lifecycle\s*\{[^}]*prevent_destroy\s*=\s*true")

    def test_tunnel_resource_has_prevent_destroy(self):
        text = (MODULES / "cloudflare-tunnel" / "main.tf").read_text(encoding="utf-8")
        resource = re.search(
            r'^resource\s+"cloudflare_zero_trust_tunnel_cloudflared"\s+"this"\s*\{(?P<body>.*?)^\}',
            text,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(resource)
        self.assertRegex(resource.group("body"), r"lifecycle\s*\{[^}]*prevent_destroy\s*=\s*true")

    def test_tunnel_resource_ignores_the_write_only_secret_after_creation(self):
        text = (MODULES / "cloudflare-tunnel" / "main.tf").read_text(encoding="utf-8")
        resource = re.search(
            r'^resource\s+"cloudflare_zero_trust_tunnel_cloudflared"\s+"this"\s*\{(?P<body>.*?)^\}',
            text,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(resource)
        self.assertRegex(
            resource.group("body"),
            r"lifecycle\s*\{[^}]*ignore_changes\s*=\s*\[\s*tunnel_secret\s*\]",
        )

    def test_generated_tunnel_secret_has_prevent_destroy(self):
        text = (MODULES / "cloudflare-tunnel" / "main.tf").read_text(encoding="utf-8")
        resource = re.search(
            r'^resource\s+"random_bytes"\s+"tunnel_secret"\s*\{(?P<body>.*?)^\}',
            text,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(resource)
        self.assertRegex(resource.group("body"), r"lifecycle\s*\{[^}]*prevent_destroy\s*=\s*true")

    def test_tunnel_replacement_is_triggered_by_secret_replacement(self):
        text = (MODULES / "cloudflare-tunnel" / "main.tf").read_text(encoding="utf-8")
        resource = re.search(
            r'^resource\s+"cloudflare_zero_trust_tunnel_cloudflared"\s+"this"\s*\{(?P<body>.*?)^\}',
            text,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(resource)
        self.assertRegex(
            resource.group("body"),
            r"replace_triggered_by\s*=\s*\[\s*random_bytes\.tunnel_secret\s*\]",
        )

    def apply_lifecycle_fixture(self, terraform, root):
        (root / "main.tf").write_text(
            textwrap.dedent(
                """
                resource "terraform_data" "secret" {
                  input = "original-secret"
                }

                resource "terraform_data" "tunnel" {
                  input = terraform_data.secret.output

                  lifecycle {
                    prevent_destroy      = true
                    ignore_changes       = [input]
                    replace_triggered_by = [terraform_data.secret]
                  }
                }
                """
            ).lstrip(),
            encoding="utf-8",
        )
        applied = subprocess.run(
            [terraform, f"-chdir={root}", "apply", "-auto-approve", "-input=false", "-no-color"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)

    def test_secret_replacement_blocks_the_dependent_resource_plan(self):
        terraform = shutil.which("terraform")
        self.assertIsNotNone(terraform)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.apply_lifecycle_fixture(terraform, root)
            tainted = subprocess.run(
                [terraform, f"-chdir={root}", "taint", "-no-color", "terraform_data.secret"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(tainted.returncode, 0, tainted.stdout + tainted.stderr)
            planned = subprocess.run(
                [terraform, f"-chdir={root}", "plan", "-input=false", "-detailed-exitcode", "-no-color"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(planned.returncode, 1, planned.stdout + planned.stderr)
            self.assertIn("Instance cannot be destroyed", planned.stdout + planned.stderr)
            self.assertIn("terraform_data.tunnel", planned.stdout + planned.stderr)

    def test_manual_secret_state_removal_requires_an_external_guard(self):
        terraform = shutil.which("terraform")
        self.assertIsNotNone(terraform)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.apply_lifecycle_fixture(terraform, root)
            removed = subprocess.run(
                [terraform, f"-chdir={root}", "state", "rm", "-no-color", "terraform_data.secret"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
            planned = subprocess.run(
                [terraform, f"-chdir={root}", "plan", "-input=false", "-detailed-exitcode", "-no-color"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(planned.returncode, 2, planned.stdout + planned.stderr)
            self.assertIn("terraform_data.secret will be created", planned.stdout)
            self.assertNotIn("terraform_data.tunnel must be replaced", planned.stdout)

    def test_tunnel_credentials_output_is_sensitive(self):
        text = (MODULES / "cloudflare-tunnel" / "outputs.tf").read_text(encoding="utf-8")
        output = re.search(
            r'^output\s+"credentials_json"\s*\{(?P<body>.*?)^\}',
            text,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(output)
        self.assertRegex(output.group("body"), r"(?m)^\s*sensitive\s*=\s*true\s*$")

    def test_tunnel_module_has_no_remote_config_or_file_writer(self):
        module = MODULES / "cloudflare-tunnel"
        text = "\n".join(path.read_text(encoding="utf-8") for path in module.glob("*.tf"))
        self.assertNotIn('resource "cloudflare_zero_trust_tunnel_cloudflared_config"', text)
        self.assertIsNone(
            re.search(r'(?m)^\s*resource\s+"(?:local_file|local_sensitive_file)"', text)
        )

    def test_access_email_input_is_sensitive(self):
        text = (MODULES / "access-applications" / "variables.tf").read_text(encoding="utf-8")
        variable = re.search(
            r'^variable\s+"allowed_emails"\s*\{(?P<body>.*?)^\}',
            text,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(variable)
        self.assertRegex(variable.group("body"), r"(?m)^\s*sensitive\s*=\s*true\s*$")

    def test_complete_example_wires_tunnel_dns_and_access_inputs(self):
        text = (ROOT / "examples" / "complete" / "main.tf").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^\s*content\s*=\s*local\.tunnel_dns_targets\[key\]\s*$")
        self.assertRegex(text, r'(?s)module\s+"dns_records"\s*\{.*?\n\s*records\s*=\s*local\.dns_records\s*\n')
        self.assertRegex(text, r'(?s)module\s+"access_applications"\s*\{.*?\n\s*applications\s*=\s*local\.applications\s*\n')


if __name__ == "__main__":
    unittest.main()
