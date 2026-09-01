import pathlib
import re
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


if __name__ == "__main__":
    unittest.main()
