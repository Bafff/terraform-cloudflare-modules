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


if __name__ == "__main__":
    unittest.main()
