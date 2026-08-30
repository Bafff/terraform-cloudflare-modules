#!/usr/bin/env python3
"""Scan a public module repository without exposing matched values."""

from __future__ import annotations

import argparse
import dataclasses
import fnmatch
import pathlib
import re
import stat


@dataclasses.dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str


FILENAME_RULES = (
    ("*.tfstate*", "forbidden-state-file"),
    ("*.tfplan*", "forbidden-plan-file"),
    ("credentials.json", "forbidden-credentials-file"),
    ("age-key.txt", "forbidden-age-key-file"),
    ("*.sops.*", "forbidden-sops-file"),
)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
GITHUB_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")
AGE_SECRET_KEY = re.compile(r"\bAGE-SECRET-KEY-1[A-Z0-9]+\b")
NAMED_SECRET = re.compile(
    r"(?i)\b(?:aws|cloudflare|github)[a-z0-9_-]*(?:token|secret|api[_-]?key)\b\s*[:=]\s*(?!re\.compile\()\S+"
)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
HOSTNAME = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
CLOUDFLARE_ID = re.compile(r"\b[0-9a-fA-F]{32}\b")
PROVIDER_BLOCK = re.compile(r"\bprovider\s+\"")
BACKEND_BLOCK = re.compile(r"\bbackend\s+\"")


def _is_permitted_domain(domain: str) -> bool:
    domain = domain.lower()
    return domain == "example.com" or domain.endswith(".example.com") or domain == "users.noreply.github.com"


def _relative_path(root: pathlib.Path, path: pathlib.Path) -> str:
    return path.relative_to(root).as_posix()


def _iter_regular_files(root: pathlib.Path):
    for path in sorted(root.rglob("*")):
        relative_parts = path.relative_to(root).parts
        if ".git" in relative_parts or ".terraform" in relative_parts:
            continue
        if path.is_symlink():
            continue
        try:
            if stat.S_ISREG(path.stat().st_mode):
                yield path
        except OSError:
            continue


def scan_path(root: pathlib.Path) -> tuple[Finding, ...]:
    """Return findings without storing or reporting matched values."""
    root = root.resolve()
    findings: list[Finding] = []
    for path in _iter_regular_files(root):
        relative = _relative_path(root, path)
        for pattern, rule in FILENAME_RULES:
            if fnmatch.fnmatch(path.name, pattern):
                findings.append(Finding(relative, 0, rule))

        try:
            with path.open("rb") as source:
                prefix = source.read(8192)
                if b"\0" in prefix:
                    continue
                content = prefix + source.read()
        except OSError:
            continue
        text = content.decode("utf-8", errors="replace")
        in_example = pathlib.PurePosixPath(relative).parts[:1] == ("examples",)
        in_module = pathlib.PurePosixPath(relative).parts[:1] == ("modules",)
        for line_number, line in enumerate(text.splitlines(), start=1):
            if PRIVATE_KEY.search(line):
                findings.append(Finding(relative, line_number, "private-key-marker"))
            if AWS_ACCESS_KEY.search(line):
                findings.append(Finding(relative, line_number, "aws-secret-format"))
            if GITHUB_TOKEN.search(line):
                findings.append(Finding(relative, line_number, "github-secret-format"))
            if AGE_SECRET_KEY.search(line):
                findings.append(Finding(relative, line_number, "age-secret-format"))
            if NAMED_SECRET.search(line):
                findings.append(Finding(relative, line_number, "named-secret-format"))

            for match in EMAIL.finditer(line):
                if not _is_permitted_domain(match.group(1)):
                    findings.append(Finding(relative, line_number, "non-public-email-domain"))

            if in_example:
                without_emails = EMAIL.sub("", line)
                for match in HOSTNAME.finditer(without_emails):
                    if not _is_permitted_domain(match.group(0)):
                        findings.append(Finding(relative, line_number, "non-example-hostname"))
                for match in CLOUDFLARE_ID.finditer(line):
                    if set(match.group(0)) != {"0"}:
                        findings.append(Finding(relative, line_number, "non-sentinel-cloudflare-id"))

            if in_module and PROVIDER_BLOCK.search(line):
                findings.append(Finding(relative, line_number, "module-provider-configuration"))
            if in_module and BACKEND_BLOCK.search(line):
                findings.append(Finding(relative, line_number, "module-backend-configuration"))

    return tuple(sorted(set(findings), key=lambda finding: (finding.path, finding.line, finding.rule)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    for finding in scan_path(arguments.path):
        print(f"{finding.path}:{finding.line}:{finding.rule}")
    return 1 if scan_path(arguments.path) else 0


if __name__ == "__main__":
    raise SystemExit(main())
