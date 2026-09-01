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


@dataclasses.dataclass
class HclHostnameState:
    block_comment_depth: int = 0
    in_string: bool = False
    expression_depth: int = 0
    expression_comment_depth: int = 0
    expression_string: bool = False


FILENAME_RULES = (
    ("*.tfstate*", "forbidden-state-file"),
    ("*.tfplan*", "forbidden-plan-file"),
    ("credentials.json", "forbidden-credentials-file"),
    ("age-key.txt", "forbidden-age-key-file"),
    ("*.sops.*", "forbidden-sops-file"),
)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
AWS_SECRET_ACCESS_KEY_ASSIGNMENT = re.compile(
    r"(?i)\bAWS_SECRET_ACCESS_KEY\b\s*[:=]\s*(?!re\.compile\()\S+"
)
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
HCL_HEREDOC = re.compile(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)")


def _is_permitted_domain(domain: str) -> bool:
    domain = domain.lower()
    return domain == "example.com" or domain.endswith(".example.com") or domain == "users.noreply.github.com"


def _relative_path(root: pathlib.Path, path: pathlib.Path) -> str:
    return path.relative_to(root).as_posix()


def _consume_hcl_string(line: str, start: int) -> tuple[str, int]:
    literal: list[str] = []
    index = start + 1
    while index < len(line):
        if line[index] == "\\" and index + 1 < len(line):
            literal.append(line[index : index + 2])
            index += 2
        elif line[index] == '"':
            return "".join(literal), index + 1
        elif line.startswith("$${", index):
            literal.append("${")
            index += 3
        elif line.startswith("%%{", index):
            literal.append("%{")
            index += 3
        elif line.startswith(("${", "%{"), index):
            nested_literals, index = _consume_hcl_expression(line, index + 2)
            literal.append(nested_literals)
        else:
            literal.append(line[index])
            index += 1
    return "".join(literal), index


def _consume_hcl_expression(line: str, start: int) -> tuple[str, int]:
    nested_literals: list[str] = []
    depth = 1
    index = start
    while index < len(line) and depth > 0:
        if line[index] == '"':
            literal, index = _consume_hcl_string(line, index)
            nested_literals.append(literal)
        elif line.startswith("/*", index):
            comment: list[str] = []
            comment_depth = 1
            index += 2
            while index < len(line) and comment_depth > 0:
                if line.startswith("/*", index):
                    comment_depth += 1
                    index += 2
                elif line.startswith("*/", index):
                    comment_depth -= 1
                    index += 2
                else:
                    comment.append(line[index])
                    index += 1
            nested_literals.append("".join(comment))
        elif line[index] == "{":
            depth += 1
            index += 1
        elif line[index] == "}":
            depth -= 1
            index += 1
        else:
            index += 1
    return " ".join(nested_literals), index


def _hcl_template_text(line: str) -> str:
    literal: list[str] = []
    index = 0
    while index < len(line):
        if line.startswith("$${", index):
            literal.append("${")
            index += 3
        elif line.startswith("%%{", index):
            literal.append("%{")
            index += 3
        elif line.startswith(("${", "%{"), index):
            nested_literals, index = _consume_hcl_expression(line, index + 2)
            literal.append(nested_literals)
        else:
            literal.append(line[index])
            index += 1
    return "".join(literal)


def _hcl_hostname_source(line: str, state: HclHostnameState) -> str:
    literal: list[str] = []
    index = 0
    while index < len(line):
        if state.block_comment_depth > 0:
            if line.startswith("/*", index):
                state.block_comment_depth += 1
                index += 2
            elif line.startswith("*/", index):
                state.block_comment_depth -= 1
                index += 2
            else:
                literal.append(line[index])
                index += 1
        elif state.expression_comment_depth > 0:
            if line.startswith("/*", index):
                state.expression_comment_depth += 1
                index += 2
            elif line.startswith("*/", index):
                state.expression_comment_depth -= 1
                index += 2
            else:
                literal.append(line[index])
                index += 1
        elif state.expression_string:
            if line[index] == "\\" and index + 1 < len(line):
                literal.append(line[index : index + 2])
                index += 2
            elif line[index] == '"':
                state.expression_string = False
                index += 1
            else:
                literal.append(line[index])
                index += 1
        elif state.expression_depth > 0:
            if line.startswith("/*", index):
                state.expression_comment_depth = 1
                index += 2
            elif line.startswith("//", index):
                literal.append(line[index + 2 :])
                break
            elif line[index] == "#":
                literal.append(line[index + 1 :])
                break
            elif line[index] == '"':
                state.expression_string = True
                index += 1
            elif line[index] == "{":
                state.expression_depth += 1
                index += 1
            elif line[index] == "}":
                state.expression_depth -= 1
                index += 1
            else:
                index += 1
        elif state.in_string:
            if line[index] == "\\" and index + 1 < len(line):
                literal.append(line[index : index + 2])
                index += 2
            elif line.startswith("$${", index):
                literal.append("${")
                index += 3
            elif line.startswith("%%{", index):
                literal.append("%{")
                index += 3
            elif line.startswith(("${", "%{"), index):
                state.expression_depth = 1
                index += 2
            elif line[index] == '"':
                state.in_string = False
                index += 1
            else:
                literal.append(line[index])
                index += 1
        elif line.startswith("/*", index):
            state.block_comment_depth = 1
            index += 2
        elif line.startswith("//", index):
            literal.append(line[index + 2 :])
            break
        elif line[index] == "#":
            literal.append(line[index + 1 :])
            break
        elif line[index] == '"':
            state.in_string = True
            index += 1
        else:
            index += 1
    return "".join(literal)


def _iter_regular_files(root: pathlib.Path):
    for path in sorted(root.rglob("*")):
        relative_parts = path.relative_to(root).parts
        if ".git" in relative_parts or ".terraform" in relative_parts or path.name == ".terraform.lock.hcl":
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
        heredoc_terminator: str | None = None
        hcl_hostname_state = HclHostnameState()
        for line_number, line in enumerate(text.splitlines(), start=1):
            if PRIVATE_KEY.search(line):
                findings.append(Finding(relative, line_number, "private-key-marker"))
            if AWS_ACCESS_KEY.search(line):
                findings.append(Finding(relative, line_number, "aws-secret-format"))
            if AWS_SECRET_ACCESS_KEY_ASSIGNMENT.search(line):
                findings.append(Finding(relative, line_number, "aws-secret-access-key-assignment"))
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
                hostname_source = without_emails
                if path.suffix in {".tf", ".hcl"}:
                    if heredoc_terminator is not None:
                        hostname_source = _hcl_template_text(without_emails)
                        if line.strip() == heredoc_terminator:
                            heredoc_terminator = None
                    else:
                        hostname_source = _hcl_hostname_source(
                            without_emails, hcl_hostname_state
                        )
                        heredoc = HCL_HEREDOC.search(line)
                        if heredoc:
                            heredoc_terminator = heredoc.group(1)
                for match in HOSTNAME.finditer(hostname_source):
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
    findings = scan_path(arguments.path)
    for finding in findings:
        print(f"{finding.path}:{finding.line}:{finding.rule}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
