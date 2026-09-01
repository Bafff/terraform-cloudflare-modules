#!/usr/bin/env python3
"""Scan a public module repository without exposing matched values."""

from __future__ import annotations

import argparse
import dataclasses
import fnmatch
import json
import pathlib
import re
import stat


@dataclasses.dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str


@dataclasses.dataclass(frozen=True)
class JsonObject:
    pairs: tuple[tuple[str, object], ...]


@dataclasses.dataclass
class HclHostnameState:
    block_comment_depth: int = 0
    in_string: bool = False
    in_heredoc: bool = False
    expression_depth: int = 0
    expression_comment_depth: int = 0
    expression_string: bool = False
    expression_string_return_depths: list[int] = dataclasses.field(
        default_factory=list
    )


FILENAME_RULES = (
    ("*.tfstate*", "forbidden-state-file"),
    ("*.tfplan*", "forbidden-plan-file"),
    ("credentials.json", "forbidden-credentials-file"),
    ("age-key.txt", "forbidden-age-key-file"),
    ("*.sops.*", "forbidden-sops-file"),
)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
AWS_SECRET_ACCESS_KEY_NAME = re.compile(r"(?i)^AWS_SECRET_ACCESS_KEY$")
AWS_SECRET_ACCESS_KEY_ASSIGNMENT = re.compile(
    r'''(?i)(?<![A-Za-z0-9_-])["']?AWS_SECRET_ACCESS_KEY["']?'''
    r'''(?![A-Za-z0-9_-])'''
)
GITHUB_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")
AGE_SECRET_KEY = re.compile(r"\bAGE-SECRET-KEY-1[A-Z0-9]+\b")
NAMED_SECRET_NAME = re.compile(
    r"(?i)^(?:aws|cloudflare|github)[a-z0-9_-]*(?:token|secret|api[_-]?key)$"
)
NAMED_SECRET_ASSIGNMENT = re.compile(
    r'''(?i)(?<![A-Za-z0-9_-])["']?(?:aws|cloudflare|github)[a-z0-9_-]*(?:token|secret|api[_-]?key)["']?'''
    r'''(?![A-Za-z0-9_-])'''
)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
HOSTNAME = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
CLOUDFLARE_ID = re.compile(r"\b[0-9a-fA-F]{32}\b")
PROVIDER_BLOCK = re.compile(r"\bprovider\s+\"")
BACKEND_BLOCK = re.compile(r"\bbackend\s+\"")
HCL_HEREDOC = re.compile(
    r"<<(?P<allows_indent>-?)\s*(?P<terminator>[A-Za-z_][A-Za-z0-9_]*)"
)


def _is_permitted_domain(domain: str) -> bool:
    domain = domain.lower()
    return domain == "example.com" or domain.endswith(".example.com") or domain == "users.noreply.github.com"


def _relative_path(root: pathlib.Path, path: pathlib.Path) -> str:
    return path.relative_to(root).as_posix()


def _is_hcl_path(path: pathlib.Path) -> bool:
    return path.suffix in {".tf", ".hcl"} or path.name.endswith(".tf.json")


def _assignment_exposes_literal(
    path: pathlib.Path,
    text: str,
    match: re.Match[str],
    value_start: int,
) -> bool:
    value = text[value_start:].lstrip()
    if value.startswith("re.compile("):
        return False
    if not _is_hcl_path(path):
        return True
    if _hcl_position_is_in_comment_or_string(text, match.start()):
        return True
    return _hcl_expression_exposes_literal(text, value_start)


def _assignment_value_start(
    text: str, match: re.Match[str]
) -> int | None:
    block_comment_depth = 0
    index = match.end()
    while index < len(text):
        if block_comment_depth > 0:
            if text.startswith("/*", index):
                block_comment_depth += 1
                index += 2
            elif text.startswith("*/", index):
                block_comment_depth -= 1
                index += 2
            else:
                index += 1
        elif text.startswith("/*", index):
            block_comment_depth = 1
            index += 2
        elif text[index].isspace():
            index += 1
        elif text[index] in "=:":
            index += 1
            while index < len(text) and text[index].isspace():
                index += 1
            return index
        else:
            return None
    return None


def _hcl_value_is_static_literal(value: str) -> bool:
    value = value.lstrip()
    if value.startswith("<<"):
        return True
    if not value.startswith(('"', "'")):
        return False
    exposes_literal, _ = _scan_hcl_quoted_string(value, 0)
    return exposes_literal


def _scan_hcl_quoted_string(value: str, start: int) -> tuple[bool, int]:
    quote = value[start]
    if quote == "'":
        end = value.find("'", start + 1)
        return True, len(value) if end == -1 else end + 1

    has_dynamic_segment = False
    has_literal_segment = False
    index = start + 1
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            has_literal_segment = True
            index += 2
        elif value.startswith(("$${", "%%{"), index):
            has_literal_segment = True
            index += 3
        elif value.startswith(("${", "%{"), index):
            has_dynamic_segment = True
            index, nested_literal = _scan_hcl_template_expression(
                value, index + 2
            )
            has_literal_segment = has_literal_segment or nested_literal
        elif value[index] == '"':
            return (
                has_literal_segment or not has_dynamic_segment,
                index + 1,
            )
        else:
            has_literal_segment = True
            index += 1
    return True, len(value)


def _scan_hcl_template_expression(
    value: str, start: int
) -> tuple[int, bool]:
    depth = 1
    block_comment_depth = 0
    found_literal = False
    index = start
    while index < len(value) and depth > 0:
        if block_comment_depth > 0:
            if value.startswith("/*", index):
                block_comment_depth += 1
                index += 2
            elif value.startswith("*/", index):
                block_comment_depth -= 1
                index += 2
            else:
                index += 1
        elif value.startswith("/*", index):
            block_comment_depth = 1
            index += 2
        elif value.startswith("//", index) or value[index] == "#":
            newline = value.find("\n", index)
            index = len(value) if newline == -1 else newline + 1
        elif value[index] in {'"', "'"}:
            nested_literal, index = _scan_hcl_quoted_string(value, index)
            found_literal = found_literal or nested_literal
        elif HCL_HEREDOC.match(value, index):
            return len(value), True
        elif value[index] == "{":
            depth += 1
            index += 1
        elif value[index] == "}":
            depth -= 1
            index += 1
        else:
            index += 1
    return index, found_literal


def _hcl_position_is_in_comment_or_string(text: str, position: int) -> bool:
    state = HclHostnameState()
    heredoc_stack: list[tuple[str, bool, HclHostnameState]] = []
    current_line_comment = False
    lines = text[:position].split("\n")
    for line_index, line in enumerate(lines):
        is_current_line = line_index == len(lines) - 1
        if heredoc_stack:
            terminator, allows_indent, heredoc_state = heredoc_stack[-1]
            is_terminator = (
                line.lstrip(" \t") == terminator
                if allows_indent
                else line == terminator
            )
            if is_terminator:
                heredoc_stack.pop()
                continue
            if is_current_line:
                return True
            _, opened_heredoc, current_line_comment = (
                _hcl_hostname_source(line, heredoc_state)
            )
        else:
            _, opened_heredoc, current_line_comment = (
                _hcl_hostname_source(line, state)
            )
        if opened_heredoc is not None:
            heredoc_stack.append(
                (*opened_heredoc, HclHostnameState(in_heredoc=True))
            )
    return bool(
        heredoc_stack
        or current_line_comment
        or state.block_comment_depth
        or state.expression_comment_depth
        or state.expression_string
        or (state.in_string and state.expression_depth == 0)
    )


def _hcl_expression_exposes_literal(text: str, start: int) -> bool:
    delimiter_depth = 0
    block_comment_depth = 0
    saw_value = False
    index = start
    while index < len(text):
        if block_comment_depth > 0:
            if text.startswith("/*", index):
                block_comment_depth += 1
                index += 2
            elif text.startswith("*/", index):
                block_comment_depth -= 1
                index += 2
            else:
                index += 1
        elif text.startswith("/*", index):
            block_comment_depth = 1
            index += 2
        elif text.startswith("//", index) or text[index] == "#":
            newline = text.find("\n", index)
            if saw_value and delimiter_depth == 0:
                return False
            index = len(text) if newline == -1 else newline + 1
        elif heredoc_match := HCL_HEREDOC.match(text, index):
            return True
        elif text[index] in {'"', "'"}:
            exposes_literal, index = _scan_hcl_quoted_string(text, index)
            if exposes_literal:
                return True
            saw_value = True
        elif text[index] in "([{":
            delimiter_depth += 1
            saw_value = True
            index += 1
        elif text[index] in ")]}" and delimiter_depth > 0:
            delimiter_depth -= 1
            saw_value = True
            index += 1
        elif text[index] == "," and delimiter_depth == 0:
            return False
        elif text[index] == "\n" and delimiter_depth == 0:
            if saw_value:
                return False
            index += 1
        elif text[index].isspace():
            index += 1
        else:
            saw_value = True
            index += 1
    return False


def _json_contains_static_named_secret(value: object) -> bool:
    if isinstance(value, JsonObject):
        for key, child in value.pairs:
            is_secret_name = bool(
                AWS_SECRET_ACCESS_KEY_NAME.fullmatch(key)
                or NAMED_SECRET_NAME.fullmatch(key)
            )
            if is_secret_name and _json_value_contains_static_literal(child):
                return True
            if _json_contains_static_named_secret(child):
                return True
    elif isinstance(value, dict):
        return _json_contains_static_named_secret(
            JsonObject(tuple(value.items()))
        )
    elif isinstance(value, list):
        return any(_json_contains_static_named_secret(child) for child in value)
    return False


def _json_value_contains_static_literal(value: object) -> bool:
    if isinstance(value, str):
        return _hcl_value_is_static_literal(json.dumps(value))
    if isinstance(value, JsonObject):
        return any(
            _json_value_contains_static_literal(child)
            for _, child in value.pairs
        )
    if isinstance(value, dict):
        return _json_value_contains_static_literal(
            JsonObject(tuple(value.items()))
        )
    if isinstance(value, list):
        return any(_json_value_contains_static_literal(child) for child in value)
    return value is not None


def _hcl_hostname_source(
    line: str, state: HclHostnameState
) -> tuple[str, tuple[str, bool] | None, bool]:
    literal: list[str] = []
    heredoc = None
    line_comment = False
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
            elif line.startswith("$${", index):
                literal.append("${")
                index += 3
            elif line.startswith("%%{", index):
                literal.append("%{")
                index += 3
            elif line.startswith(("${", "%{"), index):
                state.expression_string_return_depths.append(
                    state.expression_depth
                )
                state.expression_depth += 1
                state.expression_string = False
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
                line_comment = True
                break
            elif line[index] == "#":
                literal.append(line[index + 1 :])
                line_comment = True
                break
            elif heredoc_match := HCL_HEREDOC.match(line, index):
                heredoc = (
                    heredoc_match.group("terminator"),
                    heredoc_match.group("allows_indent") == "-",
                )
                index = heredoc_match.end()
            elif line[index] == '"':
                state.expression_string = True
                index += 1
            elif line[index] == "{":
                state.expression_depth += 1
                index += 1
            elif line[index] == "}":
                state.expression_depth -= 1
                if (
                    state.expression_string_return_depths
                    and state.expression_depth
                    == state.expression_string_return_depths[-1]
                ):
                    state.expression_string_return_depths.pop()
                    state.expression_string = True
                index += 1
            else:
                index += 1
        elif state.in_heredoc:
            if line.startswith("$${", index):
                literal.append("${")
                index += 3
            elif line.startswith("%%{", index):
                literal.append("%{")
                index += 3
            elif line.startswith(("${", "%{"), index):
                state.expression_depth = 1
                index += 2
            else:
                literal.append(line[index])
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
            line_comment = True
            break
        elif line[index] == "#":
            literal.append(line[index + 1 :])
            line_comment = True
            break
        elif line[index] == '"':
            state.in_string = True
            index += 1
        elif heredoc_match := HCL_HEREDOC.match(line, index):
            heredoc = (
                heredoc_match.group("terminator"),
                heredoc_match.group("allows_indent") == "-",
            )
            index = heredoc_match.end()
        else:
            index += 1
    return "".join(literal), heredoc, line_comment


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
        json_was_parsed = False
        if path.suffix == ".json":
            try:
                json_value = json.loads(
                    text,
                    object_pairs_hook=lambda pairs: JsonObject(tuple(pairs)),
                )
            except json.JSONDecodeError:
                pass
            else:
                json_was_parsed = True
                if _json_contains_static_named_secret(json_value):
                    findings.append(Finding(relative, 0, "named-secret-format"))
        if path.suffix != ".json" or not json_was_parsed:
            for assignment_pattern, assignment_rule in (
                (
                    AWS_SECRET_ACCESS_KEY_ASSIGNMENT,
                    "aws-secret-access-key-assignment",
                ),
                (NAMED_SECRET_ASSIGNMENT, "named-secret-format"),
            ):
                for assignment_match in assignment_pattern.finditer(text):
                    value_start = _assignment_value_start(
                        text, assignment_match
                    )
                    if value_start is None:
                        continue
                    assignment_line = (
                        text.count("\n", 0, assignment_match.start()) + 1
                    )
                    if _assignment_exposes_literal(
                        path, text, assignment_match, value_start
                    ):
                        findings.append(
                            Finding(relative, assignment_line, assignment_rule)
                        )
        in_example = pathlib.PurePosixPath(relative).parts[:1] == ("examples",)
        in_module = pathlib.PurePosixPath(relative).parts[:1] == ("modules",)
        in_metadata_scope = in_example or (in_module and path.suffix == ".tf")
        heredoc_stack: list[tuple[str, bool, HclHostnameState]] = []
        hcl_hostname_state = HclHostnameState()
        for line_number, line in enumerate(text.splitlines(), start=1):
            if PRIVATE_KEY.search(line):
                findings.append(Finding(relative, line_number, "private-key-marker"))
            if AWS_ACCESS_KEY.search(line):
                findings.append(Finding(relative, line_number, "aws-secret-format"))
            if GITHUB_TOKEN.search(line):
                findings.append(Finding(relative, line_number, "github-secret-format"))
            if AGE_SECRET_KEY.search(line):
                findings.append(Finding(relative, line_number, "age-secret-format"))

            for match in EMAIL.finditer(line):
                if not _is_permitted_domain(match.group(1)):
                    findings.append(Finding(relative, line_number, "non-public-email-domain"))

            if in_metadata_scope:
                without_emails = EMAIL.sub("", line)
                hostname_source = without_emails
                if path.suffix in {".tf", ".hcl"}:
                    if heredoc_stack:
                        terminator, allows_indent, heredoc_hostname_state = (
                            heredoc_stack[-1]
                        )
                        is_terminator = (
                            line.lstrip(" \t") == terminator
                            if allows_indent
                            else line == terminator
                        )
                        if is_terminator:
                            heredoc_stack.pop()
                            hostname_source = ""
                        else:
                            (
                                hostname_source,
                                opened_heredoc,
                                _,
                            ) = _hcl_hostname_source(
                                without_emails, heredoc_hostname_state
                            )
                            if opened_heredoc is not None:
                                heredoc_stack.append(
                                    (
                                        *opened_heredoc,
                                        HclHostnameState(in_heredoc=True),
                                    )
                                )
                    else:
                        (
                            hostname_source,
                            opened_heredoc,
                            _,
                        ) = _hcl_hostname_source(
                            without_emails, hcl_hostname_state
                        )
                        if opened_heredoc is not None:
                            heredoc_stack.append(
                                (
                                    *opened_heredoc,
                                    HclHostnameState(in_heredoc=True),
                                )
                            )
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
