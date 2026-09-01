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
class HclExpressionFrame:
    opener: str
    function_name: str | None = None
    argument_index: int = 0
    selector_context: bool = False
    expecting_object_key: bool = False


@dataclasses.dataclass(frozen=True)
class HclHeredocMatch:
    terminator: str
    allows_indent: bool
    end: int


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
ASSET_PATH_EXTENSION = re.compile(
    r"(?i)(?<![:/])/([A-Za-z0-9.-]+)\.(?:gif|ico|jpe?g|png|svg|webp)(?=[/?#\s\"']|$)"
)
CLOUDFLARE_ID = re.compile(r"\b[0-9a-fA-F]{32}\b")
PROVIDER_BLOCK = re.compile(r"\bprovider\s+\"")
BACKEND_BLOCK = re.compile(r"\bbackend\s+\"")
HCL_NUMBER_LITERAL = re.compile(
    r"[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
)


def _is_permitted_domain(domain: str) -> bool:
    domain = domain.lower()
    return (
        domain == "example.com"
        or domain.endswith(".example.com")
        or domain == "users.noreply.github.com"
        or domain == "2.0.192.in-addr.arpa"
        or domain.endswith(".2.0.192.in-addr.arpa")
    )


def _relative_path(root: pathlib.Path, path: pathlib.Path) -> str:
    return path.relative_to(root).as_posix()


def _is_hcl_path(path: pathlib.Path) -> bool:
    return path.suffix in {".tf", ".hcl", ".tfvars"} or path.name.endswith(
        (".tf.json", ".tfvars.json", ".tftest.json", ".tfmock.json")
    )


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


def _hcl_template_contains_static_literal(value: str) -> bool:
    saw_dynamic = False
    index = 0
    while index < len(value):
        if value.startswith(("$${", "%%{"), index):
            return True
        if value.startswith(("${", "%{"), index):
            saw_dynamic = True
            end, _ = _scan_hcl_template_expression(value, index + 2)
            if end <= index + 2 or value[end - 1 : end] != "}":
                return True
            if _hcl_expression_exposes_literal(
                value[index + 2 : end - 1], 0
            ):
                return True
            index = end
            continue
        return True
    return bool(value) and not saw_dynamic


def _iter_hcl_template_expression_spans(value: str):
    index = 0
    while index < len(value):
        if value.startswith(("$${", "%%{"), index):
            index += 3
        elif value.startswith(("${", "%{"), index):
            expression_start = index + 2
            end, _ = _scan_hcl_template_expression(
                value, expression_start
            )
            if end <= expression_start or value[end - 1 : end] != "}":
                return
            yield expression_start, end - 1
            index = end
        else:
            index += 1


def _scan_hcl_quoted_string(value: str, start: int) -> tuple[bool, int]:
    quote = value[start]
    if quote == "'":
        end = value.find("'", start + 1)
        return True, len(value) if end == -1 else end + 1

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
            expression_start = index + 2
            index, _ = _scan_hcl_template_expression(value, expression_start)
            nested_literal = (
                index <= expression_start
                or value[index - 1 : index] != "}"
                or _hcl_expression_exposes_literal(
                    value[expression_start : index - 1], 0
                )
            )
            has_literal_segment = has_literal_segment or nested_literal
        elif value[index] == '"':
            return has_literal_segment, index + 1
        else:
            has_literal_segment = True
            index += 1
    return True, len(value)


def _decode_hcl_quoted_escape(value: str, start: int) -> tuple[str, int]:
    simple_escapes = {
        "n": "\n",
        "r": "\r",
        "t": "\t",
        '"': '"',
        "\\": "\\",
    }
    if start + 1 >= len(value):
        return "\\", start + 1

    escape = value[start + 1]
    if escape in simple_escapes:
        return simple_escapes[escape], start + 2

    digit_count = {"u": 4, "U": 8}.get(escape)
    if digit_count is not None:
        end = start + 2 + digit_count
        digits = value[start + 2 : end]
        if len(digits) == digit_count and re.fullmatch(
            rf"[0-9A-Fa-f]{{{digit_count}}}", digits
        ):
            codepoint = int(digits, 16)
            if codepoint <= 0x10FFFF and not 0xD800 <= codepoint <= 0xDFFF:
                return chr(codepoint), end

    return value[start : start + 2], start + 2


def _decode_hcl_quoted_candidate(
    text: str, quote_start: int
) -> tuple[str, int] | None:
    decoded: list[str] = []
    index = quote_start + 1
    while index < len(text):
        if text.startswith(("${", "%{"), index):
            return None
        if text[index] == "\\":
            character, index = _decode_hcl_quoted_escape(text, index)
            decoded.append(character)
        elif text.startswith("$${", index):
            decoded.append("${")
            index += 3
        elif text.startswith("%%{", index):
            decoded.append("%{")
            index += 3
        elif text[index] == '"':
            return "".join(decoded), index + 1
        else:
            decoded.append(text[index])
            index += 1
    return None


def _scan_hcl_heredoc_literal(
    value: str, start: int, match: HclHeredocMatch
) -> tuple[bool, int]:
    opener_end = value.find("\n", match.end)
    if opener_end == -1:
        return True, len(value)

    terminator = match.terminator
    allows_indent = match.allows_indent
    body_start = opener_end + 1
    line_start = body_start
    while line_start <= len(value):
        line_end = value.find("\n", line_start)
        if line_end == -1:
            line_end = len(value)
        line = value[line_start:line_end].removesuffix("\r")
        is_terminator = (
            line.lstrip(" \t") == terminator
            if allows_indent
            else line == terminator
        )
        if is_terminator:
            return line_start > body_start, line_end
        if line_end == len(value):
            break
        line_start = line_end + 1
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
        elif heredoc_match := _match_hcl_heredoc(value, index):
            exposes_literal, index = _scan_hcl_heredoc_literal(
                value, index, heredoc_match
            )
            found_literal = found_literal or exposes_literal
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
                _, _, current_line_comment = _hcl_hostname_source(
                    line, heredoc_state
                )
                return bool(
                    current_line_comment
                    or heredoc_state.expression_comment_depth
                    or heredoc_state.expression_string
                    or (
                        heredoc_state.in_heredoc
                        and heredoc_state.expression_depth == 0
                    )
                )
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
    frames: list[HclExpressionFrame] = []
    block_comment_depth = 0
    conditional_predicate_positions = _hcl_conditional_predicate_map(
        text[start:]
    )
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
            next_line = len(text) if newline == -1 else newline + 1
            if (
                saw_value
                and not frames
                and not _hcl_expression_continues_at(text, next_line)
            ):
                return False
            _hcl_maybe_start_next_object_entry(
                text,
                index,
                frames,
                next_position=next_line,
            )
            index = next_line
        elif heredoc_match := _match_hcl_heredoc(text, index):
            exposes_literal, index = _scan_hcl_heredoc_literal(
                text, index, heredoc_match
            )
            if exposes_literal:
                return True
            saw_value = True
        elif text[index] in {'"', "'"}:
            exposes_literal, string_end = _scan_hcl_quoted_string(
                text, index
            )
            if (
                exposes_literal
                and not _hcl_string_is_selector(frames)
                and (
                    not _hcl_string_is_object_key(
                        text, string_end, frames
                    )
                    or _hcl_object_key_can_flow_to_value(frames)
                )
            ):
                return True
            index = string_end
            saw_value = True
        elif scalar_end := _hcl_scalar_literal_end(text, index):
            if (
                not _hcl_scalar_is_control_position(
                    index,
                    frames,
                    conditional_predicate_positions,
                    position_offset=start,
                )
                and not (
                    _hcl_token_is_object_key(
                        text, scalar_end, frames
                    )
                    and not _hcl_object_key_can_flow_to_value(frames)
                )
            ):
                return True
            index = scalar_end
            saw_value = True
        elif text[index] in "([{":
            selector_context = _hcl_scalar_is_selector(frames) or (
                text[index] == "("
                and bool(frames)
                and frames[-1].opener == "{"
                and frames[-1].expecting_object_key
            )
            function_name = (
                _hcl_function_name_before(text, index)
                if text[index] == "("
                else None
            )
            is_index = (
                text[index] == "["
                and _hcl_bracket_opens_index(text, index)
            )
            frames.append(
                HclExpressionFrame(
                    opener="index" if is_index else text[index],
                    function_name=function_name,
                    selector_context=selector_context,
                    expecting_object_key=text[index] == "{",
                )
            )
            saw_value = True
            index += 1
        elif text[index] in ")]}" and frames:
            frames.pop()
            saw_value = True
            index += 1
        elif text[index] == ",":
            if not frames:
                return False
            if frames[-1].opener == "{":
                frames[-1].expecting_object_key = True
            else:
                frames[-1].argument_index += 1
            index += 1
        elif (
            text[index] in "=:"
            and frames
            and frames[-1].opener == "{"
            and frames[-1].expecting_object_key
            and not text.startswith("==", index)
        ):
            frames[-1].expecting_object_key = False
            index += 1
        elif text[index] == "\n":
            if not frames:
                if saw_value and not _hcl_expression_continues_at(
                    text, index + 1
                ):
                    return False
            else:
                _hcl_maybe_start_next_object_entry(
                    text,
                    index,
                    frames,
                    next_position=index + 1,
                )
            index += 1
        elif text[index].isspace():
            index += 1
        else:
            saw_value = True
            index += 1
    return False


def _hcl_scalar_literal_end(text: str, start: int) -> int | None:
    if start > 0:
        previous = text[start - 1]
        if previous.isalnum() or previous in "_.":
            return None
        if (
            previous == "-"
            and start > 1
            and (text[start - 2].isalnum() or text[start - 2] in "_-")
        ):
            return None

    for value in ("true", "false"):
        if text.startswith(value, start):
            end = start + len(value)
            if end == len(text) or not (
                text[end].isalnum() or text[end] in "_-"
            ):
                return end

    match = HCL_NUMBER_LITERAL.match(text, start)
    if match is None:
        return None
    end = match.end()
    if end < len(text) and (text[end].isalnum() or text[end] == "_"):
        return None
    return end


def _hcl_scalar_is_control_position(
    start: int,
    frames: list[HclExpressionFrame],
    conditional_predicate_positions: bytearray,
    *,
    position_offset: int,
) -> bool:
    return bool(
        _hcl_scalar_is_selector(frames)
        or conditional_predicate_positions[start - position_offset]
    )


def _hcl_conditional_predicate_map(text: str) -> bytearray:
    interval_events = [0] * (len(text) + 1)
    openers: list[str] = []
    segment_starts = [0]
    pending_conditionals = [0]
    for_expressions = [False]
    for_filter_starts: list[int | None] = [None]
    block_comment_depth = 0
    index = 0
    while index < len(text):
        if block_comment_depth:
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
            index = len(text) if newline == -1 else newline + 1
        elif text[index] in {'"', "'"}:
            _, index = _scan_hcl_quoted_string(text, index)
        elif heredoc_match := _match_hcl_heredoc(text, index):
            _, index = _scan_hcl_heredoc_literal(
                text, index, heredoc_match
            )
        elif text[index] in "([{":
            openers.append(text[index])
            segment_starts.append(index + 1)
            pending_conditionals.append(0)
            for_expressions.append(False)
            for_filter_starts.append(None)
            index += 1
        elif text[index] in ")]}":
            if openers:
                if for_filter_starts[-1] is not None:
                    interval_events[for_filter_starts[-1]] += 1
                    interval_events[index] -= 1
                openers.pop()
                segment_starts.pop()
                pending_conditionals.pop()
                for_expressions.pop()
                for_filter_starts.pop()
            index += 1
        elif text[index] == "_" or text[index].isidentifier():
            identifier_start = index
            index += 1
            while index < len(text) and (
                text[index] == "-"
                or ("a" + text[index]).isidentifier()
            ):
                index += 1
            identifier = text[identifier_start:index]
            if openers and openers[-1] in "[{":
                if identifier == "for":
                    for_expressions[-1] = True
                elif identifier == "if" and for_expressions[-1]:
                    for_filter_starts[-1] = index
        elif text[index] == "?":
            interval_events[segment_starts[-1]] += 1
            interval_events[index] -= 1
            pending_conditionals[-1] += 1
            segment_starts[-1] = index + 1
            index += 1
        elif text[index] == ":":
            if pending_conditionals[-1]:
                pending_conditionals[-1] -= 1
            segment_starts[-1] = index + 1
            index += 1
        elif text[index] == ",":
            segment_starts[-1] = index + 1
            index += 1
        elif (
            text[index] == "="
            and openers
            and openers[-1] == "{"
            and not text.startswith(("==", "=>"), index)
        ):
            segment_starts[-1] = index + 1
            index += 1
        elif (
            text[index] == "\n"
            and not _hcl_expression_continues_at(text, index + 1)
        ):
            segment_starts[-1] = index + 1
            index += 1
        else:
            index += 1

    positions = bytearray(len(text))
    active_intervals = 0
    for position in range(len(text)):
        active_intervals += interval_events[position]
        positions[position] = active_intervals > 0
    return positions


def _hcl_function_name_before(text: str, position: int) -> str | None:
    significant = _hcl_previous_significant_position(text, position)
    if significant is None:
        return None
    index = significant
    end = index + 1
    while index >= 0 and (
        text[index].isalnum() or text[index] in "_-:"
    ):
        index -= 1
    return text[index + 1 : end] or None


def _match_hcl_heredoc(
    text: str, start: int
) -> HclHeredocMatch | None:
    if not text.startswith("<<", start):
        return None
    index = start + 2
    allows_indent = index < len(text) and text[index] == "-"
    if allows_indent:
        index += 1
    if index >= len(text) or not (
        text[index] == "_" or text[index].isidentifier()
    ):
        return None
    terminator_start = index
    index += 1
    while index < len(text) and (
        text[index] == "-" or ("a" + text[index]).isidentifier()
    ):
        index += 1
    if index < len(text) and text[index] not in "\r\n":
        return None
    return HclHeredocMatch(
        terminator=text[terminator_start:index],
        allows_indent=allows_indent,
        end=index,
    )


def _hcl_maybe_start_next_object_entry(
    text: str,
    position: int,
    frames: list[HclExpressionFrame],
    *,
    next_position: int,
) -> None:
    if (
        not frames
        or frames[-1].opener != "{"
        or frames[-1].expecting_object_key
    ):
        return
    previous = _hcl_previous_significant_character(text, position)
    if (
        previous is not None
        and previous not in "?=:,+-*/%&|!<>.([{"
        and not _hcl_expression_continues_at(text, next_position)
    ):
        frames[-1].expecting_object_key = True


def _hcl_previous_significant_character(
    text: str, position: int
) -> str | None:
    index = _hcl_previous_significant_position(text, position)
    return None if index is None else text[index]


def _hcl_previous_significant_position(
    text: str, position: int
) -> int | None:
    last_significant: int | None = None
    block_comment_depth = 0
    quote: str | None = None
    index = 0
    while index < position:
        if block_comment_depth:
            if text.startswith("/*", index):
                block_comment_depth += 1
                index += 2
            elif text.startswith("*/", index):
                block_comment_depth -= 1
                index += 2
            else:
                index += 1
        elif quote is not None:
            last_significant = index
            if text[index] == "\\" and index + 1 < position:
                index += 2
            elif text[index] == quote:
                quote = None
                index += 1
            else:
                index += 1
        elif text.startswith("/*", index):
            block_comment_depth = 1
            index += 2
        elif text.startswith("//", index) or text[index] == "#":
            newline = text.find("\n", index, position)
            index = position if newline == -1 else newline + 1
        elif text[index] in {'"', "'"}:
            quote = text[index]
            last_significant = index
            index += 1
        elif text[index].isspace():
            index += 1
        else:
            last_significant = index
            index += 1
    return last_significant


def _hcl_next_significant_position(
    text: str, position: int
) -> int | None:
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if text.startswith("/*", position):
            depth = 1
            position += 2
            while position < len(text) and depth:
                if text.startswith("/*", position):
                    depth += 1
                    position += 2
                elif text.startswith("*/", position):
                    depth -= 1
                    position += 2
                else:
                    position += 1
            continue
        if text.startswith("//", position) or (
            position < len(text) and text[position] == "#"
        ):
            newline = text.find("\n", position)
            position = len(text) if newline == -1 else newline + 1
            continue
        return position
    return None


def _hcl_expression_continues_at(text: str, position: int) -> bool:
    position = _hcl_next_significant_position(text, position)
    return (
        position is not None
        and text[position] in "?=:,+-*/%&|!<>.(["
    )


def _hcl_bracket_opens_index(text: str, position: int) -> bool:
    previous = _hcl_previous_significant_character(text, position)
    return previous is not None and (
        previous.isalnum() or previous in "_.)]}"
    )


def _hcl_string_is_selector(
    frames: list[HclExpressionFrame],
) -> bool:
    if not frames:
        return False
    frame = frames[-1]
    return bool(
        frame.selector_context
        or frame.opener == "index"
        or (
            frame.function_name == "lookup"
            and frame.argument_index == 1
        )
    )


def _hcl_scalar_is_selector(
    frames: list[HclExpressionFrame],
) -> bool:
    if _hcl_string_is_selector(frames):
        return True
    if not frames:
        return False
    frame = frames[-1]
    control_arguments = {
        "element": {1},
        "slice": {1, 2},
        "substr": {1, 2},
    }
    return bool(
        frame.function_name in control_arguments
        and frame.argument_index
        in control_arguments[frame.function_name]
    )


def _hcl_string_is_object_key(
    text: str, string_end: int, frames: list[HclExpressionFrame]
) -> bool:
    return _hcl_token_is_object_key(text, string_end, frames)


def _hcl_object_key_can_flow_to_value(
    frames: list[HclExpressionFrame],
) -> bool:
    return any(frame.function_name == "keys" for frame in frames[:-1])


def _hcl_token_is_object_key(
    text: str, token_end: int, frames: list[HclExpressionFrame]
) -> bool:
    if (
        not frames
        or frames[-1].opener != "{"
        or not frames[-1].expecting_object_key
    ):
        return False
    index = _hcl_next_significant_position(text, token_end)
    return index is not None and (
        text[index] == ":"
        or (text[index] == "=" and not text.startswith("==", index))
    )


def _iter_decoded_hcl_quoted_assignments(
    text: str,
    structural_quote_starts: frozenset[int] | None = None,
):
    if structural_quote_starts is None:
        structural_quote_starts = _hcl_structural_quote_starts(text)
    for quote_start in sorted(structural_quote_starts):
        candidate = _decode_hcl_quoted_candidate(text, quote_start)
        if candidate is None:
            continue
        decoded_name, string_end = candidate
        if not (
            AWS_SECRET_ACCESS_KEY_NAME.fullmatch(decoded_name)
            or NAMED_SECRET_NAME.fullmatch(decoded_name)
        ):
            continue
        operator = _hcl_quoted_key_operator(
            text, quote_start, string_end
        )
        if (
            decoded_name is not None
            and operator is not None
        ):
            value_start = _hcl_next_significant_position(text, operator + 1)
            if value_start is not None:
                yield (
                    decoded_name,
                    value_start,
                    _hcl_object_value_end(text, value_start),
                    text.count("\n", 0, quote_start) + 1,
                )


def _hcl_static_secret_assignment_rules(text: str) -> tuple[str, ...]:
    rules: set[str] = set()
    structural_quote_starts = _hcl_structural_quote_starts(text)
    for assignment_pattern, assignment_rule in (
        (
            AWS_SECRET_ACCESS_KEY_ASSIGNMENT,
            "aws-secret-access-key-assignment",
        ),
        (NAMED_SECRET_ASSIGNMENT, "named-secret-format"),
    ):
        for assignment_match in assignment_pattern.finditer(text):
            if (
                text[assignment_match.start()] in {'"', "'"}
                and assignment_match.start() in structural_quote_starts
            ):
                continue
            value_start = _assignment_value_start(text, assignment_match)
            if value_start is None:
                continue
            if _hcl_position_is_in_comment_or_string(
                text, assignment_match.start()
            ) or _hcl_expression_exposes_literal(text, value_start):
                rules.add(assignment_rule)

    for decoded_name, value_start, value_end, _ in (
        _iter_decoded_hcl_quoted_assignments(
            text, structural_quote_starts
        )
    ):
        if AWS_SECRET_ACCESS_KEY_NAME.fullmatch(decoded_name):
            assignment_rule = "aws-secret-access-key-assignment"
        elif NAMED_SECRET_NAME.fullmatch(decoded_name):
            assignment_rule = "named-secret-format"
        else:
            continue
        if _hcl_expression_exposes_literal(
            text[value_start:value_end], 0
        ):
            rules.add(assignment_rule)
    return tuple(sorted(rules))


def _hcl_quoted_key_operator(
    text: str, quote_start: int, string_end: int
) -> int | None:
    operator = _hcl_next_significant_position(text, string_end)
    context_start = quote_start
    while (
        operator is not None
        and operator < len(text)
        and text[operator] == ")"
    ):
        opening = _hcl_previous_significant_position(text, context_start)
        if opening is None or text[opening] != "(":
            return None
        before_opening = _hcl_previous_significant_character(text, opening)
        if before_opening is not None and (
            before_opening.isalnum() or before_opening in "_.)]}"
        ):
            return None
        context_start = opening
        operator = _hcl_next_significant_position(text, operator + 1)

    if (
        operator is None
        or operator >= len(text)
        or text[operator] not in "=:"
        or text.startswith("==", operator)
    ):
        return None
    previous = _hcl_previous_significant_character(text, context_start)
    if text[operator] == ":" and previous == "?":
        return None
    return operator


def _hcl_object_value_end(text: str, start: int) -> int:
    frames: list[str] = []
    block_comment_depth = 0
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
            if not frames:
                return len(text) if newline == -1 else newline
            index = len(text) if newline == -1 else newline + 1
        elif text[index] in {'"', "'"}:
            _, index = _scan_hcl_quoted_string(text, index)
        elif heredoc_match := _match_hcl_heredoc(text, index):
            _, index = _scan_hcl_heredoc_literal(
                text, index, heredoc_match
            )
        elif text[index] in "([{":
            frames.append(text[index])
            index += 1
        elif text[index] in ")]}":
            if not frames:
                return index
            frames.pop()
            index += 1
        elif text[index] == "," and not frames:
            return index
        elif text[index] == "\n" and not frames:
            if not _hcl_expression_continues_at(text, index + 1):
                return index
            index += 1
        else:
            index += 1
    return len(text)


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
        return _hcl_template_contains_static_literal(value)
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


def _iter_json_strings(value: object):
    if isinstance(value, str):
        yield value, True
    elif isinstance(value, JsonObject):
        for key, child in value.pairs:
            yield key, False
            yield from _iter_json_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_json_strings(child)


def _decoded_json_source(
    path: pathlib.Path, decoded: str, is_expression: bool
) -> str:
    if not is_expression or not _is_hcl_path(path):
        return decoded
    state = HclHostnameState(in_heredoc=True)
    heredoc_stack: list[tuple[str, bool, HclHostnameState]] = []
    sources: list[str] = []
    for line in decoded.splitlines():
        if heredoc_stack:
            terminator, allows_indent, heredoc_state = heredoc_stack[-1]
            is_terminator = (
                line.lstrip(" \t") == terminator
                if allows_indent
                else line == terminator
            )
            if is_terminator:
                heredoc_stack.pop()
                sources.append("")
                continue
            source, opened_heredoc, _ = _hcl_hostname_source(
                line, heredoc_state
            )
        else:
            source, opened_heredoc, _ = _hcl_hostname_source(line, state)
        sources.append(source)
        if opened_heredoc is not None:
            heredoc_stack.append(
                (*opened_heredoc, HclHostnameState(in_heredoc=True))
            )
    return " ".join(sources)


def _hcl_hostname_source(
    line: str,
    state: HclHostnameState,
    structural_quote_starts: list[int] | None = None,
    line_offset: int = 0,
) -> tuple[str, tuple[str, bool] | None, bool]:
    literal: list[str] = []
    heredoc = None
    line_comment = False
    index = 0
    while index < len(line):
        if state.block_comment_depth > 0:
            if line.startswith("/*", index):
                literal.append(" ")
                state.block_comment_depth += 1
                index += 2
            elif line.startswith("*/", index):
                state.block_comment_depth -= 1
                if state.block_comment_depth == 0:
                    literal.append(" ")
                index += 2
            else:
                literal.append(line[index])
                index += 1
        elif state.expression_comment_depth > 0:
            if line.startswith("/*", index):
                literal.append(" ")
                state.expression_comment_depth += 1
                index += 2
            elif line.startswith("*/", index):
                state.expression_comment_depth -= 1
                if state.expression_comment_depth == 0:
                    literal.append(" ")
                index += 2
            else:
                literal.append(line[index])
                index += 1
        elif state.expression_string:
            if line[index] == "\\" and index + 1 < len(line):
                decoded, index = _decode_hcl_quoted_escape(line, index)
                literal.append(decoded)
            elif line.startswith("$${", index):
                literal.append("${")
                index += 3
            elif line.startswith("%%{", index):
                literal.append("%{")
                index += 3
            elif line.startswith(("${", "%{"), index):
                literal.append(" ")
                state.expression_string_return_depths.append(
                    state.expression_depth
                )
                state.expression_depth += 1
                state.expression_string = False
                index += 2
            elif line[index] == '"':
                state.expression_string = False
                literal.append(" ")
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
            elif heredoc_match := _match_hcl_heredoc(line, index):
                heredoc = (
                    heredoc_match.terminator,
                    heredoc_match.allows_indent,
                )
                index = heredoc_match.end
            elif line[index] == '"':
                if structural_quote_starts is not None:
                    structural_quote_starts.append(line_offset + index)
                state.expression_string = True
                index += 1
            elif line[index] == "{":
                state.expression_depth += 1
                index += 1
            elif line[index] == "}":
                state.expression_depth -= 1
                expression_ended = state.expression_depth == 0
                if (
                    state.expression_string_return_depths
                    and state.expression_depth
                    == state.expression_string_return_depths[-1]
                ):
                    state.expression_string_return_depths.pop()
                    state.expression_string = True
                    expression_ended = True
                if expression_ended:
                    literal.append(" ")
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
                literal.append(" ")
                state.expression_depth = 1
                index += 2
            else:
                literal.append(line[index])
                index += 1
        elif state.in_string:
            if line[index] == "\\" and index + 1 < len(line):
                decoded, index = _decode_hcl_quoted_escape(line, index)
                literal.append(decoded)
            elif line.startswith("$${", index):
                literal.append("${")
                index += 3
            elif line.startswith("%%{", index):
                literal.append("%{")
                index += 3
            elif line.startswith(("${", "%{"), index):
                literal.append(" ")
                state.expression_depth = 1
                index += 2
            elif line[index] == '"':
                state.in_string = False
                literal.append(" ")
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
            if structural_quote_starts is not None:
                structural_quote_starts.append(line_offset + index)
            state.in_string = True
            index += 1
        elif heredoc_match := _match_hcl_heredoc(line, index):
            heredoc = (
                heredoc_match.terminator,
                heredoc_match.allows_indent,
            )
            index = heredoc_match.end
        else:
            index += 1
    return "".join(literal), heredoc, line_comment


def _hcl_structural_quote_starts(text: str) -> frozenset[int]:
    quote_starts: list[int] = []
    state = HclHostnameState()
    heredoc_stack: list[tuple[str, bool, HclHostnameState]] = []
    offset = 0
    for raw_line in text.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        if heredoc_stack:
            terminator, allows_indent, heredoc_state = heredoc_stack[-1]
            is_terminator = (
                line.lstrip(" \t") == terminator
                if allows_indent
                else line == terminator
            )
            if is_terminator:
                heredoc_stack.pop()
                offset += len(raw_line)
                continue
            _, opened_heredoc, _ = _hcl_hostname_source(
                line,
                heredoc_state,
                quote_starts,
                offset,
            )
        else:
            _, opened_heredoc, _ = _hcl_hostname_source(
                line,
                state,
                quote_starts,
                offset,
            )
        if opened_heredoc is not None:
            heredoc_stack.append(
                (*opened_heredoc, HclHostnameState(in_heredoc=True))
            )
        offset += len(raw_line)
    return frozenset(quote_starts)


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
        decoded_json_sources: tuple[str, ...] = ()
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
                decoded_json_sources = tuple(
                    _decoded_json_source(path, decoded, is_expression)
                    for decoded, is_expression in _iter_json_strings(
                        json_value
                    )
                )
                if _is_hcl_path(path):
                    for decoded, is_expression in _iter_json_strings(
                        json_value
                    ):
                        if not is_expression:
                            continue
                        for expression_start, expression_end in (
                            _iter_hcl_template_expression_spans(decoded)
                        ):
                            expression = decoded[
                                expression_start:expression_end
                            ]
                            for assignment_rule in (
                                _hcl_static_secret_assignment_rules(
                                    expression
                                )
                            ):
                                findings.append(
                                    Finding(relative, 0, assignment_rule)
                                )
                for decoded_source in decoded_json_sources:
                    for assignment_pattern, assignment_rule in (
                        (
                            AWS_SECRET_ACCESS_KEY_ASSIGNMENT,
                            "aws-secret-access-key-assignment",
                        ),
                        (NAMED_SECRET_ASSIGNMENT, "named-secret-format"),
                    ):
                        for assignment_match in assignment_pattern.finditer(
                            decoded_source
                        ):
                            if _assignment_value_start(
                                decoded_source, assignment_match
                            ) is not None:
                                findings.append(
                                    Finding(relative, 0, assignment_rule)
                                )
                    for pattern, rule in (
                        (PRIVATE_KEY, "private-key-marker"),
                        (AWS_ACCESS_KEY, "aws-secret-format"),
                        (GITHUB_TOKEN, "github-secret-format"),
                        (AGE_SECRET_KEY, "age-secret-format"),
                    ):
                        if pattern.search(decoded_source):
                            findings.append(Finding(relative, 0, rule))
                    for match in EMAIL.finditer(decoded_source):
                        if not _is_permitted_domain(match.group(1)):
                            findings.append(
                                Finding(
                                    relative,
                                    0,
                                    "non-public-email-domain",
                                )
                            )
        structural_quote_starts = (
            _hcl_structural_quote_starts(text)
            if _is_hcl_path(path) and not json_was_parsed
            else frozenset()
        )
        if path.suffix != ".json" or not json_was_parsed:
            for assignment_pattern, assignment_rule in (
                (
                    AWS_SECRET_ACCESS_KEY_ASSIGNMENT,
                    "aws-secret-access-key-assignment",
                ),
                (NAMED_SECRET_ASSIGNMENT, "named-secret-format"),
            ):
                for assignment_match in assignment_pattern.finditer(text):
                    if (
                        _is_hcl_path(path)
                        and text[assignment_match.start()] in {'"', "'"}
                        and assignment_match.start()
                        in structural_quote_starts
                    ):
                        continue
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
            if _is_hcl_path(path):
                for (
                    decoded_name,
                    value_start,
                    value_end,
                    assignment_line,
                ) in _iter_decoded_hcl_quoted_assignments(
                    text, structural_quote_starts
                ):
                    if AWS_SECRET_ACCESS_KEY_NAME.fullmatch(decoded_name):
                        assignment_rule = (
                            "aws-secret-access-key-assignment"
                        )
                    elif NAMED_SECRET_NAME.fullmatch(decoded_name):
                        assignment_rule = "named-secret-format"
                    else:
                        continue
                    if _hcl_expression_exposes_literal(
                        text[value_start:value_end], 0
                    ):
                        findings.append(
                            Finding(
                                relative,
                                assignment_line,
                                assignment_rule,
                            )
                        )
        in_example = pathlib.PurePosixPath(relative).parts[:1] == ("examples",)
        in_module = pathlib.PurePosixPath(relative).parts[:1] == ("modules",)
        in_metadata_scope = in_example or (
            in_module and _is_hcl_path(path)
        )
        if in_metadata_scope and json_was_parsed:
            for metadata_source in decoded_json_sources:
                hostname_source = EMAIL.sub("", metadata_source)
                hostname_source = ASSET_PATH_EXTENSION.sub(
                    r"/\1", hostname_source
                )
                for match in HOSTNAME.finditer(hostname_source):
                    if not _is_permitted_domain(match.group(0)):
                        findings.append(
                            Finding(relative, 0, "non-example-hostname")
                        )
                for match in CLOUDFLARE_ID.finditer(metadata_source):
                    if set(match.group(0)) != {"0"}:
                        findings.append(
                            Finding(
                                relative,
                                0,
                                "non-sentinel-cloudflare-id",
                            )
                        )
        heredoc_stack: list[tuple[str, bool, HclHostnameState]] = []
        hcl_hostname_state = HclHostnameState()
        is_hcl = _is_hcl_path(path)
        for line_number, line in enumerate(text.splitlines(), start=1):
            if json_was_parsed:
                continue
            hcl_literal_source = line
            if is_hcl:
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
                        hcl_literal_source = ""
                    else:
                        (
                            hcl_literal_source,
                            opened_heredoc,
                            _,
                        ) = _hcl_hostname_source(
                            line, heredoc_hostname_state
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
                        hcl_literal_source,
                        opened_heredoc,
                        _,
                    ) = _hcl_hostname_source(line, hcl_hostname_state)
                    if opened_heredoc is not None:
                        heredoc_stack.append(
                            (
                                *opened_heredoc,
                                HclHostnameState(in_heredoc=True),
                            )
                        )

            scan_sources = (line, hcl_literal_source) if is_hcl else (line,)
            for scan_source in scan_sources:
                for pattern, rule in (
                    (PRIVATE_KEY, "private-key-marker"),
                    (AWS_ACCESS_KEY, "aws-secret-format"),
                    (GITHUB_TOKEN, "github-secret-format"),
                    (AGE_SECRET_KEY, "age-secret-format"),
                ):
                    if pattern.search(scan_source):
                        findings.append(Finding(relative, line_number, rule))

                for match in EMAIL.finditer(scan_source):
                    if not _is_permitted_domain(match.group(1)):
                        findings.append(
                            Finding(
                                relative,
                                line_number,
                                "non-public-email-domain",
                            )
                        )

            if is_hcl:
                for assignment_pattern, assignment_rule in (
                    (
                        AWS_SECRET_ACCESS_KEY_ASSIGNMENT,
                        "aws-secret-access-key-assignment",
                    ),
                    (NAMED_SECRET_ASSIGNMENT, "named-secret-format"),
                ):
                    for assignment_match in assignment_pattern.finditer(
                        hcl_literal_source
                    ):
                        if _assignment_value_start(
                            hcl_literal_source, assignment_match
                        ) is not None:
                            findings.append(
                                Finding(
                                    relative,
                                    line_number,
                                    assignment_rule,
                                )
                            )

            if in_metadata_scope:
                metadata_source = hcl_literal_source if is_hcl else line
                hostname_source = EMAIL.sub("", metadata_source)
                hostname_source = ASSET_PATH_EXTENSION.sub(
                    r"/\1", hostname_source
                )
                for match in HOSTNAME.finditer(hostname_source):
                    if not _is_permitted_domain(match.group(0)):
                        findings.append(Finding(relative, line_number, "non-example-hostname"))
                for id_source in (line, metadata_source):
                    for match in CLOUDFLARE_ID.finditer(id_source):
                        if set(match.group(0)) != {"0"}:
                            findings.append(
                                Finding(
                                    relative,
                                    line_number,
                                    "non-sentinel-cloudflare-id",
                                )
                            )

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
