# ruff: noqa: D101, D103
"""Frontmatter."""

import json
import re
import unicodedata
from itertools import pairwise

_MAX_BYTES = 256 * 1024
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
_CLOSE = re.compile(r"^---\r?(?:\n|\Z)", re.MULTILINE)
_SINGLE = re.compile(r"'(?:[^']|'')*'\Z")
_YAML_VALUE = re.compile(
    r"(?:~|null|true|false|yes|no|on|off|[-+]?(?:\.(?:inf|nan)|0[xob][0-9a-f_]+|"
    r"(?:0|[1-9][0-9_]*)(?:\.[0-9_]*)?(?:e[-+]?[0-9]+)?)|\d{4}-\d{1,2}-\d{1,2})\Z",
    re.IGNORECASE,
)


class FrontmatterError(ValueError):
    pass


def _fail(line: int, message: str) -> FrontmatterError:
    return FrontmatterError(f"frontmatter line {line}: {message}")


def _validate(text: str, *, header: bool = False) -> None:
    try:
        size = len(text.encode())
    except UnicodeEncodeError as error:
        raise FrontmatterError("frontmatter contains an invalid Unicode scalar") from error
    if size > _MAX_BYTES:
        raise FrontmatterError(f"skill is {size} bytes; maximum is {_MAX_BYTES} bytes")
    allowed = {"\n"} if header else {"\n", "\r", "\t"}
    for index, char in enumerate(text):
        if char not in allowed and unicodedata.category(char) in {"Cc", "Cs"}:
            line = text.count("\n", 0, index) + 1
            column = index - text.rfind("\n", 0, index)
            raise FrontmatterError(
                f"line {line}, column {column}: prohibited control character U+{ord(char):04X}"
            )


def _split(text: str) -> tuple[list[str], str]:
    start = 5 if text.startswith("---\r\n") else 4 if text.startswith("---\n") else 0
    match = _CLOSE.search(text, start) if start else None
    if match is None:
        message = (
            "frontmatter has no closing '---' line" if start else "skill must begin with '---'"
        )
        raise FrontmatterError(message)
    header = text[start : match.start()]
    _validate(header.replace("\r\n", "\n"), header=True)
    return header.splitlines(), text[match.end() :]


def _item(source: str, line: int) -> tuple[str, str]:
    key, separator, value = source.partition(":")
    if not separator or _KEY.fullmatch(key) is None:
        raise _fail(line, "expected an unquoted string key followed by ':'")
    if value and not value.startswith(" "):
        raise _fail(line, "expected a space after ':'")
    return key, value.strip(" ")


def _list(source: str, line: int) -> list[str]:
    if not source.endswith("]"):
        raise _fail(line, "unterminated inline list")
    inner = source[1:-1]
    if not inner.strip():
        return []
    parts: list[str] = []
    start, index, quote = 0, 0, ""
    while index < len(inner):
        char = inner[index]
        if quote == "'" and char == "'" and index + 1 < len(inner) and inner[index + 1] == "'":
            index += 2
            continue
        if quote and char == quote:
            quote = ""
        elif quote == '"' and char == "\\":
            index += 2
            continue
        elif not quote and char in "'\"":
            quote = char
        elif not quote and char == ",":
            parts.append(inner[start:index])
            start = index + 1
        elif not quote and char in "[]{}":
            raise _fail(line, "nested inline collections are not supported")
        index += 1
    if quote:
        raise _fail(line, "unterminated quoted inline-list item")
    values: list[str] = []
    for part in [*parts, inner[start:]]:
        item = part.strip(" ")
        parsed = _value(item, line) if item else []
        if not isinstance(parsed, str):
            raise _fail(line, "inline lists require nonempty string items")
        values.append(parsed)
    return values


def _value(source: str, line: int) -> str | list[str]:
    if not source:
        raise _fail(line, "empty strings must be quoted")
    if source.startswith("'"):
        if _SINGLE.fullmatch(source) is None:
            raise _fail(line, "invalid single-quoted string")
        return source[1:-1].replace("''", "'")
    if source.startswith('"'):
        try:
            value = json.loads(source)
        except json.JSONDecodeError as error:
            raise _fail(line, "invalid double-quoted string") from error
        if not isinstance(value, str) or any(
            unicodedata.category(char) in {"Cc", "Cs"} for char in value
        ):
            raise _fail(line, "expected a control-free string")
        return value
    if source.startswith("["):
        return _list(source, line)
    if (
        source[0] in "&*!,[]#|>%@`"
        or source.startswith(("- ", "? ", ": ", "{"))
        or source.endswith("}")
        or re.search(r":(?: |$)|(?:^| )#", source)
        or _YAML_VALUE.fullmatch(source)
    ):
        raise _fail(line, "ambiguous YAML plain strings must be quoted")
    return source


def _block(lines: list[str], start: int, style: str) -> tuple[str, int]:
    content: list[str] = []
    while start < len(lines):
        source = lines[start]
        if source and not source.startswith("  "):
            break
        if source.startswith("   "):
            raise _fail(start + 2, "indentation must be exactly two spaces")
        content.append(source[2:] if source else "")
        start += 1
    while content and not content[-1]:
        content.pop()
    if not content:
        return "", start
    if style == "|":
        return "\n".join(content) + "\n", start
    folded = content[0]
    for previous, current in pairwise(content):
        folded += ("\n" if not previous else " " if current else "") + current
    return folded + "\n", start


def _parse(lines: list[str]) -> dict[str, object]:
    result: dict[str, object] = {}
    metadata: dict[str, object] | None = None
    metadata_indent: int | None = None
    index = 0
    while index < len(lines):
        source, line = lines[index], index + 2
        if not source:
            index += 1
            continue
        spaces = len(source) - len(source.lstrip(" "))
        if spaces:
            if spaces not in {2, 4} or metadata_indent not in (None, spaces):
                raise _fail(line, "metadata indentation must be consistently two or four spaces")
            if metadata is None:
                raise _fail(line, "only metadata values may be indented")
            metadata_indent = spaces
            key, value = _item(source[spaces:], line)
            if key in metadata or not value:
                raise _fail(line, "duplicate key or nested mapping")
            parsed = _value(value, line)
            if not isinstance(parsed, str):
                raise _fail(line, "metadata values must be scalar strings")
            metadata[key] = parsed
            index += 1
            continue
        metadata = None
        metadata_indent = None
        key, value = _item(source, line)
        if key in result:
            raise _fail(line, f"duplicate key {key!r}")
        if key == "metadata":
            if value:
                raise _fail(line, "metadata must be an indented mapping")
            metadata = {}
            result[key] = metadata
            index += 1
        elif value in {"|", ">"}:
            result[key], index = _block(lines, index + 1, value)
        else:
            result[key] = _value(value, line)
            index += 1
    return result


def parse_skill(text: str) -> tuple[dict[str, object], str]:
    _validate(text)
    lines, body = _split(text)
    return _parse(lines), body


def render_skill(fields: dict[str, object], body: str) -> bytes:
    order = ("name", "description", "license", "compatibility", "metadata", "allowed-tools")
    if set(fields) - set(order):
        raise FrontmatterError("frontmatter contains an unsupported field")
    lines = ["---"]
    for key in order:
        if key not in fields:
            continue
        value = fields[key]
        if key == "compatibility" and (not isinstance(value, str) or not 1 <= len(value) <= 500):
            raise FrontmatterError("compatibility must be a 1 to 500 character string")
        if key == "metadata":
            if not isinstance(value, dict) or any(
                not isinstance(item_key, str) or not isinstance(item, str)
                for item_key, item in value.items()
            ):
                raise FrontmatterError("metadata must be a string mapping")
            lines.append("metadata:")
            lines.extend(
                f"  {item_key}: {json.dumps(value[item_key], ensure_ascii=False)}"
                for item_key in sorted(value)
            )
        else:
            if not isinstance(value, str):
                raise FrontmatterError(f"{key} must be a string")
            lines.append(f"{key}: {json.dumps(value, ensure_ascii=False)}")
    canonical_body = body.rstrip("\n") + "\n"
    text = "\n".join([*lines, "---", canonical_body])
    if parse_skill(text) != (fields, canonical_body):
        raise FrontmatterError("canonical frontmatter did not round-trip")
    return text.encode()
