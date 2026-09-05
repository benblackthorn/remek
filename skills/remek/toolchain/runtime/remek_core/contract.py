# ruff: noqa: D103
"""Contracts."""

import json
from collections.abc import Iterable
from pathlib import Path
from typing import NoReturn, TypeAlias, cast

from .filesystem import MAX_FILE_BYTES, read_regular
from .model import Error

SCHEMA = "remek.2"
MAX_DEPTH = 12
MAX_ITEMS = 4096
JSONScalar: TypeAlias = str | int | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
JSONObject: TypeAlias = dict[str, JSONValue]


def _pairs(items: Iterable[tuple[str, JSONValue]]) -> JSONObject:
    result: JSONObject = {}
    for key, value in items:
        if key in result:
            raise Error("JSON object repeats a key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise Error(f"JSON constant {value!r} is not supported")


def _float(value: str) -> NoReturn:
    raise Error(f"JSON floating-point number {value!r} is not supported")


def _text(value: str, *, label: str) -> None:
    if not isinstance(value, str):
        raise Error(f"JSON {label} must be a string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise Error(f"JSON {label} contains invalid Unicode") from None
    if len(encoded) > MAX_FILE_BYTES:
        raise Error(f"JSON {label} exceeds the size limit")


def value_count(value: JSONValue, *, depth: int = 0) -> int:
    if depth > MAX_DEPTH:
        raise Error(f"JSON exceeds maximum depth {MAX_DEPTH}")
    if isinstance(value, str):
        _text(value, label="string")
        return 1
    if value is None or isinstance(value, (bool, int)):
        return 1
    if isinstance(value, list):
        count = 1 + sum(value_count(item, depth=depth + 1) for item in value)
    elif isinstance(value, dict):
        count = 1
        for key, item in value.items():
            _text(key, label="object key")
            count += value_count(item, depth=depth + 1)
    else:
        raise Error(f"JSON value type {type(value).__name__!r} is not supported")
    return count


def document_limit(kind: str) -> int:
    """Bound bytes by the caller's expected kind, never an input's claimed kind."""
    if kind == "skill-record":
        return 256 * 1024
    if kind in {"evaluation", "release-review"}:
        return 512 * 1024
    if kind in {"repository", "distribution", "disclosure-policy"}:
        return 64 * 1024
    if kind == "command-result":
        return 1024 * 1024
    return MAX_FILE_BYTES


def _validate(value: JSONValue, *, kind: str, rendering: bool = False) -> int:
    count = value_count(value)
    maximum = 16384 if kind == "release-review" else MAX_ITEMS
    if rendering and kind == "command-result":
        maximum = 32768
    if count > maximum:
        raise Error(f"JSON exceeds {maximum} values for {kind}")
    return count


def parse_document(data: bytes, *, kind: str) -> JSONObject:
    maximum = document_limit(kind)
    if len(data) > maximum:
        raise Error(f"JSON exceeds {maximum} bytes for {kind}")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise Error(f"JSON is not UTF-8: {exc}") from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_float=_float,
        )
    except Error:
        raise
    except RecursionError:
        raise Error("invalid JSON nesting") from None
    except json.JSONDecodeError as exc:
        message = f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        raise Error(message) from None
    except (OverflowError, ValueError) as exc:
        raise Error(f"invalid JSON number: {exc}") from None
    if not isinstance(value, dict):
        raise Error("JSON document must contain one object")
    document = cast(JSONObject, value)
    _validate(document, kind=kind)
    if document.get("schema") != SCHEMA:
        if document.get("schema") == "remek.1":
            raise Error("JSON schema remek.1 requires offline migration to a fresh remek.2 source")
        raise Error(f"JSON schema must be {SCHEMA!r}")
    if document.get("kind") != kind:
        raise Error(f"JSON kind must be {kind!r}")
    return document


def load_document(path: Path, *, kind: str) -> JSONObject:
    return parse_document(read_regular(path, limit=document_limit(kind)).data, kind=kind)


def parse_canonical_document(data: bytes, *, kind: str) -> JSONObject:
    document = parse_document(data, kind=kind)
    fields = {key: value for key, value in document.items() if key not in {"schema", "kind"}}
    if data != render_document(kind, fields):
        raise Error("record.canonical", "owned JSON document is not canonical")
    return document


def load_canonical_document(path: Path, *, kind: str) -> JSONObject:
    return parse_canonical_document(read_regular(path, limit=document_limit(kind)).data, kind=kind)


def render_document(kind: str, fields: JSONObject) -> bytes:
    if not kind or set(fields) & {"schema", "kind"}:
        raise Error("document fields cannot replace schema or kind")
    document: JSONObject = {"schema": SCHEMA, "kind": kind, **fields}
    _validate(document, kind=kind, rendering=True)
    try:
        output = (json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
            "utf-8", errors="strict"
        )
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise Error(f"JSON cannot be output canonically: {exc}") from None
    maximum = document_limit(kind)
    if len(output) > maximum:
        raise Error(f"JSON exceeds {maximum} bytes for {kind}")
    return output
