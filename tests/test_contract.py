import json

import pytest
from remek_core.contract import (
    MAX_DEPTH,
    SCHEMA,
    load_document,
    parse_canonical_document,
    parse_document,
    render_document,
)
from remek_core.model import RemekError


def document(**fields):
    return json.dumps({"schema": SCHEMA, "kind": "test", **fields}).encode()


def test_round_trip_is_canonical():
    rendered = render_document("test", {"z": 1, "a": ["value"]})
    assert rendered.startswith(b'{\n  "a"')
    assert parse_document(rendered, kind="test")["z"] == 1


def test_owned_document_parser_requires_canonical_bytes():
    assert parse_canonical_document(render_document("test", {"value": 1}), kind="test")
    with pytest.raises(RemekError, match="not canonical"):
        parse_canonical_document(document(value=1), kind="test")


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"[]", "one object"),
        (b'{"schema":"unsupported","kind":"test"}', "schema"),
        (b'{"schema":"remek.1","kind":"other"}', "kind"),
        (b'{"schema":"remek.1","kind":"test","x":1,"x":2}', "repeats"),
        (b'{"schema":"remek.1","kind":"test","x":NaN}', "constant"),
        (b'{"schema":"remek.1","kind":"test","x":1.5}', "floating-point"),
        (b'{"schema":"remek.1","kind":"test","x":1e999}', "floating-point"),
        (b'{"schema":"remek.1","kind":"test","x":"\\ud800"}', "invalid Unicode"),
        (b"{", "invalid JSON"),
        (b"\xff", "UTF-8"),
    ],
)
def test_malformed_documents_are_actionable(data, message):
    with pytest.raises(RemekError, match=message):
        parse_document(data, kind="test")


def test_render_refuses_values_its_parser_cannot_round_trip():
    with pytest.raises(RemekError, match="invalid Unicode"):
        render_document("test", {"value": "\ud800"})
    with pytest.raises(RemekError, match="invalid Unicode"):
        render_document("test", {"\ud800": "value"})
    with pytest.raises(RemekError, match="not supported"):
        render_document("test", {"value": 1.5})


def test_depth_and_value_count_are_bounded():
    value = "leaf"
    for _ in range(MAX_DEPTH + 2):
        value = [value]
    with pytest.raises(RemekError, match="depth"):
        parse_document(document(value=value), kind="test")
    with pytest.raises(RemekError, match="values"):
        parse_document(document(values=list(range(5000))), kind="test")
    deeply_nested = (
        b'{"schema":"remek.1","kind":"test","value":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}"
    )
    with pytest.raises(RemekError, match=r"nesting|depth"):
        parse_document(deeply_nested, kind="test")


def test_load_document_refuses_symlink(tmp_path):
    real = tmp_path / "real.json"
    real.write_bytes(document())
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(RemekError, match="regular file"):
        load_document(link, kind="test")


def test_render_refuses_reserved_fields():
    with pytest.raises(RemekError, match="cannot replace"):
        render_document("test", {"schema": "other"})
