import json

import pytest
from remek_core.contract import (
    MAX_DEPTH,
    MAX_ITEMS,
    SCHEMA,
    document_limit,
    load_canonical_document,
    load_document,
    parse_canonical_document,
    parse_document,
    render_document,
)
from remek_core.model import RemekError


def document(*, kind="test", **fields):
    return json.dumps({"schema": SCHEMA, "kind": kind, **fields}).encode()


def test_round_trip_is_canonical():
    rendered = render_document("test", {"z": 1, "a": ["value"]})
    assert rendered.startswith(b'{\n  "a"')
    assert parse_document(rendered, kind="test")["z"] == 1


def test_owned_document_parser_requires_canonical_bytes():
    assert parse_canonical_document(render_document("test", {"value": 1}), kind="test")
    with pytest.raises(RemekError, match="not canonical"):
        parse_canonical_document(document(value=1), kind="test")


def test_authored_json_preserves_raw_order_whitespace_and_case_order(tmp_path):
    raw = b'{ "cases": ["second", "first"], "kind": "skill-record",\r\n "schema": "remek.2" }'
    path = tmp_path / "skill.json"
    path.write_bytes(raw)
    parsed = load_document(path, kind="skill-record")
    assert parsed["cases"] == ["second", "first"]
    assert path.read_bytes() == raw
    with pytest.raises(RemekError, match="not canonical"):
        load_canonical_document(path, kind="skill-record")


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"[]", "one object"),
        (b'{"schema":"unsupported","kind":"test"}', "schema"),
        (b'{"schema":"remek.1","kind":"test"}', "migration"),
        (b'{"schema":"remek.2","kind":"other"}', "kind"),
        (b'{"schema":"remek.2","kind":"test","x":1,"x":2}', "repeats"),
        (b'{"schema":"remek.2","kind":"test","x":NaN}', "constant"),
        (b'{"schema":"remek.2","kind":"test","x":1.5}', "floating-point"),
        (b'{"schema":"remek.2","kind":"test","x":1e999}', "floating-point"),
        (b'{"schema":"remek.2","kind":"test","x":"\\ud800"}', "invalid Unicode"),
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
        b'{"schema":"remek.2","kind":"test","value":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}"
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


def test_document_byte_limits_use_expected_kind_without_rewriting(tmp_path):
    for kind, maximum in (
        ("repository", 64 * 1024),
        ("distribution", 64 * 1024),
        ("disclosure-policy", 64 * 1024),
        ("skill-record", 256 * 1024),
        ("evaluation", 512 * 1024),
        ("release-review", 512 * 1024),
    ):
        assert document_limit(kind) == maximum
        raw = document(kind=kind, value="")
        raw = raw[:-2] + b"x" * (maximum - len(raw)) + raw[-2:]
        path = tmp_path / f"{kind}.json"
        path.write_bytes(raw)
        assert load_document(path, kind=kind)["kind"] == kind
        with pytest.raises(RemekError, match=f"{maximum} bytes"):
            parse_document(raw + b" ", kind=kind)
        with pytest.raises(RemekError, match=f"{maximum} bytes"):
            render_document(kind, {"value": "x" * maximum})
        assert path.read_bytes() == raw
    with pytest.raises(RemekError, match=r"65536 bytes.*distribution"):
        parse_document(document(kind="release-review", value="x" * 65536), kind="distribution")


def test_review_budget_is_explicit_and_general_inputs_stay_bounded():
    # The maximum skill/profile grid exceeds the ordinary parser's value budget.
    skills = [
        {"skill": f"skill-{index}", "profiles": [f"profile-{slot}" for slot in range(32)]}
        for index in range(128)
    ]
    raw = render_document("release-review", {"skills": skills})
    assert len(raw) < 512 * 1024
    assert parse_canonical_document(raw, kind="release-review")["skills"] == skills
    with pytest.raises(RemekError, match="4096 values"):
        parse_document(raw, kind="evaluation")
    maximum = {"values": list(range(16384 - 4))}
    assert (
        parse_canonical_document(render_document("release-review", maximum), kind="release-review")[
            "values"
        ]
        == maximum["values"]
    )
    with pytest.raises(RemekError, match="16384 values"):
        parse_document(
            document(kind="release-review", values=list(range(16384))), kind="release-review"
        )
    nested = "leaf"
    for _ in range(MAX_DEPTH + 1):
        nested = [nested]
    with pytest.raises(RemekError, match="depth"):
        parse_document(document(kind="release-review", nested=nested), kind="release-review")


def test_command_output_budget_does_not_expand_input_parser_limits():
    raw = render_document("command-result", {"values": list(range(32768 - 4))})
    assert len(raw) < 1024 * 1024
    with pytest.raises(RemekError, match=f"{MAX_ITEMS} values"):
        parse_document(raw, kind="command-result")
    with pytest.raises(RemekError, match="32768 values"):
        render_document("command-result", {"values": list(range(32768 - 3))})
    with pytest.raises(RemekError, match="1048576 bytes"):
        render_document("command-result", {"value": "x" * (1024 * 1024)})
