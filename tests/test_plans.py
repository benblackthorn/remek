import json
import shutil

import pytest
from helpers import TOOLCHAIN
from remek_core.contract import render_document
from remek_core.filesystem import TreeDirectory, tree_from_entries
from remek_core.model import RemekError
from remek_core.plans import (
    MAX_DIFF_BYTES,
    Plan,
    SourceBinding,
    load_operation_plan,
    operation_document,
    plan_diff,
    reconstruct_plan,
    validate_output_path,
    verify_operation_plan,
)
from remek_core.transaction import delete_change, tree_change, write_change
from remek_core.workflows import init_plan


def save(path, plan):
    data, _ = operation_document(plan, TOOLCHAIN)
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def test_plan_contains_identities_not_payload_bytes(tmp_path):
    plan = init_plan(
        tmp_path / "source",
        TOOLCHAIN,
        "22222222-2222-4222-8222-222222222222",
    )
    data, _ = operation_document(plan, TOOLCHAIN)
    document = json.loads(data)
    assert set(document) == {
        "schema",
        "kind",
        "root",
        "command",
        "inputs",
        "generated",
        "bundleIdentity",
        "sources",
        "changes",
        "bindings",
        "planDigest",
    }
    assert "toolchain-manifest" not in data.decode()


def test_plan_digest_tampering_refuses(tmp_path):
    plan = init_plan(tmp_path / "source", TOOLCHAIN)
    path = save(tmp_path / "plan.json", plan)
    document = json.loads(path.read_text())
    document["inputs"]["project"] = True
    path.write_bytes(
        render_document(
            "operation-plan",
            {key: value for key, value in document.items() if key not in {"schema", "kind"}},
        )
    )
    with pytest.raises(RemekError, match="digest"):
        load_operation_plan(path)


def test_reconstruction_reports_precise_divergence(tmp_path):
    plan = init_plan(
        tmp_path / "source",
        TOOLCHAIN,
        "22222222-2222-4222-8222-222222222222",
    )
    path = save(tmp_path / "plan.json", plan)
    loaded = load_operation_plan(path)
    plan.changes[0].path.parent.joinpath("source").mkdir()
    with pytest.raises(RemekError):
        verify_operation_plan(loaded, reconstruct_plan(loaded, TOOLCHAIN), TOOLCHAIN)


def test_plan_diff_ceiling_can_only_lower(tmp_path):
    plan = init_plan(tmp_path / "source", TOOLCHAIN)
    assert "truncated" in plan_diff(plan, max_bytes=128)
    with pytest.raises(RemekError, match="max-bytes"):
        plan_diff(plan, max_bytes=MAX_DIFF_BYTES + 1)
    root = tmp_path / "diff"
    root.mkdir()
    (root / "x").write_text("safe\n")
    change = write_change(root, root / "x", b"\x1b[2J", "test")
    rendered = plan_diff(Plan("test", root, (change,)))
    assert "\x1b" not in rendered and r"\u001b" in rendered
    (root / "x").unlink()
    (root / "x").symlink_to("missing")
    assert "mode" in plan_diff(Plan("test", root, (change,)))
    (root / "x").unlink()
    (root / "x").write_bytes(b"x" * ((2 << 20) + 1))
    assert "mode" in plan_diff(Plan("test", root, (change,)))


def test_plan_diff_shows_added_removed_binary_and_type_transition_content(tmp_path):
    root = tmp_path / "diff-content"
    root.mkdir()
    path = root / "item"
    cases = (
        (None, b"# New skill\n\nExact step.\n", ("+# New skill", "+Exact step.")),
        (b"private procedure\n", None, ("-private procedure",)),
        (None, b"\xff\x00", ("binary", "2 bytes", "sha256")),
    )
    for before, after, expected in cases:
        path.unlink(missing_ok=True)
        if before is not None:
            path.write_bytes(before)
        change = (
            delete_change(root, path, "test")
            if after is None
            else write_change(root, path, after, "test")
        )
        rendered = plan_diff(Plan("test", root, (change,)))
        assert all(value in rendered for value in expected)
    path.write_text("old\n")
    transition = tree_change(
        root,
        path,
        tree_from_entries([], [TreeDirectory("child")], root_mode=0o644),
        "test",
    )
    transition_diff = plan_diff(Plan("test", root, (transition,)))
    assert f"type {path}: file -> directory" in transition_diff and "-old" in transition_diff


def test_plan_output_stays_outside_all_protected_roots(tmp_path):
    roots = [tmp_path / name for name in ("source", "mirror", "workspace", "artifact")]
    for root in roots:
        root.mkdir()
    plan = Plan(
        "test",
        roots[0],
        (),
        {"mirror": str(roots[1]), "workspace": str(roots[2])},
        sources=(SourceBinding(roots[3], "identity"),),
    )
    for root in [*roots, TOOLCHAIN]:
        with pytest.raises(RemekError, match="related"):
            validate_output_path(root / "plan.json", plan, TOOLCHAIN)
    safe = tmp_path.parent / f"{tmp_path.name}-plan.json"
    assert validate_output_path(safe, plan, TOOLCHAIN) == safe


def test_loaded_bundle_change_stales_plan(tmp_path):
    plan = init_plan(tmp_path / "source", TOOLCHAIN)
    loaded = load_operation_plan(save(tmp_path / "plan.json", plan))
    copied = tmp_path / "toolchain"
    shutil.copytree(TOOLCHAIN, copied)
    (copied / "assets/gate").write_text("different\n")
    with pytest.raises(RemekError, match="toolchain differs"):
        verify_operation_plan(loaded, plan, copied)
