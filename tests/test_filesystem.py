import os

import pytest
import remek_core.filesystem as filesystem_module
import remek_core.transaction as transaction_module
from remek_core.filesystem import (
    TreeFile,
    checked_path,
    checked_root,
    fingerprint,
    portable_path,
    read_regular,
    snapshot_tree,
    tree_from_entries,
    write_artifact,
)
from remek_core.model import RemekError
from remek_core.transaction import (
    apply_changes,
    delete_change,
    tree_change,
    write_change,
)


def test_write_plan_is_exact_and_plan_only(root):
    change = write_change(root, root / "a.txt", b"hello", "create a")
    assert change.expected == "absent"
    assert change.after.endswith("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    assert not (root / "a.txt").exists()
    apply_changes([change])
    assert (root / "a.txt").read_bytes() == b"hello"
    longest = root / ("x" * 255)
    apply_changes([write_change(root, longest, b"x", "x")])
    assert longest.read_bytes() == b"x"


def test_write_and_delete_one_bound_file(root):
    target = root / "a.txt"
    target.write_text("old")
    change = write_change(root, target, b"new", "replace a", mode=0o600)
    apply_changes([change])
    assert target.read_text() == "new"
    assert target.stat().st_mode & 0o777 == 0o600
    apply_changes([delete_change(root, target, "remove a")])
    assert not target.exists()


def test_stale_plan_preserves_foreign_winner(root):
    target = root / "a.txt"
    target.write_text("old")
    change = write_change(root, target, b"new", "replace a")
    target.write_text("foreign")
    with pytest.raises(RemekError, match="changed since planning"):
        apply_changes([change])
    assert target.read_text() == "foreign"


def test_verification_failure_rolls_back_exact_bytes(root):
    target = root / "a.txt"
    target.write_text("old")
    change = write_change(root, target, b"new", "replace a")

    def fail():
        raise RemekError("verification failed")

    with pytest.raises(RemekError, match="verification failed"):
        apply_changes([change], verify=fail)
    assert target.read_text() == "old"


def test_rollback_never_erases_foreign_winner(root):
    target = root / "a.txt"
    target.write_text("old")
    change = write_change(root, target, b"new", "replace a")

    def race():
        target.write_text("foreign")
        raise RemekError("verification failed")

    with pytest.raises(RemekError, match="exact residue"):
        apply_changes([change], verify=race)
    assert target.read_text() == "foreign"


def test_cleanup_preserves_foreign_backup(root):
    target = root / "a.txt"
    target.write_text("old")
    change = write_change(root, target, b"new", "replace a")
    raced = []

    def race():
        backup = next(root.glob(".remek-backup-*"))
        backup.unlink()
        backup.write_text("foreign")
        raced.append(backup)

    with pytest.raises(RemekError, match="cleanup residue") as captured:
        apply_changes([change], verify=race)

    assert captured.value.changed is True
    assert target.read_text() == "new"
    assert raced[0].read_text() == "foreign"


def test_tree_plan_captures_then_replaces_one_destination(root, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "one").write_text("captured")
    change = tree_change(root, root / "tree", source, "install tree")
    (source / "one").write_text("later")
    apply_changes([change])
    assert (root / "tree" / "one").read_text() == "captured"
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "new").write_text("new")
    apply_changes([tree_change(root, root / "tree", replacement, "replace tree")])
    assert sorted(item.name for item in (root / "tree").iterdir()) == ["new"]


def test_duplicate_destination_is_refused(root):
    first = write_change(root, root / "a", b"one", "one")
    second = write_change(root, root / "a", b"two", "two")
    with pytest.raises(RemekError, match="repeats a destination"):
        apply_changes([first, second])


def test_same_destination_across_boundaries_is_refused(root):
    nested = root / "nested"
    nested.mkdir()
    target = nested / "item"
    first = write_change(root, target, b"one", "one")
    second = write_change(nested, target, b"two", "two")
    with pytest.raises(RemekError, match="destinations overlap"):
        apply_changes([first, second])


def test_checked_path_refuses_escape_and_symlink(root, tmp_path):
    with pytest.raises(RemekError, match="escapes"):
        checked_path(root, root / ".." / "outside")
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(RemekError, match=r"not a real directory|outside"):
        checked_path(root, root / "link" / "file")


def test_reads_and_trees_refuse_symlinks(root):
    (root / "real").write_text("secret")
    (root / "link").symlink_to("real")
    with pytest.raises(RemekError, match="regular file"):
        read_regular(root / "link")
    with pytest.raises(RemekError, match="link"):
        snapshot_tree(root)
    (root / "link").unlink()
    os.link(root / "real", root.parent / "external-name")
    with pytest.raises(RemekError, match="unlinked"):
        read_regular(root / "real")
    with pytest.raises(RemekError, match="unlinked"):
        snapshot_tree(root)


def test_read_regular_refuses_directory_and_excess(root):
    with pytest.raises(RemekError, match="regular file"):
        read_regular(root)
    target = root / "large"
    target.write_bytes(b"1234")
    with pytest.raises(RemekError, match="exceeds 3"):
        read_regular(target, limit=3)


def test_snapshot_tree_is_stable(root):
    (root / "b").write_text("b")
    (root / "a").write_text("a")
    first = snapshot_tree(root)
    second = snapshot_tree(root)
    assert first == second
    assert [item.path for item in first.files] == ["a", "b"]
    (root / "c").write_text("c")
    assert snapshot_tree(root).digest != first.digest


def test_fingerprint_distinguishes_mode(root):
    target = root / "file"
    target.write_text("same")
    before = fingerprint(target)
    target.chmod(0o755)
    assert fingerprint(target) != before


def test_checked_root_refuses_file_and_accepts_alias(tmp_path):
    target = tmp_path / "file"
    target.write_text("x")
    with pytest.raises(RemekError, match="one real directory"):
        checked_root(target)
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    assert checked_root(alias) == real.resolve()


@pytest.mark.parametrize("foreign", [False, True])
def test_file_stage_cleanup(
    root,
    monkeypatch,
    foreign,
):
    target = root / "file"
    change = write_change(root, target, b"complete bytes", "x", mode=0o755)
    if foreign:
        original = filesystem_module.os.fstat
        calls = 0

        def fail_once(descriptor):
            nonlocal calls
            calls += 1
            if calls == 1:
                stage = next(root.glob(".remek-stage-*"))
                stage.unlink()
                stage.write_text("foreign")
                raise OSError("fstat")
            return original(descriptor)

        monkeypatch.setattr(filesystem_module.os, "fstat", fail_once)
    else:
        original = filesystem_module.os.write
        calls = 0

        def partial(descriptor, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return original(descriptor, bytes(data)[:2])
            raise OSError("write")

        monkeypatch.setattr(filesystem_module.os, "write", partial)

    with pytest.raises((OSError, RemekError)) as captured:
        apply_changes([change])

    assert not target.exists()
    stages = list(root.glob(".remek-stage-*"))
    if foreign:
        assert isinstance(captured.value, RemekError) and captured.value.changed
        assert stages[0].read_text() == "foreign"
    else:
        assert not stages


def test_tree_stage_cleanup(root, tmp_path, monkeypatch):
    source = tmp_path / "source-tree"
    source.mkdir()
    (source / "one").write_text("one")
    (source / "two").write_text("two")
    change = tree_change(root, root / "tree", source, "x")
    opened = filesystem_module.os.open

    def fail_created_stage(path, flags, *args, **options):
        if str(path).startswith(".remek-stage-") and (root / str(path)).is_dir():
            raise OSError("tree open")
        return opened(path, flags, *args, **options)

    monkeypatch.setattr(filesystem_module.os, "open", fail_created_stage)
    with pytest.raises((OSError, RemekError), match="tree open"):
        apply_changes([change])
    assert not (root / "tree").exists() and not list(root.glob(".remek-stage-*"))
    monkeypatch.setattr(filesystem_module.os, "open", opened)
    original = filesystem_module.write_file_at
    calls = 0

    def fail_second(parent, name, data, mode):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("tree write")
        return original(parent, name, data, mode)

    monkeypatch.setattr(filesystem_module, "write_file_at", fail_second)
    with pytest.raises((OSError, RemekError), match="tree write"):
        apply_changes([change])
    assert not (root / "tree").exists()


def test_restrictive_umask_cannot_change_planned_modes(root, tmp_path):
    source = tmp_path / "source-mode"
    (source / "nested").mkdir(parents=True)
    payload = source / "nested" / "run"
    payload.write_text("run")
    payload.chmod(0o751)
    previous = os.umask(0o077)
    try:
        apply_changes(
            [
                write_change(root, root / "script", b"run", "mode", mode=0o755),
                tree_change(root, root / "tree", source, "tree mode"),
            ]
        )
    finally:
        os.umask(previous)
    assert (root / "script").stat().st_mode & 0o777 == 0o755
    assert (root / "tree").stat().st_mode & 0o777 == 0o755
    assert (root / "tree" / "nested").stat().st_mode & 0o777 == 0o755
    assert (root / "tree" / "nested" / "run").stat().st_mode & 0o777 == 0o751


def test_interruption_during_final_cleanup_reports_changed_truth(root, monkeypatch):
    target = root / "file"
    target.write_text("before")
    change = write_change(root, target, b"after", "replace")
    original = transaction_module.remove_at

    def interrupt(parent, name, expected, **options):
        if ".remek-backup-" in name:
            raise KeyboardInterrupt
        original(parent, name, expected, **options)

    monkeypatch.setattr(transaction_module, "remove_at", interrupt)
    with pytest.raises(RemekError, match="cleanup residue") as captured:
        apply_changes([change])
    assert captured.value.changed is True
    assert target.read_bytes() == b"after"
    assert list(root.glob(".remek-backup-*"))


def test_empty_directories_and_directory_modes_affect_identity(root):
    before = snapshot_tree(root).digest
    empty = root / "empty"
    empty.mkdir()
    with_empty = snapshot_tree(root).digest
    empty.chmod(0o700)
    assert with_empty != before
    assert snapshot_tree(root).digest != with_empty


def test_runtime_snapshot_rejects_cache_and_bytecode(root):
    cache = root / "__pycache__"
    cache.mkdir()
    (cache / "module.pyc").write_bytes(b"not executable")
    with pytest.raises(RemekError, match="cache or bytecode"):
        snapshot_tree(root, reject_bytecode=True)


def test_directory_entry_and_depth_limits_fire_before_unbounded_retention(root, monkeypatch):
    monkeypatch.setattr(filesystem_module, "MAX_DIRECTORY_ENTRIES", 2)
    for name in ("a", "b", "c"):
        (root / name).mkdir()
    with pytest.raises(RemekError, match="entry limits"):
        snapshot_tree(root)

    for item in root.iterdir():
        item.rmdir()
    monkeypatch.setattr(filesystem_module, "MAX_DIRECTORY_ENTRIES", 1024)
    monkeypatch.setattr(filesystem_module, "MAX_TREE_DEPTH", 2)
    (root / "a" / "b" / "c").mkdir(parents=True)
    with pytest.raises(RemekError, match="depth"):
        snapshot_tree(root)
    with pytest.raises(RemekError, match="depth"):
        tree_from_entries([], [filesystem_module.TreeDirectory("a/b/c")])


def test_stable_read_rejects_metadata_change_during_read(root, monkeypatch):
    target = root / "large"
    target.write_bytes(b"x" * 70_000)
    original = filesystem_module.os.read
    changed = False

    def mutate(descriptor, size):
        nonlocal changed
        data = original(descriptor, size)
        if data and not changed:
            changed = True
            os.fchmod(descriptor, 0o600)
        return data

    monkeypatch.setattr(filesystem_module.os, "read", mutate)
    with pytest.raises(RemekError, match="changed while reading"):
        read_regular(target)


@pytest.mark.parametrize("value", ["a//b", "a/./b", "../a", "/a", "a/\0b", "a/\u202eb"])
def test_portable_paths_reject_noncanonical_components(value):
    with pytest.raises(RemekError):
        portable_path(value)


def test_tree_rejects_portable_path_conflicts():
    for first, second in (("A", "a"), ("café", "café")):
        with pytest.raises(RemekError, match="portable collision"):
            tree_from_entries([TreeFile(first, b"one", 0o644), TreeFile(second, b"two", 0o644)])
    with pytest.raises(RemekError, match="conflicts with descendant"):
        tree_from_entries(
            [TreeFile("a", b"file", 0o644), TreeFile("a/b", b"child", 0o644)],
        )
    with pytest.raises(RemekError, match="remek marker"):
        portable_path(".name.remek-stage-token", authored=True)


def test_artifact_races(tmp_path, monkeypatch):
    longest = tmp_path / ("x" * 255)
    write_artifact(longest, b"plan")
    destination = tmp_path / "plan.json"
    original = filesystem_module.os.link

    def race(source, target, **options):
        destination.write_bytes(b"winner")
        original(source, target, **options)

    monkeypatch.setattr(filesystem_module.os, "link", race)
    with pytest.raises(RemekError, match="already exists"):
        write_artifact(destination, b"plan")
    assert destination.read_bytes() == b"winner"

    effected = tmp_path / "effected.json"

    def effect_then_error(source, target, **options):
        original(source, target, **options)
        raise OSError("x")

    monkeypatch.setattr(filesystem_module.os, "link", effect_then_error)
    assert write_artifact(effected, b"plan") == effected
    assert effected.read_bytes() == b"plan"
