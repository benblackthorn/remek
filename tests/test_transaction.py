import os

import pytest
import remek_core.filesystem as filesystem_module
import remek_core.transaction as transaction_module
from remek_core.model import RemekError
from remek_core.transaction import (
    ApplyOutcome,
    apply_changes,
    tree_change,
    write_change,
)


def test_every_object_is_staged_before_first_public_replace(root, monkeypatch):
    changes = [
        write_change(root, root / "one", b"one", "one"),
        write_change(root, root / "two", b"two", "two"),
    ]
    original = transaction_module.os.replace
    observed = False

    def replace(source, destination, **options):
        nonlocal observed
        if not observed:
            observed = True
            stages = list(root.glob(".remek-stage-*"))
            assert len(stages) == 2
        original(source, destination, **options)

    monkeypatch.setattr(transaction_module.os, "replace", replace)
    outcome = apply_changes(changes)
    assert outcome == ApplyOutcome(True)


def test_overlapping_destinations_refuse(root, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "member").write_text("tree")
    changes = [
        tree_change(root, root / "tree", source, "outer"),
        write_change(root, root / "tree" / "member", b"inner", "inner"),
    ]
    with pytest.raises(RemekError, match="overlap"):
        apply_changes(changes)
    assert not (root / "tree").exists()


def test_missing_descriptor_capability_refuses_before_mutation(root, monkeypatch):
    supported = set(os.supports_dir_fd)
    with monkeypatch.context() as patch:
        patch.setattr(filesystem_module.os, "supports_dir_fd", supported - {os.symlink})
        assert not filesystem_module._detect_posix_capabilities()

    def unavailable(*_args, **_kwargs):
        raise NotImplementedError

    with monkeypatch.context() as patch:
        patch.setattr(filesystem_module.os, "replace", unavailable)
        assert not filesystem_module._detect_posix_capabilities()
    change = write_change(root, root / "file", b"data", "capability")
    monkeypatch.setattr(filesystem_module, "_POSIX_CAPABILITIES", False)
    with pytest.raises(RemekError, match="dir-fd operations unavailable"):
        apply_changes([change])
    assert not (root / "file").exists()


def test_no_unplanned_parent(root):
    change = write_change(root, root / "nested" / "file", b"data", "nested")
    with pytest.raises(RemekError, match="cannot traverse"):
        apply_changes([change])
    assert not (root / "nested").exists()


@pytest.mark.parametrize("fault", ["backup", "install"])
def test_effect_then_error_is_classified_from_actual_state(root, monkeypatch, fault):
    target = root / "file"
    target.write_bytes(b"before")
    change = write_change(root, target, b"after", "replace")
    original = transaction_module.os.replace
    injected = False

    def replace(source, destination, **options):
        nonlocal injected
        is_backup = "remek-backup" in destination
        is_install = "remek-stage" in source
        original(source, destination, **options)
        if not injected and (
            (fault == "backup" and is_backup) or (fault == "install" and is_install)
        ):
            injected = True
            raise OSError(f"{fault} returned an error after taking effect")

    monkeypatch.setattr(transaction_module.os, "replace", replace)
    assert apply_changes([change]).changed is True
    assert target.read_bytes() == b"after"
    assert not list(root.glob(".remek-*-*"))


def test_third_commit_failure_restores_every_destination(root, monkeypatch):
    changes = [write_change(root, root / name, name.encode(), name) for name in ("a", "b", "c")]
    original = transaction_module.os.replace
    installs = 0

    def replace(source, destination, **options):
        nonlocal installs
        if "remek-stage" in source:
            installs += 1
            if installs == 3:
                raise OSError("third install")
        original(source, destination, **options)

    monkeypatch.setattr(transaction_module.os, "replace", replace)
    with pytest.raises(RemekError, match="prior state was restored"):
        apply_changes(changes)
    assert not any((root / name).exists() for name in ("a", "b", "c"))
    assert not list(root.glob(".remek-*-*"))


def test_rollback_interruption_after_effect_still_restores(root, monkeypatch):
    target = root / "file"
    target.write_bytes(b"before")
    change = write_change(root, target, b"after", "replace")
    original = transaction_module.os.replace
    interrupted = False

    def replace(source, destination, **options):
        nonlocal interrupted
        original(source, destination, **options)
        if "remek-rollback" in destination and not interrupted:
            interrupted = True
            raise KeyboardInterrupt

    def fail():
        raise RemekError("verification failed")

    monkeypatch.setattr(transaction_module.os, "replace", replace)
    with pytest.raises(RemekError, match="verification failed"):
        apply_changes([change], verify=fail)
    assert target.read_bytes() == b"before"
    assert not list(root.glob(".remek-*-*"))


def test_compound_rollback_failure_preserves_named_residue(root, monkeypatch):
    target = root / "file"
    target.write_bytes(b"before")
    change = write_change(root, target, b"after", "replace")
    original = transaction_module.os.replace

    def replace(source, destination, **options):
        if "remek-rollback" in destination:
            raise OSError("rollback blocked")
        original(source, destination, **options)

    def fail():
        raise RemekError("verification failed")

    monkeypatch.setattr(transaction_module.os, "replace", replace)
    with pytest.raises(RemekError, match="exact residue") as captured:
        apply_changes([change], verify=fail)
    assert captured.value.changed is True
    assert target.read_bytes() == b"after"
    assert list(root.glob(".remek-backup-*"))


@pytest.mark.skipif(os.name != "posix", reason="opened-boundary contract is POSIX only")
def test_umask_preserves_planned_file_mode(root):
    previous = os.umask(0o077)
    try:
        apply_changes([write_change(root, root / "run", b"run", "mode", mode=0o751)])
    finally:
        os.umask(previous)
    assert (root / "run").stat().st_mode & 0o777 == 0o751
