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


@pytest.fixture
def replacement(root):
    target = root / "file"
    target.write_bytes(b"before")
    return target, write_change(root, target, b"after", "replace")


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
    assert outcome == ApplyOutcome(True, (str(root / "one"), str(root / "two")))
    assert outcome.outcome == "applied"


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
def test_effect_then_error_is_classified_from_actual_state(root, monkeypatch, fault, replacement):
    target, change = replacement
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
    outcome = apply_changes([change])
    assert outcome.changed is True
    assert outcome.outcome == "applied"
    assert outcome.changed_paths == (str(target),)
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
    with pytest.raises(RemekError, match="prior state was restored") as captured:
        apply_changes(changes)
    assert captured.value.outcome == "restored"
    assert captured.value.changed is False
    assert captured.value.exit_code == 2
    assert captured.value.changed_paths == ()
    assert captured.value.residue == ()
    assert not any((root / name).exists() for name in ("a", "b", "c"))
    assert not list(root.glob(".remek-*-*"))


def test_rollback_interruption_after_effect_still_restores(root, monkeypatch, replacement):
    target, change = replacement
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


def test_compound_rollback_failure_preserves_named_residue(root, monkeypatch, replacement):
    target, change = replacement
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
    assert captured.value.outcome == "residue"
    assert captured.value.exit_code == 3
    assert captured.value.changed_paths == (str(target),)
    assert target.read_bytes() == b"after"
    backups = list(root.glob(".remek-backup-*"))
    assert backups
    assert {item["path"] for item in captured.value.residue} == {str(target), str(backups[0])}


def test_empty_transaction_has_explicit_unchanged_outcome():
    outcome = apply_changes([])
    assert outcome.outcome == "unchanged"
    assert outcome.changed is False
    assert outcome.changed_paths == ()


def test_interrupted_commit_reports_verified_restoration(replacement):
    target, change = replacement

    def interrupt():
        raise KeyboardInterrupt

    with pytest.raises(RemekError, match="prior state was restored") as captured:
        apply_changes([change], verify=interrupt)
    assert captured.value.outcome == "restored"
    assert captured.value.changed is False
    assert captured.value.exit_code == 130
    assert captured.value.residue == ()
    assert target.read_bytes() == b"before"


def test_cleanup_probe_failure_preserves_known_change_and_names_unknown_path(
    root, monkeypatch, replacement
):
    target, change = replacement
    original = transaction_module.probe
    committed = False

    def verified():
        nonlocal committed
        committed = True

    def unreadable(parent, name):
        if committed and "remek-backup" in name:
            raise RemekError("forced unreadable cleanup")
        return original(parent, name)

    monkeypatch.setattr(transaction_module, "probe", unreadable)
    with pytest.raises(RemekError, match="cleanup residue") as captured:
        apply_changes([change], verify=verified)
    failure = captured.value
    assert failure.outcome == "unknown"
    assert failure.changed is True
    assert failure.exit_code == 3
    assert failure.changed_paths == (str(target),)
    assert failure.residue[0]["identity"] == "unknown"
    assert failure.residue[0]["path"] == str(next(root.glob(".remek-backup-*")))
    assert target.read_bytes() == b"after"


def test_cleanup_error_after_effect_uses_observed_absence(root, monkeypatch, replacement):
    target, change = replacement
    original = transaction_module.remove_at

    def remove_then_interrupt(parent, name, expected):
        original(parent, name, expected)
        if "remek-backup" in name:
            raise KeyboardInterrupt

    monkeypatch.setattr(transaction_module, "remove_at", remove_then_interrupt)
    outcome = apply_changes([change])
    assert outcome.outcome == "applied"
    assert outcome.changed_paths == (str(target),)
    assert target.read_bytes() == b"after"
    assert not list(root.glob(".remek-*-*"))


def test_descriptor_interruption_preserves_applied_and_restored_outcomes(monkeypatch, replacement):
    target, change = replacement
    original = transaction_module._close

    def interrupted_close(states, boundaries):
        original(states, boundaries)
        raise KeyboardInterrupt

    monkeypatch.setattr(transaction_module, "_close", interrupted_close)
    with pytest.raises(RemekError) as captured:
        apply_changes([change])
    error = captured.value
    assert error.code == "transaction.finalize" and error.outcome == "applied"
    assert error.changed and error.exit_code == 3 and error.changed_paths == (str(target),)
    assert target.read_bytes() == b"after"

    target.write_bytes(b"before")

    def refuse():
        raise RemekError("fixture.postcondition", "semantic check failed")

    with pytest.raises(RemekError) as captured:
        apply_changes([change], verify=refuse)
    error = captured.value
    assert error.code == "fixture.postcondition" and error.outcome == "restored"
    assert not error.changed and error.exit_code == 2
    assert target.read_bytes() == b"before"


@pytest.mark.skipif(os.name != "posix", reason="opened-boundary contract is POSIX only")
def test_umask_preserves_planned_file_mode(root):
    previous = os.umask(0o077)
    try:
        apply_changes([write_change(root, root / "run", b"run", "mode", mode=0o751)])
    finally:
        os.umask(previous)
    assert (root / "run").stat().st_mode & 0o777 == 0o751
