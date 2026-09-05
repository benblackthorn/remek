"""One-time converter preservation and refusal boundaries, using synthetic v1 bytes."""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import distribution_document, git_commit

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from tools import migrate_v1 as migration  # noqa: E402


def legacy(path, kind, **fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"schema": "remek.1", "kind": kind, **fields}, indent=2, sort_keys=True) + "\n"
    )


def fixture(tmp_path, *, imported=False, project=False, producer=False):
    source, archive = tmp_path / "old", tmp_path / "backup"
    names = ["remek"] if producer else ["active", "retired"]
    source.mkdir()
    target = tmp_path / "rehearsals" / "rehearsal"
    target.parent.mkdir()
    skills_root = ".agents/skills" if project else "skills"
    legacy(
        source / "remek.json",
        "repository",
        repositoryId="11111111-1111-4111-8111-111111111111",
        skillsRoot=skills_root,
        governedSkills=names,
    )
    (source / "README.md").write_bytes(b"owner prose\r\n<!-- remek-skills:start -->\r\n")
    (source / "remek").write_bytes(b"old wrapper\n")
    (source / "gate").write_bytes(b"old gate\n")
    bundle = source / ("skills/remek/toolchain" if producer else ".remek/toolchain")
    bundle.mkdir(parents=True)
    (bundle / "old-runtime.py").write_bytes(b"raise RuntimeError('never import me')\n")
    if producer:
        (source / "skills/remek/scripts").mkdir()
        (source / "skills/remek/scripts/cli.py").write_bytes(b"old bootstrap\n")
    for name in names:
        skill = source / skills_root / name
        skill.mkdir(parents=True, exist_ok=True)
        (skill / "SKILL.md").write_bytes(
            (
                f"---\r\nname: {name}\r\n"
                "description: Use when inspecting a synthetic deployment.\r\n"
                "license: MIT\r\n---\r\n# Instructions\r\n\r\n"
                "Inspect the exact deployment before changing it.\r\n"
            ).encode()
        )
        (skill / "run.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
        (skill / "run.sh").chmod(0o755)
        base = source / ".remek/skills" / name
        retained = (
            b'{"legacy": "manifest of normalized bytes"}\n'
            if imported
            else b"# Actual retained design\r\n"
        )
        legacy(
            base / "policy.json",
            "skill-policy",
            skill=name,
            lifecycle="retired" if name == "retired" else "ready",
            exposure="private-only",
            stateReason="Owner recorded this exact old state.",
        )
        legacy(
            base / "provenance.json",
            "provenance",
            skill=name,
            origin="imported" if imported else "designed",
            sourceDigest=hashlib.sha256(retained).hexdigest(),
            sourceLabel="source.md",
            upstreamRepository="https://example.test/original" if imported else "",
            upstreamRef="main" if imported else "",
            upstreamCandidate="c" * 64 if imported else "",
            rights="owned",
            rightsBasis="Synthetic test author wrote these instructions.",
            license="MIT",
        )
        (base / "sources").mkdir()
        (base / "sources/source.md").write_bytes(retained)
        legacy(
            base / "routing-cases.json",
            "routing-cases",
            cases=[
                {"id": "positive", "prompt": "Inspect deployment", "shouldActivate": True},
                {"id": "negative", "prompt": "Write a poem", "shouldActivate": False},
            ],
        )
        legacy(
            base / "behavior-cases.json",
            "behavior-cases",
            cases=[
                {
                    "id": "inspection",
                    "prompt": "Inspect current state",
                    "expectations": ["Shows the exact current state"],
                }
            ],
        )
        (base / "evidence").mkdir()
        (base / "evidence/broken.json").write_bytes(b"{malformed old evidence\r\n")
        (base / "approvals").mkdir()
        legacy(base / "approvals/old.json", "approval", reviewer="old owner")
    distribution = distribution_document("team", names[0])
    distribution["skills"] = names
    for key in ("schema", "kind", "activeReview"):
        distribution.pop(key)
    legacy(source / ".remek/distributions/team.json", "distribution", **distribution)
    legacy(
        source / ".remek/disclosure-policy.json",
        "disclosure-policy",
        entries=[
            {
                "id": "active",
                "class": "note",
                "match": "literal",
                "value": "internal-test",
                "retired": False,
            },
            {
                "id": "retired",
                "class": "note",
                "match": "literal",
                "value": "old-test",
                "retired": True,
            },
        ],
    )
    shutil.copytree(source, archive)
    archive.chmod(0o700)
    return source, archive, target


def saved(tmp_path, source, archive, target):
    path = tmp_path / "operation.json"
    plan = migration._conversion_plan(source, target, archive)
    data, _ = migration.operation_document(plan, migration.BUNDLE)
    migration.write_artifact(path, data)
    return path, plan


def test_conversion_preserves_payload_identity_and_archives_history(tmp_path):
    source, archive, target = fixture(tmp_path, imported=True, project=True)
    ordinary_log = Path(".agents/skills/active/evidence/log.txt")
    retained_source = Path(".remek/skills/active/sources/policy.json")
    for root in (source, archive):
        (root / ordinary_log).parent.mkdir()
        (root / ordinary_log).write_bytes(b"ordinary authored payload log\n")
        (root / retained_source).write_bytes(b"retained source with declaration-like name\n")
    before = migration._inventory_v1(source)
    operation_path, plan = saved(tmp_path, source, archive, target)
    assert not target.exists()
    migration.apply_changes(plan.changes)
    config = json.loads((target / "remek.json").read_text())
    assert config["repositoryId"] == before.config.repository_id
    assert config["skillsRoot"] == ".agents/skills"
    for name in ("active", "retired"):
        for filename in ("SKILL.md", "run.sh"):
            old, new = (
                source / ".agents/skills" / name / filename,
                target / ".agents/skills" / name / filename,
            )
            assert new.read_bytes() == old.read_bytes()
            assert stat.S_IMODE(new.stat().st_mode) == stat.S_IMODE(old.stat().st_mode)
    record = json.loads((target / ".remek/skills/active/skill.json").read_text())
    assert "not the original imported source tree" in record["provenance"]["sourceNote"]
    assert "upstreamCandidate" not in record["provenance"]
    assert record["cases"]["routing"][0]["id"] == "positive"
    assert (
        json.loads((target / ".remek/skills/retired/skill.json").read_text())["exposure"]
        == "source-only"
    )
    distribution = json.loads((target / ".remek/distributions/team.json").read_text())
    assert distribution["skills"] == ["active"] and distribution["activeReview"] is None
    assert list((target / ".remek/skills/active/evidence").iterdir()) == []
    assert list((target / ".remek/reviews").iterdir()) == []
    assert len(json.loads((target / ".remek/disclosure-policy.json").read_text())["entries"]) == 1
    assert (target / "README.md").read_bytes() == (source / "README.md").read_bytes()
    assert migration._inventory_v1(source).tree == before.tree
    assert migration._verify_archive(before, archive)
    mapping = plan.data["mapping"]
    for preserved in (ordinary_log, retained_source):
        row = next(row for row in mapping["mapping"] if row["oldPath"] == str(preserved))
        assert row["disposition"] == "preserved" and row["activeDestination"] == str(preserved)
        assert (target / preserved).read_bytes() == (source / preserved).read_bytes()
    assert any("malformed legacy" in row["disposition"] for row in mapping["mapping"])
    assert mapping["distributionGates"][0]["profiles"] == distribution["evidencePolicy"]
    assert not migration._conversion_plan(source, target, archive).changes
    assert not migration._reconstruct(migration.load_operation_plan(operation_path)).changes


@pytest.mark.parametrize("layout", ["consumer", "project", "producer", "absent"])
def test_cli_rehearsal_preserves_foreign_objects(tmp_path, layout):
    source, archive, target = fixture(
        tmp_path, project=layout == "project", producer=layout == "producer"
    )
    before = migration._inventory_v1(source)
    if layout != "absent":
        shutil.copytree(source, target)
        target.chmod(0o700)
        (target / "owner-note").write_bytes(b"unique untracked work\0")
        (target / "owner-link").symlink_to("owner-note")
    path = tmp_path / "migration.json"
    commands = [
        [
            "plan",
            "--source",
            str(source),
            "--archive",
            str(archive),
            "--target",
            str(target),
            "--output",
            str(path),
        ],
        ["show", str(path)],
        ["apply", str(path)],
        ["apply", str(path)],
    ]
    if layout == "consumer":
        residue = target / ".remek-backup-foreign"
        residue.write_bytes(b"foreign; never discard")
        assert migration.main(commands[0]) == 2
        assert residue.read_bytes() == b"foreign; never discard" and not path.exists()
        residue.unlink()
    for command in commands:
        result = subprocess.run(
            [sys.executable, "-B", str(PROJECT / "tools/migrate_v1.py"), *command],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == 0, result.stderr
    if layout != "absent":
        assert (target / "owner-note").read_bytes() == b"unique untracked work\0"
        assert os.readlink(target / "owner-link") == "owner-note"
    for item in before.tree.files:
        if Path(item.path).name in {"SKILL.md", "run.sh"}:
            assert (target / item.path).read_bytes() == item.data
            assert stat.S_IMODE((target / item.path).stat().st_mode) == item.mode
    assert migration._inventory_v1(source).tree == before.tree
    assert migration._verify_archive(before, archive)
    final = migration._conversion_plan(source, target, archive)
    migration._verify_result(final)
    assert not final.changes
    if layout == "producer":
        assert not (target / ".remek/toolchain").exists()
        assert (target / "skills/remek/scripts/cli.py").read_bytes() == (
            PROJECT / "skills/remek/scripts/cli.py"
        ).read_bytes()
        assert (archive / "skills/remek/toolchain/old-runtime.py").read_bytes() == (
            b"raise RuntimeError('never import me')\n"
        )
        assert not (target / "skills/remek/toolchain/old-runtime.py").exists()
        assert final.data["mapping"]["managedToolchain"] == "skills/remek/toolchain"


def test_saved_conversion_refuses_source_archive_and_target_drift(tmp_path):
    source, archive, target = fixture(tmp_path)
    path, _ = saved(tmp_path, source, archive, target)
    loaded = migration.load_operation_plan(path)
    changed = source / "skills/active/SKILL.md"
    original = changed.read_bytes()
    changed.write_bytes(original + b"revision\n")
    with pytest.raises(migration.RemekError, match="archive"):
        migration._reconstruct(loaded)
    changed.write_bytes(original)
    backup = archive / "skills/active/SKILL.md"
    backup.write_bytes(original + b"altered backup\n")
    with pytest.raises(migration.RemekError, match="archive"):
        migration._reconstruct(loaded)
    backup.write_bytes(original)
    target.mkdir()
    (target / "foreign").write_text("do not replace")
    with pytest.raises((migration.RemekError, OSError)):
        migration._reconstruct(loaded)
    assert (target / "foreign").read_text() == "do not replace"


def test_archive_overlap_and_unsafe_owned_objects_refuse(tmp_path):
    source, archive, target = fixture(tmp_path)
    with pytest.raises(migration.RemekError, match="disjoint"):
        migration._conversion_plan(source, source / "target", archive)
    with pytest.raises(migration.RemekError, match="disjoint"):
        migration._conversion_plan(source, target, source)
    path = source / "skills/active/run.sh"
    original = path.read_bytes()
    path.unlink()
    path.symlink_to("SKILL.md")
    with pytest.raises(migration.RemekError):
        migration._conversion_plan(source, target, archive)
    path.unlink()
    path.write_bytes(original)
    os.link(path, source / "outside-owned-hardlink")
    with pytest.raises(migration.RemekError):
        migration._conversion_plan(source, target, archive)
    assert not target.exists()


def test_missing_declarations_and_mixed_schema_never_invent_values(tmp_path):
    source, archive, target = fixture(tmp_path)
    path = source / ".remek/skills/active/provenance.json"
    original = path.read_bytes()
    document = json.loads(original)
    document.pop("rightsBasis")
    path.write_text(json.dumps(document))
    (archive / path.relative_to(source)).write_bytes(path.read_bytes())
    with pytest.raises(migration.RemekError, match="rightsBasis"):
        migration._conversion_plan(source, target, archive)
    document = json.loads(original)
    document["schema"] = "remek.2"
    path.write_text(json.dumps(document))
    (archive / path.relative_to(source)).write_bytes(path.read_bytes())
    with pytest.raises(migration.RemekError, match="mixed schema"):
        migration._conversion_plan(source, target, archive)
    assert not target.exists()


def test_missing_retained_origin_is_limited_and_changed_retained_digest_refuses(tmp_path):
    source, archive, target = fixture(tmp_path)
    path = Path(".remek/skills/active/sources/source.md")
    original = (source / path).read_bytes()
    (source / path).write_bytes(original + b"changed")
    (archive / path).write_bytes(original + b"changed")
    with pytest.raises(migration.RemekError, match="retained source digest differs"):
        migration._conversion_plan(source, target, archive)
    (source / path).unlink()
    (archive / path).unlink()
    plan = migration._conversion_plan(source, target, archive)
    migration.apply_changes(plan.changes)
    record = json.loads((target / ".remek/skills/active/skill.json").read_text())
    assert record["provenance"]["source"] is None
    assert "No verifiable retained origin" in record["provenance"]["sourceNote"]


@pytest.mark.parametrize("failure", ["prevalidation", "installed", "postcleanup", "temporary"])
def test_conversion_failure_preserves_phase_and_foreign_data(
    tmp_path, monkeypatch, capsys, failure
):
    source, archive, target = fixture(tmp_path)
    if failure == "prevalidation":
        for root in (source, archive):
            (root / "skills/active/SKILL.md").write_bytes(b"invalid skill without frontmatter")
    shutil.copytree(source, target)
    target.chmod(0o700)
    before = migration._inventory_v1(source)
    path, plan = saved(tmp_path, source, archive, target)
    migration.write_artifact(
        Path(str(path) + ".mapping.json"), migration._json(plan.data["mapping"])
    )
    verify, installed, fingerprint = (
        migration._verify_result,
        migration._verify_installed,
        migration.fingerprint,
    )

    def verify_result(current):
        if failure == "postcleanup" and current.root == target:
            (target / ".remek-backup-foreign").write_bytes(b"foreign; never discard")
        verify(current)

    def verify_installed(current):
        with monkeypatch.context() as patch:
            patch.setattr(
                migration,
                "fingerprint",
                lambda p: (
                    "wrong installed identity" if p == current.changes[0].path else fingerprint(p)
                ),
            )
            installed(current)

    if failure == "installed":
        monkeypatch.setattr(migration, "_verify_installed", verify_installed)
    monkeypatch.setattr(migration, "_verify_result", verify_result)
    temporary = tmp_path / "private-validation"
    if failure == "temporary":
        temporary.mkdir(mode=0o700)
        monkeypatch.setattr(migration, "mkdtemp", lambda **_: str(temporary))

        def fail_cleanup(*_):
            raise OSError("injected cleanup failure")

        monkeypatch.setattr(migration, "remove_at", fail_cleanup)
    assert migration.main(["apply", str(path)]) == (
        3 if failure in {"postcleanup", "temporary"} else 2
    )
    diagnostic = capsys.readouterr().err
    if failure == "postcleanup":
        assert json.loads((target / "remek.json").read_text())["schema"] == "remek.2"
        assert "changed=true" in diagnostic and str(target / ".remek") in diagnostic
        assert (target / ".remek-backup-foreign").read_bytes() == b"foreign; never discard"
        assert ".remek-backup-foreign" in diagnostic
    else:
        assert migration._inventory_v1(target).tree == before.tree
    if failure == "installed":
        assert "prior state was restored" in diagnostic
    if failure == "temporary":
        assert str(temporary) in diagnostic and "rehearsal unchanged" in diagnostic
        assert migration.snapshot_tree(temporary / "source") == plan.data["expected"]
    assert migration._inventory_v1(source).tree == before.tree
    assert migration._verify_archive(before, archive)


def test_cli_private_plan_mapping_and_no_overwrite(tmp_path, capsys):
    source, archive, target = fixture(tmp_path)
    path = tmp_path / "private-plan.json"
    arguments = [
        "plan",
        "--source",
        str(source),
        "--target",
        str(target),
        "--archive",
        str(archive),
        "--output",
        str(path),
    ]
    assert migration.main(arguments) == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    mapping = Path(str(path) + ".mapping.json")
    assert stat.S_IMODE(mapping.stat().st_mode) == 0o600
    assert migration.main(["show", str(path)]) == 0
    assert "historical-only" in capsys.readouterr().out
    assert migration.main(arguments) == 2
    original_mapping = mapping.read_bytes()
    mapping.write_bytes(original_mapping + b" ")
    assert migration.main(["apply", str(path)]) == 2
    assert not target.exists()
    mapping.write_bytes(original_mapping)
    assert migration.main(["apply", str(path)]) == 0
    assert migration.main(["apply", str(path)]) == 0
    assert "Applied conversion to rehearsal only." in capsys.readouterr().out
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    migration._verify_result(migration._conversion_plan(source, target, archive))


def test_git_inventory_preserves_dirty_and_untracked_owned_work(tmp_path):
    source, archive, target = fixture(tmp_path)

    git_commit(source, "Synthetic v1 checkpoint")
    changed = source / "skills/active/SKILL.md"
    changed.write_bytes(changed.read_bytes() + b"\r\nUncommitted owner revision.\r\n")
    (source / "skills/active/untracked.md").write_bytes(b"untracked owned bytes\n")
    archive = tmp_path / "dirty-backup"
    shutil.copytree(source, archive)
    archive.chmod(0o700)
    plan = migration._conversion_plan(source, target, archive)
    report = plan.data["mapping"]["inventory"]["git"]
    assert len(report["head"]) == 40
    assert report["branch"] == "refs/heads/main"
    assert "skills/active/SKILL.md" in report["workingOwnedPathsDifferentFromRawHead"]
    assert "skills/active/untracked.md" in report["workingOwnedPathsDifferentFromRawHead"]
    migration.apply_changes(plan.changes)
    assert (target / "skills/active/SKILL.md").read_bytes() == changed.read_bytes()
    assert (target / "skills/active/untracked.md").read_bytes() == b"untracked owned bytes\n"


def test_converter_refuses_uninventoried_governance_and_escaping_source_claim(tmp_path):
    source, archive, target = fixture(tmp_path)
    note = source / ".remek/owner-notes.txt"
    note.write_bytes(b"unique owner work\n")
    with pytest.raises(migration.RemekError, match="unknown governance file"):
        migration._conversion_plan(source, target, archive)
    assert note.read_bytes() == b"unique owner work\n"
    note.rename(source / "owner-notes.txt")
    empty = source / ".remek/unclassified"
    empty.mkdir()
    with pytest.raises(migration.RemekError, match="unknown governance directory"):
        migration._conversion_plan(source, target, archive)
    empty.rename(source / "unclassified")
    path = source / ".remek/skills/active/provenance.json"
    declaration = json.loads(path.read_text())
    declaration["sourceLabel"] = "../secret"
    path.write_text(json.dumps(declaration))
    (archive / path.relative_to(source)).write_bytes(path.read_bytes())
    with pytest.raises(migration.RemekError):
        migration._conversion_plan(source, target, archive)
    assert not target.exists()


def test_apply_output_failure_preserves_changed_exit_even_if_stderr_fails(tmp_path, monkeypatch):
    source, archive, target = fixture(tmp_path)
    path, plan = saved(tmp_path, source, archive, target)
    migration.write_artifact(
        Path(str(path) + ".mapping.json"), migration._json(plan.data["mapping"])
    )

    def broken_output(*_args, **_kwargs):
        raise BrokenPipeError("output stream closed")

    monkeypatch.setattr(migration, "print", broken_output, raising=False)
    assert migration.main(["apply", str(path)]) == 3
    assert json.loads((target / "remek.json").read_text())["schema"] == "remek.2"
    assert migration._verify_archive(migration._inventory_v1(source), archive)


def test_closed_output_pipes_preserve_real_conversion_exit(tmp_path):
    source, archive, target = fixture(tmp_path)
    path, plan = saved(tmp_path, source, archive, target)
    migration.write_artifact(
        Path(str(path) + ".mapping.json"), migration._json(plan.data["mapping"])
    )
    with subprocess.Popen(
        [sys.executable, "-B", str(PROJECT / "tools/migrate_v1.py"), "apply", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        process.stdout.close()
        process.stderr.close()
        assert process.wait(timeout=15) == 3
    assert json.loads((target / "remek.json").read_text())["schema"] == "remek.2"
    assert migration._verify_archive(migration._inventory_v1(source), archive)
