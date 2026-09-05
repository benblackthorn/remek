import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

import pytest
import remek_core.transaction as transaction_module
import remek_core.workflows as workflows_module
from helpers import (
    PROJECT,
    TOOLCHAIN,
    apply,
    authored,
    authored_distribution,
    completed_evaluation,
    disclosure_document,
    disclosure_entry,
    distribution_document,
    git_commit,
    initialized,
    mirror,
    ready_source,
    record_evidence,
    record_review,
    set_exposure,
    write_input,
)
from remek_core.contract import load_document
from remek_core.model import Error
from remek_core.repository import (
    evaluation_plan,
    inspect_repository,
    repository_findings,
)
from remek_core.review import release_findings
from remek_core.workflows import (
    _git_state,
    _run,
    _skills_payload,
    eval_record_plan,
    release_plan,
    release_verify,
    update_plan,
    verify_github_target,
    verify_materialized_release,
)

VERIFY_TARGET = "remek_core.workflows.verify_github_target"
VERIFY_SCRIPT = PROJECT / "tools/verify_release_manifest.py"
HTTPS_REMOTE = "https://github.com/business-a/private-skills.git"


def verified_target(target, _forbidden_roots=()):
    return {
        "provider": "github",
        "hostname": target["hostname"],
        "nameWithOwner": target["nameWithOwner"],
        "visibility": target["expectedVisibility"],
    }


def release_roots(tmp_path, monkeypatch):
    root = ready_source(tmp_path)
    git_commit(root)
    target = mirror(tmp_path)
    monkeypatch.setattr(VERIFY_TARGET, verified_target)
    return root, target


def release(root, target, **options):
    return release_plan(root, "org-private", mirror=target, **options)


def reported_evaluation(root, kind, distribution=None):
    return completed_evaluation(
        evaluation_plan(inspect_repository(root), "deploy-safely", kind, distribution).template()
    )


def reviewed_distributions(tmp_path):
    root = ready_source(tmp_path)
    write_input(
        root / ".remek/distributions/other-private.json", distribution_document("other-private")
    )
    artifact = write_input(
        tmp_path / "other-routing.json", reported_evaluation(root, "routing", "other-private")
    )
    apply(eval_record_plan(root, "deploy-safely", artifact))
    record_review(tmp_path, root, distribution="other-private")
    unrelated = distribution_document("unrelated")
    unrelated["skills"] = []
    write_input(root / ".remek/distributions/unrelated.json", unrelated)
    record_review(tmp_path, root, distribution="unrelated")
    return root


def materialized_release(tmp_path, monkeypatch):
    root, target = release_roots(tmp_path, monkeypatch)
    apply(release(root, target))
    return root, target


def execution_sentinel(tmp_path):
    marker = tmp_path / "executed"
    command = tmp_path / "sentinel.py"
    command.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n"
    )
    command.chmod(0o755)
    return command, marker


def fake_tool(directory, name, body):
    directory.mkdir(parents=True, exist_ok=True)
    command = directory / name
    command.write_text(f"#!{sys.executable}\n{body}\n")
    command.chmod(0o755)
    return command


def git(root, *arguments, **options):
    return subprocess.run(
        ["git", *arguments], cwd=root, check=options.pop("check", True), **options
    )


def test_subprocess_output_is_bounded(tmp_path, monkeypatch):
    with pytest.raises(Error, match="output exceeds"):
        _run(
            [sys.executable, "-c", "import os; os.write(1, b'x' * 2048)"],
            cwd=tmp_path,
            output_limit=1024,
        )
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    def fail_registration(*_args):
        raise OSError("selector registration failed")

    monkeypatch.setattr(workflows_module.selectors.DefaultSelector, "register", fail_registration)
    with pytest.raises(Error, match="query failed"):
        workflows_module._capture_process(child, ["synthetic child"], 1024)
    assert child.returncode is not None


def test_parent_cancellation_reaps_target_query(tmp_path):
    root = ready_source(tmp_path)
    git_commit(root)
    target = mirror(tmp_path)
    started, finished = tmp_path / "child.pid", tmp_path / "child-finished"
    trusted = tmp_path / "bin"
    fake_tool(
        trusted,
        "gh",
        "import os,time\nfrom pathlib import Path\n"
        f"Path({str(started)!r}).write_text(str(os.getpid()))\n"
        f"time.sleep(10)\nPath({str(finished)!r}).touch()",
    )
    before = workflows_module.snapshot(root / ".remek").digest
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(TOOLCHAIN.parent / "scripts/cli.py"),
            "--root",
            str(root),
            "--json",
            "release",
            "plan",
            "org-private",
            "--mirror",
            str(target),
        ],
        env={**os.environ, "PATH": str(trusted) + os.pathsep + os.environ["PATH"]},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while not started.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert started.exists()
        child = int(started.read_text())
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 130, stderr
        assert json.loads(stdout)["changed"] is False
        with pytest.raises(ProcessLookupError):
            os.kill(child, 0)
        assert not finished.exists() and not (target / "release-manifest.json").exists()
        assert workflows_module.snapshot(root / ".remek").digest == before
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        if started.exists():
            with suppress(ProcessLookupError):
                os.kill(int(started.read_text()), signal.SIGKILL)


def test_deleted_credential_path_cannot_enter_release_manifest(tmp_path, monkeypatch):
    _root, target = materialized_release(tmp_path, monkeypatch)
    manifest = json.loads((target / "release-manifest.json").read_text())
    secret = "gh" + "p_" + "x" * 24
    manifest["expectedCommitPaths"] = [
        f"skills/deploy-safely/{secret}.txt",
        "release-manifest.json",
    ]
    with pytest.raises(Error) as captured:
        workflows_module._manifest(manifest, "release.manifest")
    assert secret not in str(captured.value)


def test_external_tool_uses_canonical_executable_and_filtered_path(tmp_path):
    trusted = tmp_path / "trusted"
    surviving = tmp_path / "surviving"
    surviving.mkdir()
    missing = tmp_path / "missing"
    nondirectory = tmp_path / "not-a-directory"
    nondirectory.write_text("not a PATH directory")
    command = fake_tool(
        trusted,
        "git",
        "import json, os, sys; print(json.dumps([sys.argv[0], os.environ['PATH']]))",
    )
    environment = {
        **os.environ,
        "PATH": os.pathsep.join(map(str, (missing, trusted, nondirectory, surviving))),
    }

    completed = _run(
        ["git"],
        cwd=tmp_path,
        environment=environment,
        forbidden_roots=(tmp_path / "selected",),
    )

    executable, child_path = json.loads(completed.stdout)
    assert Path(executable) == command.resolve()
    assert child_path == os.pathsep.join(map(str, (trusted.resolve(), surviving.resolve())))


def test_external_tool_refuses_empty_and_relative_path_entries(tmp_path):
    trusted = tmp_path / "trusted"
    fake_tool(trusted, "git", "pass")
    for value in (f".:{trusted}", f"{trusted}:", f"relative:{trusted}"):
        with pytest.raises(Error, match="nonempty absolute"):
            _run(
                ["git"],
                cwd=tmp_path,
                environment={**os.environ, "PATH": value},
                forbidden_roots=(tmp_path / "selected",),
            )


def test_update_refreshes_toolchain_and_shims(tmp_path):
    root = initialized(tmp_path)
    for name in ("gate", "remek"):
        (root / name).write_text("x")
    bundle = tmp_path / "bundle"
    shutil.copytree(PROJECT / "skills/remek/toolchain", bundle)
    gate = bundle / "assets/gate"
    gate.write_bytes(gate.read_bytes() + b"\n#x\n")
    path = bundle / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["files"]["assets/gate"][1] = hashlib.sha256(gate.read_bytes()).hexdigest()
    path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")

    plan = update_plan(root, bundle)
    assert plan.bindings["sourceToolchain"] == plan.changes[0].after
    apply(plan)
    assert (root / "gate").read_bytes() == gate.read_bytes()
    assert not [
        item for item in repository_findings(inspect_repository(root)) if item.severity == "error"
    ]
    (root / ".remek/unknown").write_text("x")
    with pytest.raises(Error, match=r"governance\.layout"):
        update_plan(root, bundle)


def test_external_tool_refuses_canonical_directory_and_tool_targets(tmp_path, monkeypatch):
    selected = tmp_path / "selected"
    hostile = selected / "bin"
    marker = tmp_path / "hostile-ran"
    bad = fake_tool(
        hostile,
        "git",
        f"from pathlib import Path; Path({str(marker)!r}).touch()",
    )
    trusted = tmp_path / "trusted"
    fake_tool(trusted, "git", "import os; print(os.environ['PATH'])")
    directory_link = tmp_path / "directory-link"
    directory_link.symlink_to(hostile, target_is_directory=True)

    for first in (directory_link, tmp_path / "tool-link"):
        if first.name == "tool-link":
            first.mkdir()
            (first / "git").symlink_to(bad)
        completed = _run(
            ["git"],
            cwd=tmp_path,
            environment={**os.environ, "PATH": f"{first}:{trusted}"},
            forbidden_roots=(selected,),
        )
        assert completed.stdout == f"{trusted.resolve()}\n" and not marker.exists()

    for name in ("git", "gh"):
        hostile_tool = fake_tool(
            hostile,
            name,
            f"from pathlib import Path; Path({str(marker)!r}).touch()",
        )
        linked = tmp_path / f"linked-{name}"
        linked.mkdir()
        os.link(hostile_tool, linked / name)
        fallback = tmp_path / f"trusted-{name}"
        fake_tool(fallback, name, f"print('trusted {name}')")
        completed = _run(
            [name],
            cwd=tmp_path,
            environment={**os.environ, "PATH": f"{linked}:{fallback}"},
            forbidden_roots=(selected,),
        )
        assert completed.stdout == f"trusted {name}\n" and not marker.exists()
        with pytest.raises(Error, match=rf"cannot run {name}.*multiple hard links"):
            _run(
                [name],
                cwd=tmp_path,
                environment={**os.environ, "PATH": str(linked)},
                forbidden_roots=(selected,),
            )
        assert not marker.exists()

    answers = iter((str(selected), "false", ""))
    monkeypatch.setattr(workflows_module, "_git", lambda *_args, **_options: next(answers))
    monkeypatch.setenv("PATH", str(tmp_path / "linked-git"))
    with pytest.raises(Error, match=r"release integrity.*multiple hard links"):
        _git_state(selected)


@pytest.mark.parametrize("link_kind", ("symlink", "hardlink"))
def test_filtered_child_path_cannot_reenter_selected_root(tmp_path, link_kind):
    selected = tmp_path / "selected"
    hostile = selected / "bin"
    marker = tmp_path / "hostile-ran"
    hostile_git = fake_tool(
        hostile,
        "git",
        f"from pathlib import Path; Path({str(marker)!r}).touch()",
    )
    bridge = tmp_path / "bridge"
    bridge.mkdir()
    if link_kind == "symlink":
        (bridge / "git").symlink_to(hostile_git)
    else:
        os.link(hostile_git, bridge / "git")
    trusted_gh = tmp_path / "trusted-gh"
    fake_tool(
        trusted_gh,
        "gh",
        "import subprocess; result = subprocess.run(['git'], capture_output=True, text=True); "
        "print(result.stdout, end='')",
    )
    trusted_git = tmp_path / "trusted-git"
    fake_tool(trusted_git, "git", "print('trusted nested git')")

    completed = _run(
        ["gh"],
        cwd=tmp_path,
        environment={**os.environ, "PATH": f"{bridge}:{trusted_gh}:{trusted_git}"},
        forbidden_roots=(selected,),
    )

    assert completed.stdout == "trusted nested git\n" and not marker.exists()


def test_checkout_and_github_queries_refuse_selected_root_tools(tmp_path, monkeypatch):
    selected = tmp_path / "selected"
    hostile = selected / "bin"
    marker = tmp_path / "hostile-ran"
    body = f"from pathlib import Path; Path({str(marker)!r}).touch()"
    fake_tool(hostile, "git", body)
    fake_tool(hostile, "gh", body)
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setenv("PATH", str(hostile))

    with pytest.raises(Error, match="Git is required"):
        workflows_module._git_checkout_containing(outside, (selected,))
    with pytest.raises(Error, match="cannot run gh"):
        verify_github_target(distribution_document()["target"], (selected,))
    assert not marker.exists()

    trusted = tmp_path / "trusted"
    observation = json.dumps(
        {"nameWithOwner": "business-a/private-skills", "visibility": "PRIVATE"}
    )
    fake_tool(
        trusted,
        "gh",
        f"print({observation!r})",
    )
    monkeypatch.setenv("PATH", str(trusted))
    assert (
        verify_github_target(distribution_document()["target"], (selected,))["visibility"]
        == "PRIVATE"
    )


def test_external_tool_resolution_is_rechecked_for_each_root_set(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    fake_tool(first, "git", "import os; print('first|' + os.environ['PATH'])")
    fake_tool(second, "git", "import os; print('second|' + os.environ['PATH'])")
    environment = {**os.environ, "PATH": f"{first}:{second}"}

    initial = _run(
        ["git"],
        cwd=tmp_path,
        environment=environment,
        forbidden_roots=(tmp_path / "unrelated",),
    )
    rechecked = _run(
        ["git"],
        cwd=tmp_path,
        environment=environment,
        forbidden_roots=(first,),
    )

    assert initial.stdout == f"first|{first}:{second}\n"
    assert rechecked.stdout == f"second|{second}\n"


def test_update_changes_only_managed_files_and_preserves_foreign_data(tmp_path):
    root = initialized(tmp_path, project=True)
    foreign = root / "owner-notes.txt"
    foreign.write_bytes(b"unrelated owner data\n")
    (root / "remek").write_text("damaged\n")

    plan = update_plan(root, TOOLCHAIN)
    assert {change.path for change in plan.changes} == {root / "remek"}
    apply(plan)

    assert foreign.read_bytes() == b"unrelated owner data\n"
    assert (root / "remek").read_bytes() == (PROJECT / "skills/remek/scripts/cli.py").read_bytes()


def test_git_state_refuses_forged_pack_index(tmp_path):
    root = ready_source(tmp_path)
    git_commit(root)
    git(root, "repack", "-adf", "--window=0")
    index = next((root / ".git/objects/pack").glob("*.idx"))
    data = bytearray(index.read_bytes())
    count = int.from_bytes(data[1028:1032], "big")
    first_table = 1032 + count * 20
    for table in (first_table, first_table + count * 4):
        data[table : table + 8] = data[table + 4 : table + 8] + data[table : table + 4]
    data[-20:] = hashlib.sha1(data[:-20]).digest()
    index.chmod(0o600)
    index.write_bytes(data)
    with pytest.raises(Error, match="object integrity"):
        _git_state(root)


def test_git_state_refuses_hidden_inputs(tmp_path):
    root = ready_source(tmp_path)
    head = git_commit(root)
    command, marker = execution_sentinel(tmp_path)
    git(root, "config", "core.fsmonitor", str(command))
    assert _git_state(root)["head"] == head
    assert not marker.exists()
    git(root, "config", "fsck.missingEmail", "ignore")
    with pytest.raises(Error, match="fsck"):
        _git_state(root)
    git(root, "config", "--unset", "fsck.missingEmail")
    for flag, clear in (
        ("--assume-unchanged", "--no-assume-unchanged"),
        ("--skip-worktree", "--no-skip-worktree"),
    ):
        git(root, "update-index", flag, "remek.json")
        with pytest.raises(Error, match="index flags"):
            _git_state(root)
        git(root, "update-index", clear, "remek.json")
    git(root, "update-index", "--add", "--cacheinfo", f"160000,{head},nested")
    with pytest.raises(Error, match="submodules"):
        _git_state(root)
    git(root, "update-index", "--force-remove", "nested")
    grafts = root / ".git/info/grafts"
    grafts.write_text(f"{head}\n")
    with pytest.raises(Error, match="graft"):
        _git_state(root)
    grafts.unlink()
    (root / ".git/shallow").write_text(f"{head}\n")
    with pytest.raises(Error, match="complete history"):
        _git_state(root)


def test_release_requires_owned_files_in_raw_source_head(tmp_path, monkeypatch):
    root = ready_source(tmp_path)
    for name in (".gitattributes", "bad\\name"):
        unsupported = root / "skills/deploy-safely" / name
        unsupported.write_text("unsafe\n")
        with pytest.raises(Error, match="payload path"):
            _skills_payload((inspect_repository(root).skill("deploy-safely"),))
        unsupported.unlink()
    ignored = "skills/deploy-safely/ignored.txt"
    (root / ".gitignore").write_text(f"/{ignored}\n")
    (root / ignored).write_text("release payload\n")
    record_evidence(tmp_path, root)
    record_review(tmp_path, root)
    git_commit(root)
    assert (
        subprocess.run(
            ["git", "ls-files", "--error-unmatch", ignored],
            cwd=root,
            check=False,
            capture_output=True,
        ).returncode
        != 0
    )
    target = mirror(tmp_path)
    monkeypatch.setattr(VERIFY_TARGET, verified_target)
    with pytest.raises(Error, match="raw HEAD"):
        release(root, target)


def test_authored_distribution_and_disclosure_are_checked_without_rewriting(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    path = root / ".remek/distributions/org-private.json"
    document = distribution_document()
    path.write_text(json.dumps(document))
    raw = path.read_bytes()
    assert inspect_repository(root).distribution("org-private").skills == ("deploy-safely",)
    assert path.read_bytes() == raw
    secret = distribution_document("secret")
    secret["evidencePolicy"]["routingProfiles"][0]["name"] = "github_pat_" + "a" * 20
    persisted = root / ".remek/distributions/secret.json"
    write_input(persisted, secret)
    assert any(item.code == "credential.github-token" for item in inspect_repository(root).issues)
    persisted.unlink()
    write_input(
        root / ".remek/disclosure-policy.json",
        disclosure_document(disclosure_entry("private-profile", "secret-host", "credential")),
    )
    custom = distribution_document("custom")
    custom["evidencePolicy"]["routingProfiles"][0]["name"] = "secret-host"
    write_input(root / ".remek/distributions/custom.json", custom)
    assert any(item.code == "disclosure.credential" for item in inspect_repository(root).issues)


def test_empty_distribution_releases_and_verifies_without_skills(tmp_path, monkeypatch):
    root = initialized(tmp_path)
    document = distribution_document()
    document["skills"] = []
    write_input(root / ".remek/distributions/org-private.json", document)
    record_review(tmp_path, root)
    assert release_findings(inspect_repository(root), "org-private") == ()
    assert inspect_repository(root).skills == ()
    git_commit(root)
    target = mirror(tmp_path)
    monkeypatch.setattr(VERIFY_TARGET, verified_target)
    apply(release(root, target))
    assert not (target / "skills").exists()
    verifier = [sys.executable, str(VERIFY_SCRIPT), str(target)]
    assert subprocess.run(verifier, check=False).returncode == 0
    git_commit(target, "empty release")
    assert release_verify(root, "org-private", target)["artifactVerified"] is True
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(target), str(clone)], check=True)
    verifier[-1] = str(clone)
    assert subprocess.run(verifier, check=False).returncode == 0


def test_failed_evidence_persists_content_addressed(tmp_path, monkeypatch):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    authored_distribution(tmp_path, root)
    document = reported_evaluation(root, "routing", "org-private")
    for result in document["trials"]:
        result.update(
            outcome="fail", observation="Synthetic observed failure: expected route missing."
        )
    document["artifacts"] = [{"label": "evaluation-report", "digest": "d" * 64}]
    artifact = write_input(tmp_path / "failed.json", document)
    with monkeypatch.context() as bounded:
        bounded.setattr(workflows_module, "document_limit", lambda _kind: 1)
        with pytest.raises(Error, match="governance"):
            eval_record_plan(root, "deploy-safely", artifact)
    secret = "gh" + "p_abcdefghijklmnopqrstuvwxyz"
    document["artifacts"][0]["label"] = secret
    write_input(artifact, document)
    with pytest.raises(Error) as caught:
        eval_record_plan(root, "deploy-safely", artifact)
    assert secret not in str(caught.value)
    document["artifacts"][0]["label"] = "evaluation-report"
    write_input(artifact, document)
    first = eval_record_plan(root, "deploy-safely", artifact)
    assert first.data["reportedPassing"] is False
    apply(first)
    assert eval_record_plan(root, "deploy-safely", artifact).changes == ()
    evidence = root / ".remek/skills/deploy-safely/evidence"
    [report] = evidence.glob("*.json")
    assert report.name == f"{hashlib.sha256(report.read_bytes()).hexdigest()}.json"
    malformed = report.with_name("0" * 64 + ".json")
    report.rename(malformed)
    inspection = inspect_repository(root)
    assert inspection.skill("deploy-safely")
    finding = next(item for item in inspection.issues if item.code == "evidence.malformed")
    assert finding.path == str(malformed.relative_to(root))


def test_new_routing_report_revokes_only_its_distribution_and_duplicate_is_noop(tmp_path):
    root = reviewed_distributions(tmp_path)
    before = {
        dist.distribution_id: dist.active_review for dist in inspect_repository(root).distributions
    }
    duplicate = eval_record_plan(root, "deploy-safely", tmp_path / "routing-evidence.json")
    assert duplicate.changes == ()
    assert duplicate.data["revokedDistributions"] == []
    document = reported_evaluation(root, "routing", "org-private")
    document["trials"][0]["observation"] = "Synthetic rerun confirmed the same routing behavior."
    artifact = write_input(tmp_path / "rerun.json", document)
    planned = eval_record_plan(root, "deploy-safely", artifact)
    assert planned.data["revokedDistributions"] == ["org-private"]
    apply(planned)
    inspection = inspect_repository(root)
    assert inspection.distribution("org-private").active_review is None
    assert inspection.distribution("other-private").active_review == before["other-private"]
    assert inspection.distribution("unrelated").active_review == before["unrelated"]
    report = root / ".remek/skills/deploy-safely/evidence" / f"{planned.data['reportId']}.json"
    report.unlink()
    assert inspect_repository(root).distribution("org-private").active_review is None
    assert all((root / ".remek/reviews" / f"{review}.json").is_file() for review in before.values())


def test_behavior_revocation_is_atomic_and_preserves_historical_bytes(tmp_path, monkeypatch):
    root = reviewed_distributions(tmp_path)
    unrelated_review = inspect_repository(root).distribution("unrelated").active_review
    directories = [root / ".remek" / name for name in ("distributions", "reviews", "skills")]

    def records():
        return {
            str(path): path.read_bytes()
            for directory in directories
            for path in directory.rglob("*.json")
        }

    before = records()
    document = reported_evaluation(root, "behavior")
    document["trials"][0].update(
        outcome="fail", observation="Synthetic rerun failed to stop on drift."
    )
    artifact = write_input(tmp_path / "failed-behavior.json", document)
    planned = eval_record_plan(root, "deploy-safely", artifact)
    assert planned.data["reportedPassing"] is False
    assert planned.data["revokedDistributions"] == ["org-private", "other-private"]
    original = transaction_module._replace

    def fail_second_pointer(state, source, destination):
        if "remek-stage" in source and destination == "other-private.json":
            raise OSError("synthetic second pointer failure")
        original(state, source, destination)

    with monkeypatch.context() as fault:
        fault.setattr(transaction_module, "_replace", fail_second_pointer)
        with pytest.raises(Error, match="prior state was restored") as captured:
            apply(planned)
    assert captured.value.outcome == "restored"
    assert captured.value.changed is False
    assert records() == before
    assert not list(root.rglob(".remek-stage-*"))
    assert not list(root.rglob(".remek-backup-*"))
    apply(planned)
    assert all(
        dist.active_review is None
        for dist in inspect_repository(root).distributions
        if dist.distribution_id != "unrelated"
    )
    assert inspect_repository(root).distribution("unrelated").active_review == unrelated_review
    for path, data in before.items():
        if "/distributions/" not in path:
            assert Path(path).read_bytes() == data
    assert eval_record_plan(root, "deploy-safely", artifact).changes == ()


def test_staging_release_is_unverified_and_verify_refuses(tmp_path, monkeypatch):
    root = ready_source(tmp_path)
    git_commit(root)
    staging = tmp_path / "staging"
    plan = release_plan(root, "org-private", staging=staging)
    apply(plan)
    manifest = load_document(staging / "release-manifest.json", kind="release-manifest")
    assert manifest["targetVerificationDigest"] == "not-performed"
    with pytest.raises(Error):
        release_verify(root, "org-private", staging)
    monkeypatch.setattr(workflows_module, "MAX_ITEMS", 1)
    with pytest.raises(Error, match=r"1 skills, 1 files, and \d+ JSON values"):
        release_plan(root, "org-private", staging=tmp_path / "bounded")


def test_release_apply_commit_verify_sequence(tmp_path, monkeypatch):
    root, target = release_roots(tmp_path, monkeypatch)
    plan = release(root, target)
    assert {change.path.name for change in plan.changes} == {"skills", "release-manifest.json"}
    apply(plan)
    manifest_text = (target / "release-manifest.json").read_text()
    for private_value in (
        "git@github.com",
        "business-a/private-skills",
        "org-private",
        "11111111-1111-4111-8111-111111111111",
        '"main"',
        '"origin"',
    ):
        assert private_value not in manifest_text
    assert "fetchUrlDigests" in manifest_text
    assert "sourceRepositoryIdentity" in manifest_text
    git_commit(target, "exact release")
    result = release_verify(root, "org-private", target)
    assert all(
        result[key] is True
        for key in (
            "artifactVerified",
            "sourceReadinessVerified",
            "targetVerified",
            "commitLineageVerified",
        )
    )
    assert result["publicationPerformed"] is False
    assert (
        result["reviewDigest"] == inspect_repository(root).distribution("org-private").active_review
    )
    git(root, "branch", "-m", "review")
    with pytest.raises(Error, match=r"actual source branch digest.*switch to the bound"):
        release_verify(root, "org-private", target)
    git(root, "branch", "-m", "main")
    wrong = "git@github.com:other/wrong.git"
    git(target, "remote", "set-url", "--add", "--push", "origin", wrong)
    with pytest.raises(Error, match="remote URLs"):
        release_verify(root, "org-private", target)
    git(target, "config", "--unset-all", "remote.origin.pushurl", check=False)
    git(
        target,
        "remote",
        "set-url",
        "origin",
        HTTPS_REMOTE,
    )
    with pytest.raises(Error, match=r"actual remote-binding digest.*manifest-bound"):
        release_verify(root, "org-private", target)
    git(
        target,
        "remote",
        "set-url",
        "origin",
        "git@github.com:business-a/private-skills.git",
    )
    monkeypatch.setattr(
        VERIFY_TARGET,
        lambda target, roots: {**verified_target(target, roots), "visibility": "INTERNAL"},
    )
    with pytest.raises(Error, match=r"actual target-lineage digest.*fresh mirror history"):
        release_verify(root, "org-private", target)
    monkeypatch.setattr(VERIFY_TARGET, verified_target)
    git(target, "branch", "-m", "review")
    with pytest.raises(Error, match="mirror branch"):
        release_verify(root, "org-private", target)
    git(target, "branch", "-m", "main")
    (target / "untracked.txt").write_text("dirty")
    with pytest.raises(Error, match="dirty"):
        release_verify(root, "org-private", target)
    (target / "untracked.txt").unlink()
    git(root, "commit", "--allow-empty", "-qm", "next source commit")
    with pytest.raises(Error, match=r"actual source commit.*fresh release"):
        release_verify(root, "org-private", target)


def test_release_verify_binds_mirror_owned_files(tmp_path, monkeypatch):
    root, target = release_roots(tmp_path, monkeypatch)
    (target / "README.md").write_bytes((root / "skills/deploy-safely/SKILL.md").read_bytes())
    git_commit(target, "rename source")
    apply(release(root, target))
    (target / "README.md").unlink()
    git_commit(target, "hidden foreign deletion")
    with pytest.raises(Error, match="unexpected paths"):
        release_verify(root, "org-private", target)


def test_release_verify_requires_current_readiness(tmp_path, monkeypatch):
    root, target = materialized_release(tmp_path, monkeypatch)
    git_commit(target, "release")
    mirror_head = git(target, "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
    for path in (root / ".remek/skills/deploy-safely/evidence").glob("*.json"):
        path.unlink()
    for operation in (
        release,
        lambda source, mirror: release_verify(source, "org-private", mirror),
    ):
        with pytest.raises(
            Error,
            match=r"release\.(review|evidence\.\w+) \.remek/.*source and mirror unchanged",
        ):
            operation(root, target)
    assert git(target, "status", "--porcelain=v1", capture_output=True, text=True).stdout == ""
    assert (
        git(target, "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
        == mirror_head
    )


def test_release_verify_rejects_payload_tamper(tmp_path, monkeypatch):
    root, target = materialized_release(tmp_path, monkeypatch)
    (target / "skills" / "deploy-safely" / "SKILL.md").write_text("tampered\n")
    git_commit(target, "tampered payload")
    with pytest.raises(Error, match="payload inventory"):
        release_verify(root, "org-private", target)


def test_offline_verifier_checks_complete_inventory_and_hostile_json(tmp_path, monkeypatch):
    _, target = materialized_release(tmp_path, monkeypatch)
    manifest = target / "release-manifest.json"
    canonical = manifest.read_bytes()

    def run(argument=target):
        return subprocess.run(
            [sys.executable, str(VERIFY_SCRIPT), str(argument)],
            check=False,
            capture_output=True,
            text=True,
        )

    def refused(message=None):
        with pytest.raises(Error, match=message):
            verify_materialized_release(target)
        completed = run()
        assert completed.returncode == 2 and completed.stderr == "invalid release mirror\n"

    assert run().returncode == 0 and run("--self-test").returncode == 0
    for raw in (
        canonical + b" ",
        b'{"schema":"remek.2","kind":"release-manifest","value":'
        + b"[" * 2000
        + b"0"
        + b"]" * 2000
        + b"}",
    ):
        manifest.write_bytes(raw)
        refused()
    manifest.write_bytes(canonical)
    skill = target / "skills/deploy-safely/SKILL.md"
    for path in (manifest, skill):
        path.chmod(0o600)
        assert run().returncode == 0
        verify_materialized_release(target)
        path.chmod(0o700)
        refused("mode" if path == manifest else None)
        path.chmod(0o644)
    for field in ("releaseId", "candidate", "audience", "mode"):
        document = json.loads(canonical)
        if field == "candidate":
            document["candidates"][0][field] = "0" * 64
        elif field == "mode":
            document["files"][0][field] = {}
        else:
            document[field] = 0 if field == "releaseId" else []
        write_input(manifest, document)
        refused("shape" if field in {"releaseId", "candidate"} else None)
    manifest.write_bytes(canonical)
    extra = target / "skills/extra.txt"
    extra.symlink_to(manifest)
    refused()
    extra.unlink()
    extra.write_text("unmanifested\n")
    refused()


def test_first_release_requires_adoption_for_existing_skills(tmp_path, monkeypatch):
    root, target = release_roots(tmp_path, monkeypatch)
    (target / "skills").mkdir()
    (target / "skills" / "foreign.txt").write_text("foreign")
    git_commit(target, "foreign skills")
    with pytest.raises(Error, match="--adopt-existing"):
        release(root, target)
    assert release(root, target, adopt=True).changes


def test_existing_manifest_must_belong_to_source(tmp_path, monkeypatch):
    root, target = materialized_release(tmp_path, monkeypatch)
    path = target / "release-manifest.json"
    manifest = load_document(path, kind="release-manifest")
    manifest["sourceRepositoryIdentity"] = "0" * 64
    write_input(path, manifest)
    git_commit(target, "foreign manifest")
    with pytest.raises(Error, match="another source"):
        release(root, target)


def test_managed_mirror_cannot_change_audience(tmp_path, monkeypatch):
    root, target = materialized_release(tmp_path, monkeypatch)
    git_commit(target, "private release")

    set_exposure(root, "public-eligible")

    public_distribution = distribution_document()
    public_distribution["audience"] = "public"
    target_definition = public_distribution["target"]
    assert isinstance(target_definition, dict)
    target_definition["expectedVisibility"] = "PUBLIC"
    write_input(root / ".remek/distributions/org-private.json", public_distribution)
    record_evidence(tmp_path, root)

    record_review(tmp_path, root, public=True)
    git_commit(root, "public audience")

    manifest_path = target / "release-manifest.json"
    manifest = load_document(manifest_path, kind="release-manifest")
    manifest["audience"] = "public"
    write_input(manifest_path, manifest)
    git_commit(target, "prepared public manifest")

    def unexpected_target_verification(target, _forbidden_roots):
        assert target
        pytest.fail("audience refusal must precede live target verification")

    monkeypatch.setattr(VERIFY_TARGET, unexpected_target_verification)

    with pytest.raises(Error, match="separate mirror and history"):
        release(root, target)


@pytest.mark.parametrize("field", ("branch", "nameWithOwner", "hostname"))
def test_release_history_binds_complete_target_lineage(field, tmp_path, monkeypatch):
    root, target = materialized_release(tmp_path, monkeypatch)
    git_commit(target, "first target")
    command, marker = execution_sentinel(tmp_path)
    raw = subprocess.check_output(["git", "cat-file", "commit", "HEAD"], cwd=target, text=True)
    signed = raw.replace("\n\n", "\ngpgsig fake\n fake\n\n", 1)
    forged = subprocess.check_output(
        ["git", "hash-object", "-t", "commit", "-w", "--stdin"],
        cwd=target,
        input=signed,
        text=True,
    ).strip()
    git(target, "update-ref", "HEAD", forged)
    git(target, "config", "log.showSignature", "true")
    git(target, "config", "gpg.program", str(command))
    assert release(root, target).changes == () and not marker.exists()
    document = distribution_document()
    target_definition = document["target"]
    assert isinstance(target_definition, dict)
    replacements = {
        "branch": "review",
        "nameWithOwner": "business-a/other-skills",
        "hostname": "github.example.com",
    }
    target_definition[field] = replacements[field]
    write_input(root / ".remek/distributions/org-private.json", document)
    record_evidence(tmp_path, root)
    record_review(tmp_path, root)
    git_commit(root, "changed target")
    if field == "branch":
        git(target, "branch", "-m", "review")
    else:
        host = target_definition["hostname"]
        repository = target_definition["nameWithOwner"]
        git(target, "remote", "set-url", "origin", f"git@{host}:{repository}.git")
    with pytest.raises(Error, match="fresh mirror and history"):
        release(root, target)


def test_target_lineage_excludes_remote_alias_and_transport(tmp_path, monkeypatch):
    root, target = materialized_release(tmp_path, monkeypatch)
    first = load_document(target / "release-manifest.json", kind="release-manifest")
    git_commit(target, "first release")

    document = distribution_document()
    target_definition = document["target"]
    assert isinstance(target_definition, dict)
    target_definition["remote"] = "upstream"
    write_input(root / ".remek/distributions/org-private.json", document)
    record_evidence(tmp_path, root)
    record_review(tmp_path, root)
    git_commit(root, "renamed remote alias")
    git(target, "remote", "rename", "origin", "upstream")
    apply(release(root, target))
    aliased = load_document(target / "release-manifest.json", kind="release-manifest")
    assert aliased["targetVerificationDigest"] == first["targetVerificationDigest"]
    assert aliased["remoteBinding"] != first["remoteBinding"]
    git_commit(target, "alias-bound release")
    with monkeypatch.context() as bounded:
        bounded.setattr(workflows_module, "_RELEASE_HISTORY_LIMIT", 1)
        with pytest.raises(Error, match="history exceeds its bound"):
            release(root, target)

    git(
        target,
        "remote",
        "set-url",
        "upstream",
        HTTPS_REMOTE,
    )
    git(root, "commit", "--allow-empty", "-qm", "next source release")
    apply(release(root, target))
    transported = load_document(target / "release-manifest.json", kind="release-manifest")
    assert transported["targetVerificationDigest"] == aliased["targetVerificationDigest"]
    assert transported["remoteBinding"] != aliased["remoteBinding"]


def test_prior_source_commit_must_be_an_ancestor(tmp_path, monkeypatch):
    root = ready_source(tmp_path)
    base = git_commit(root)
    git(root, "commit", "--allow-empty", "-qm", "current")
    target = mirror(tmp_path)
    monkeypatch.setattr(VERIFY_TARGET, verified_target)
    apply(release(root, target))
    git_commit(target, "release")
    git(root, "checkout", "-qb", "sibling", base)
    git(root, "commit", "--allow-empty", "-qm", "sibling")
    path = target / "release-manifest.json"
    manifest = load_document(path, kind="release-manifest")
    manifest["sourceCommit"] = base
    write_input(path, manifest)
    git_commit(target, "prepared lineage")
    with pytest.raises(Error, match="not an ancestor"):
        release(root, target)


def test_remote_and_push_overrides_refuse_before_materialization(tmp_path, monkeypatch):
    root, target = release_roots(tmp_path, monkeypatch)
    for url in (
        "git@github.com:other/wrong.git",
        "https://github.com:8443/business-a/private-skills.git",
        "git://github.com/business-a/private-skills.git",
    ):
        git(target, "remote", "set-url", "origin", url)
        with pytest.raises(Error, match="remote URL"):
            release(root, target)
    valid = "git@github.com:business-a/private-skills.git"
    git(target, "remote", "set-url", "origin", valid)
    git(target, "config", "remote.origin.url", f"{valid}\n{valid}")
    with pytest.raises(Error, match="control"):
        release(root, target)
    git(target, "config", "remote.origin.url", valid)
    command, marker = execution_sentinel(tmp_path)
    for key in (
        "remote.origin.vcs",
        "remote.origin.receivepack",
        "remote.origin.mirror",
        "core.sshCommand",
        "core.askPass",
        "credential.helper",
        "push.pushOption",
        "url.git@github.com:.insteadOf",
    ):
        git(target, "config", "--local", key, str(command))
        with pytest.raises(Error, match="local Git configuration"):
            release(root, target)
        git(target, "config", "--local", "--unset-all", key)
    https = HTTPS_REMOTE
    git(target, "remote", "set-url", "origin", https)
    git(target, "config", "--local", "http.sslVerify", "false")
    with pytest.raises(Error, match="local Git configuration"):
        release(root, target)
    git(target, "config", "--local", "--unset-all", "http.sslVerify", check=False)
    assert not marker.exists()
    secret = "not-a-real-secret"
    subprocess.run(
        [
            "git",
            "remote",
            "set-url",
            "origin",
            f"https://user:{secret}@github.com/business-a/private-skills.git",
        ],
        cwd=target,
        check=True,
    )
    with pytest.raises(Error, match="unsupported credentials") as caught:
        release(root, target)
    assert secret not in str(caught.value)
    assert not (target / "release-manifest.json").exists()
    git(target, "remote", "set-url", "origin", valid)
    (target / ".git/info/attributes").write_text("skills/** filter=evil\n")
    git(target, "config", "--local", "filter.evil.clean", str(command))
    with pytest.raises(Error, match="content filters"):
        release(root, target)
    assert not marker.exists()


def test_identical_release_is_a_no_op(tmp_path, monkeypatch):
    root, target = release_roots(tmp_path, monkeypatch)
    apply(release(root, target))
    git_commit(target, "release")
    assert release(root, target).changes == ()
    git(target, "commit", "--allow-empty", "-qm", "foreign metadata")
    with pytest.raises(Error, match="one commit over"):
        release(root, target)


@pytest.mark.parametrize(
    ("returncode", "visibility", "message"),
    [
        (1, "PRIVATE", "query failed"),
        (0, "INTERNAL", "differs"),
        (0, "PRIVATE", None),
    ],
)
def test_target_verification_fails_closed(
    returncode,
    visibility,
    message,
    monkeypatch,
):
    monkeypatch.setenv("GH_REPO", "wrong/repository")
    result = subprocess.CompletedProcess(
        [],
        returncode,
        json.dumps({"nameWithOwner": "business-a/private-skills", "visibility": visibility}),
        "",
    )

    def run(arguments, **options):
        assert arguments[-2:] == ["--", "business-a/private-skills"]
        assert options["cwd"] == Path("/") and "GH_REPO" not in options["environment"]
        return result

    monkeypatch.setattr("remek_core.workflows._run", run)
    if message:
        with pytest.raises(Error, match=message):
            verify_github_target(distribution_document()["target"], (Path.cwd(),))
    else:
        assert (
            verify_github_target(distribution_document()["target"], (Path.cwd(),))["visibility"]
            == visibility
        )
        result.stdout = '{"x":' + "1" * 5000 + "}"
        with pytest.raises(Error, match="invalid JSON"):
            verify_github_target(distribution_document()["target"], (Path.cwd(),))
