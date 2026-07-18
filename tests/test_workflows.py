import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import remek_core.workflows as workflows_module
from helpers import (
    PROFILE,
    PROJECT,
    accepted_distribution,
    apply,
    authored,
    disclosure_document,
    disclosure_entry,
    distribution_document,
    git_commit,
    initialized,
    mirror,
    promote_skill,
    ready_source,
    record_approval,
    record_evidence,
    write_input,
)
from remek_core.contract import load_document
from remek_core.frontmatter import render_skill
from remek_core.model import RemekError
from remek_core.repository import evaluation_plan, inspect_repository, release_findings
from remek_core.workflows import (
    _git_state,
    _run,
    _skills_payload,
    accept_plan,
    disclosure_accept_plan,
    distribution_accept_plan,
    eval_record_plan,
    release_plan,
    release_verify,
    remove_plan,
    repair_plan,
    retire_plan,
    scaffold_workspace,
    verify_github_target,
    verify_materialized_release,
)


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
    monkeypatch.setattr("remek_core.workflows.verify_github_target", verified_target)
    return root, target


def materialized_release(tmp_path, monkeypatch):
    root, target = release_roots(tmp_path, monkeypatch)
    apply(release_plan(root, "org-private", mirror=target))
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


def test_subprocess_output_is_bounded(tmp_path):
    with pytest.raises(RemekError, match="output exceeds"):
        _run(
            [sys.executable, "-c", "import os; os.write(1, b'x' * 2048)"],
            cwd=tmp_path,
            output_limit=1024,
        )


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
        with pytest.raises(RemekError, match="nonempty absolute"):
            _run(
                ["git"],
                cwd=tmp_path,
                environment={**os.environ, "PATH": value},
                forbidden_roots=(tmp_path / "selected",),
            )


def test_external_tool_refuses_canonical_directory_and_tool_targets(tmp_path):
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

    with pytest.raises(RemekError, match="Git is required"):
        workflows_module._git_checkout_containing(outside, (selected,))
    with pytest.raises(RemekError, match="cannot run gh"):
        verify_github_target(distribution_document()["target"], (selected,))
    assert not marker.exists()

    monkeypatch.setenv("HOME", str(tmp_path))
    root = initialized(tmp_path)
    with pytest.raises(RemekError, match="Git is required"):
        scaffold_workspace(
            root,
            tmp_path / "scaffolded",
            name="new-skill",
            origin="imported",
            source=Path("~/selected"),
        )
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


def test_repair_changes_only_managed_files_and_preserves_foreign_data(tmp_path):
    root = initialized(tmp_path, project=True)
    foreign = root / "owner-notes.txt"
    foreign.write_bytes(b"unrelated owner data\n")
    (root / "remek").write_text("damaged\n")

    plan = repair_plan(root)
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
    with pytest.raises(RemekError, match="object integrity"):
        _git_state(root)


def test_git_state_refuses_hidden_inputs(tmp_path):
    root = ready_source(tmp_path)
    head = git_commit(root)
    command, marker = execution_sentinel(tmp_path)
    git(root, "config", "core.fsmonitor", str(command))
    assert _git_state(root)["head"] == head
    assert not marker.exists()
    git(root, "config", "fsck.missingEmail", "ignore")
    with pytest.raises(RemekError, match="fsck"):
        _git_state(root)
    git(root, "config", "--unset", "fsck.missingEmail")
    for flag, clear in (
        ("--assume-unchanged", "--no-assume-unchanged"),
        ("--skip-worktree", "--no-skip-worktree"),
    ):
        git(root, "update-index", flag, "remek.json")
        with pytest.raises(RemekError, match="index flags"):
            _git_state(root)
        git(root, "update-index", clear, "remek.json")
    git(root, "update-index", "--add", "--cacheinfo", f"160000,{head},nested")
    with pytest.raises(RemekError, match="submodules"):
        _git_state(root)
    git(root, "update-index", "--force-remove", "nested")
    grafts = root / ".git/info/grafts"
    grafts.write_text(f"{head}\n")
    with pytest.raises(RemekError, match="graft"):
        _git_state(root)
    grafts.unlink()
    (root / ".git/shallow").write_text(f"{head}\n")
    with pytest.raises(RemekError, match="complete history"):
        _git_state(root)


def test_release_requires_owned_files_in_raw_source_head(tmp_path, monkeypatch):
    root = ready_source(tmp_path)
    for name in (".gitattributes", "bad\\name"):
        unsupported = root / "skills/deploy-safely" / name
        unsupported.write_text("unsafe\n")
        with pytest.raises(RemekError, match="payload path"):
            _skills_payload((inspect_repository(root).skill("deploy-safely"),))
        unsupported.unlink()
    ignored = "skills/deploy-safely/ignored.txt"
    (root / ".gitignore").write_text(f"/{ignored}\n")
    workspace = tmp_path / "ignored-revision"
    scaffold_workspace(root, workspace, skill_name="deploy-safely")
    (workspace / "candidate/ignored.txt").write_text("release payload\n")
    apply(accept_plan(root, workspace))
    promote_skill(tmp_path, root, workspace_name="ignored-promotion")
    record_evidence(tmp_path, root)
    record_approval(tmp_path, root)
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
    monkeypatch.setattr("remek_core.workflows.verify_github_target", verified_target)
    with pytest.raises(RemekError, match="raw HEAD"):
        release_plan(root, "org-private", mirror=target)


def test_scaffold_is_absent_private_and_outside_source(tmp_path, monkeypatch):  # noqa: PLR0915
    root = initialized(tmp_path)
    source = tmp_path / "work.md"
    source.write_text("completed work")
    workspace = tmp_path / "workspace"
    result = scaffold_workspace(root, workspace, name="new-skill", origin="captured", source=source)
    assert result["mode"] == "new"
    assert os.stat(workspace).st_mode & 0o777 == 0o700
    with pytest.raises(RemekError, match="absent"):
        scaffold_workspace(root, workspace, name="new-skill", origin="captured", source=source)
    with pytest.raises(RemekError, match="outside"):
        scaffold_workspace(
            root,
            root / "workspace",
            name="new-skill",
            origin="captured",
            source=source,
        )
    with pytest.raises(RemekError, match="requires --source"):
        scaffold_workspace(
            root,
            tmp_path / "missing-source",
            name="new-skill",
            origin="captured",
        )
    invalid = tmp_path / "invalid-name"
    with pytest.raises(RemekError, match="skill name"):
        scaffold_workspace(root, invalid, name="Invalid", origin="captured", source=source)
    assert not invalid.exists()
    actual_parent = tmp_path / "actual-parent"
    actual_parent.mkdir()
    alias = tmp_path / "alias-parent"
    alias.symlink_to(actual_parent, target_is_directory=True)
    with pytest.raises(RemekError, match=r"actual workspace path resolves to .*repair: rerun"):
        scaffold_workspace(
            root,
            alias / "aliased-workspace",
            name="new-skill",
            origin="captured",
            source=source,
        )
    bare = tmp_path / "bare"
    bare.mkdir()
    with pytest.raises(RemekError, match="usable toolchain"):
        scaffold_workspace(
            bare,
            tmp_path / "bare-workspace",
            name="new-skill",
            origin="captured",
            source=source,
        )
    workspace.chmod(0o755)
    with pytest.raises(RemekError, match="workspace mode"):
        accept_plan(root, workspace)
    workspace.chmod(0o700)
    (workspace / "extra").write_text("foreign")
    with pytest.raises(RemekError, match="top-level layout"):
        accept_plan(root, workspace)
    (workspace / "extra").unlink()
    manifest_path = workspace / "workspace.json"
    manifest = load_document(manifest_path, kind="workspace")
    manifest["mode"] = []
    write_input(manifest_path, manifest)
    with pytest.raises(RemekError, match="invalid workspace"):
        accept_plan(root, workspace)
    manifest["mode"] = "new"
    manifest["base"]["candidate"] = "0" * 64
    write_input(manifest_path, manifest)
    with pytest.raises(RemekError, match="invalid workspace"):
        accept_plan(root, workspace)
    manifest["base"]["candidate"] = None
    write_input(manifest_path, manifest)
    provenance_path = workspace / "provenance.json"
    provenance = load_document(provenance_path, kind="provenance")
    provenance["sourceLabel"] = "bad\0label"
    write_input(provenance_path, provenance)
    with pytest.raises(RemekError, match="source label must be portable"):
        accept_plan(root, workspace)
    provenance["sourceLabel"] = manifest["sourcePath"].split("/", 1)[1]
    write_input(provenance_path, provenance)
    policy_path = workspace / "policy.json"
    policy = load_document(policy_path, kind="skill-policy")
    policy.update({"lifecycle": "ready", "exposure": "private-only"})
    write_input(policy_path, policy)
    with pytest.raises(
        RemekError,
        match=r"actual lifecycle/exposure is ready/private-only; expected draft/source-only",
    ):
        accept_plan(root, workspace)
    policy.update({"lifecycle": "draft", "exposure": "source-only"})
    write_input(policy_path, policy)
    release_parent = tmp_path / "release/subdirectory"
    release_parent.mkdir(parents=True)
    (release_parent.parent / "release-manifest.json").write_text("{}")
    with pytest.raises(RemekError, match="release tree"):
        scaffold_workspace(
            root,
            release_parent / "workspace",
            name="new-skill",
            origin="captured",
            source=source,
        )
    with pytest.raises(RemekError, match="placeholder"):
        accept_plan(root, workspace)
    hidden = root / "hidden-workspace"
    workspace.rename(hidden)
    workspace.symlink_to(hidden, target_is_directory=True)
    with pytest.raises(RemekError, match="outside"):
        accept_plan(root, workspace)

    def missing_git(*_arguments, **_options):
        raise RemekError("external.unavailable", "cannot run git: unavailable")

    monkeypatch.setattr(workflows_module, "_run", missing_git)
    with pytest.raises(RemekError, match="Git is required"):
        scaffold_workspace(
            root,
            tmp_path / "missing-git",
            name="new-skill",
            origin="captured",
            source=source,
        )


def test_import_accept_retains_reviewed_upstream_manifest(tmp_path):
    root = initialized(tmp_path)
    source = tmp_path / "upstream-skill"
    source.mkdir()
    (source / "SKILL.md").write_bytes(
        render_skill(
            {
                "name": "imported-skill",
                "description": "Use for one reviewed imported workflow.",
                "metadata": {"github-repo": "owner/source"},
            },
            "# Imported workflow\n\nFollow the reviewed upstream procedure.\n",
        )
    )
    with pytest.raises(RemekError, match="directory basename"):
        scaffold_workspace(
            root,
            tmp_path / "wrong-import-workspace",
            name="imported-skill",
            origin="imported",
            source=source,
        )
    source = source.rename(tmp_path / "imported-skill")
    reviewed = (source / "SKILL.md").read_bytes()
    (source / "SKILL.md").write_text(
        "---\nname: imported-skill\ndescription: [one]\n---\n# Imported workflow\n"
    )
    with pytest.raises(RemekError, match="outside remek's supported profile"):
        scaffold_workspace(
            root,
            tmp_path / "unsupported-import-workspace",
            name="imported-skill",
            origin="imported",
            source=source,
        )
    (source / "SKILL.md").write_bytes(reviewed)
    workspace = tmp_path / "import-workspace"
    scaffold_workspace(
        root,
        workspace,
        name="imported-skill",
        origin="imported",
        source=source,
    )
    provenance = load_document(workspace / "provenance.json", kind="provenance")
    provenance.update(
        {
            "upstreamRepository": "owner/source",
            "upstreamRef": "reviewed-ref",
            "rights": "licensed",
            "rightsBasis": "Reviewed upstream license.",
            "license": "MIT",
        }
    )
    write_input(workspace / "provenance.json", provenance)
    apply(accept_plan(root, workspace))
    skill = inspect_repository(root).skill("imported-skill")
    retained = load_document(
        root / ".remek/skills/imported-skill/sources/import-manifest.json",
        kind="import-source",
    )
    assert retained["upstreamRepository"] == "owner/source"
    assert retained["upstreamRef"] == "reviewed-ref"
    assert retained["candidate"] == skill.provenance.upstream_candidate
    assert "metadata" not in skill.fields


def test_revision_drift_requires_rescaffold(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    workspace = tmp_path / "revision"
    scaffold_workspace(root, workspace, skill_name="deploy-safely")
    policy_path = root / ".remek" / "skills" / "deploy-safely" / "policy.json"
    policy = load_document(policy_path, kind="skill-policy")
    policy["stateReason"] = "concurrent owner edit"
    write_input(policy_path, policy)
    with pytest.raises(RemekError, match="scaffold the skill again"):
        accept_plan(root, workspace)


def test_accept_retains_source_and_revision_invalidates_records(tmp_path, monkeypatch):
    root = ready_source(tmp_path)
    skill = inspect_repository(root).skill("deploy-safely")
    retained = root / ".remek/skills/deploy-safely/sources" / skill.provenance.source_label
    assert retained.is_file()
    workspace = tmp_path / "revision"
    scaffold_workspace(root, workspace, skill_name="deploy-safely")
    with monkeypatch.context() as bounded:
        bounded.setattr("remek_core.workflows.MAX_SKILL_GOV", 1)
        with pytest.raises(RemekError, match="governance"):
            accept_plan(root, workspace)
    (workspace / "candidate" / "SKILL.md").write_bytes(
        render_skill(
            {
                "name": "deploy-safely",
                "description": "Use for the revised safe deployment workflow.",
                "license": "MIT",
            },
            "# Revised deployment\n\nUse the newly reviewed steps.\n",
        )
    )
    apply(accept_plan(root, workspace))
    skill = inspect_repository(root).skill("deploy-safely")
    assert skill.policy.lifecycle == "draft"
    assert skill.evidence == () and skill.approvals == ()


@pytest.mark.parametrize("retired", [False, True])
def test_policy_promotion_requires_new_reason(retired, tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    if retired:
        apply(retire_plan(root, "deploy-safely", "Superseded after owner review."))
    workspace = tmp_path / "revision"
    scaffold_workspace(root, workspace, skill_name="deploy-safely")
    policy = load_document(workspace / "policy.json", kind="skill-policy")
    policy["lifecycle" if retired else "exposure"] = "ready" if retired else "public-eligible"
    write_input(workspace / "policy.json", policy)
    with pytest.raises(RemekError, match="stateReason"):
        accept_plan(root, workspace)


def test_distribution_and_disclosure_accept_are_idempotent(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    distribution = write_input(tmp_path / "distribution.json", distribution_document())
    first = distribution_accept_plan(root, distribution)
    apply(first)
    assert distribution_accept_plan(root, distribution).changes == ()
    document = distribution_document("secret")
    profile = document["evidencePolicy"]["routingProfiles"][0]
    document["evidencePolicy"]["routingProfiles"] = [{**profile, "name": "github_pat_" + "a" * 20}]
    secret = write_input(tmp_path / "secret.json", document)
    with pytest.raises(RemekError, match=r"credential\.github-token"):
        distribution_accept_plan(root, secret)
    persisted = root / ".remek/distributions/secret.json"
    write_input(persisted, document)
    assert any(item.code == "credential.github-token" for item in inspect_repository(root).issues)
    persisted.unlink()
    disclosure = write_input(
        tmp_path / "disclosure.json",
        disclosure_document(disclosure_entry("client-name", "Acme Internal")),
    )
    apply(disclosure_accept_plan(root, disclosure))
    assert disclosure_accept_plan(root, disclosure).changes == ()
    credential = write_input(
        tmp_path / "credential-disclosure.json",
        disclosure_document(disclosure_entry("private-profile", "secret-host", "credential")),
    )
    apply(disclosure_accept_plan(root, credential))
    custom = distribution_document("custom")
    custom["evidencePolicy"]["routingProfiles"][0]["name"] = "secret-host"
    custom_path = write_input(tmp_path / "custom.json", custom)
    with pytest.raises(RemekError, match=r"disclosure\.credential"):
        distribution_accept_plan(root, custom_path)
    persisted = root / ".remek/distributions/custom.json"
    write_input(persisted, custom)
    assert any(item.code == "disclosure.credential" for item in inspect_repository(root).issues)
    persisted.unlink()


def test_retire_preserves_record_and_remove_refuses_distribution(tmp_path):
    root = ready_source(tmp_path)
    apply(retire_plan(root, "deploy-safely", "Superseded after owner review."))
    assert inspect_repository(root).skill("deploy-safely").policy.lifecycle == "retired"
    assert any(
        item.code == "release.lifecycle"
        for item in release_findings(inspect_repository(root), "org-private")
    )
    with pytest.raises(RemekError, match="remains in distribution"):
        remove_plan(root, "deploy-safely")


def test_empty_distribution_releases_and_verifies_without_skills(tmp_path, monkeypatch):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    accepted_distribution(tmp_path, root)
    document = distribution_document()
    document["skills"] = []
    artifact = write_input(tmp_path / "empty-distribution.json", document)
    apply(distribution_accept_plan(root, artifact))
    assert release_findings(inspect_repository(root), "org-private") == ()
    apply(remove_plan(root, "deploy-safely"))
    assert inspect_repository(root).skills == ()
    git_commit(root)
    target = mirror(tmp_path)
    monkeypatch.setattr("remek_core.workflows.verify_github_target", verified_target)
    apply(release_plan(root, "org-private", mirror=target))
    assert not (target / "skills").exists()
    verifier = [sys.executable, str(PROJECT / "tools/verify_release_manifest.py"), str(target)]
    assert subprocess.run(verifier, check=False).returncode == 0
    git_commit(target, "empty release")
    assert release_verify(root, "org-private", target)["verified"] is True
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(target), str(clone)], check=True)
    verifier[-1] = str(clone)
    assert subprocess.run(verifier, check=False).returncode == 0


def test_failed_evidence_persists_content_addressed(tmp_path, monkeypatch):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    accepted_distribution(tmp_path, root)
    plan = evaluation_plan(inspect_repository(root), "deploy-safely", "routing", "org-private")
    document = plan.template()
    document["profile"] = PROFILE
    for result in document["results"]:
        result["passCount"] = 0
    document["artifacts"] = [{"label": "evaluation-report", "digest": "d" * 64}]
    artifact = tmp_path / "failed.json"
    artifact.write_text(json.dumps(document))
    with monkeypatch.context() as bounded:
        bounded.setattr("remek_core.workflows.MAX_RECORD_BYTES", 1)
        with pytest.raises(RemekError, match="governance"):
            eval_record_plan(root, "deploy-safely", artifact)
    secret = "gh" + "p_abcdefghijklmnopqrstuvwxyz"
    document["artifacts"][0]["label"] = secret
    artifact.write_text(json.dumps(document))
    with pytest.raises(RemekError) as caught:
        eval_record_plan(root, "deploy-safely", artifact)
    assert secret not in str(caught.value)
    document["artifacts"][0]["label"] = "evaluation-report"
    artifact.write_text(json.dumps(document))
    first = eval_record_plan(root, "deploy-safely", artifact)
    apply(first)
    assert eval_record_plan(root, "deploy-safely", artifact).changes == ()
    evidence = root / ".remek" / "skills" / "deploy-safely" / "evidence"
    [receipt] = evidence.glob("*.json")
    assert receipt.name == f"{hashlib.sha256(receipt.read_bytes()).hexdigest()}.json"
    malformed = receipt.with_name("0" * 64 + ".json")
    receipt.rename(malformed)
    inspection = inspect_repository(root)
    assert inspection.skill("deploy-safely")
    finding = next(item for item in inspection.issues if item.code == "evidence.malformed")
    assert finding.path == str(malformed.relative_to(root))


def test_staging_release_is_unverified_and_verify_refuses(tmp_path, monkeypatch):
    root = ready_source(tmp_path)
    git_commit(root)
    staging = tmp_path / "staging"
    plan = release_plan(root, "org-private", staging=staging)
    apply(plan)
    manifest = load_document(staging / "release-manifest.json", kind="release-manifest")
    assert manifest["targetVerificationDigest"] == "not-performed"
    with pytest.raises(RemekError):
        release_verify(root, "org-private", staging)
    monkeypatch.setattr(workflows_module, "MAX_ITEMS", 1)
    with pytest.raises(RemekError, match=r"1 skills, 1 files, and \d+ JSON values"):
        release_plan(root, "org-private", staging=tmp_path / "bounded")


def test_release_apply_commit_verify_sequence(tmp_path, monkeypatch):
    root, target = release_roots(tmp_path, monkeypatch)
    plan = release_plan(root, "org-private", mirror=target)
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
    assert result["verified"] is True
    git(root, "branch", "-m", "review")
    with pytest.raises(RemekError, match=r"actual source branch digest.*switch to the bound"):
        release_verify(root, "org-private", target)
    git(root, "branch", "-m", "main")
    wrong = "git@github.com:other/wrong.git"
    git(target, "remote", "set-url", "--add", "--push", "origin", wrong)
    with pytest.raises(RemekError, match="remote URLs"):
        release_verify(root, "org-private", target)
    git(target, "config", "--unset-all", "remote.origin.pushurl", check=False)
    git(
        target,
        "remote",
        "set-url",
        "origin",
        "https://github.com/business-a/private-skills.git",
    )
    with pytest.raises(RemekError, match=r"actual remote-binding digest.*manifest-bound"):
        release_verify(root, "org-private", target)
    git(
        target,
        "remote",
        "set-url",
        "origin",
        "git@github.com:business-a/private-skills.git",
    )
    monkeypatch.setattr(
        "remek_core.workflows.verify_github_target",
        lambda target, roots: {**verified_target(target, roots), "visibility": "INTERNAL"},
    )
    with pytest.raises(RemekError, match=r"actual target-lineage digest.*fresh mirror history"):
        release_verify(root, "org-private", target)
    monkeypatch.setattr("remek_core.workflows.verify_github_target", verified_target)
    git(target, "branch", "-m", "review")
    with pytest.raises(RemekError, match="mirror branch"):
        release_verify(root, "org-private", target)
    git(target, "branch", "-m", "main")
    (target / "untracked.txt").write_text("dirty")
    with pytest.raises(RemekError, match="dirty"):
        release_verify(root, "org-private", target)
    (target / "untracked.txt").unlink()
    git(root, "commit", "--allow-empty", "-qm", "next source commit")
    with pytest.raises(RemekError, match=r"actual source commit.*fresh release"):
        release_verify(root, "org-private", target)


def test_release_verify_binds_mirror_owned_files(tmp_path, monkeypatch):
    root, target = release_roots(tmp_path, monkeypatch)
    (target / "README.md").write_bytes((root / "skills/deploy-safely/SKILL.md").read_bytes())
    git_commit(target, "rename source")
    apply(release_plan(root, "org-private", mirror=target))
    (target / "README.md").unlink()
    git_commit(target, "hidden foreign deletion")
    with pytest.raises(RemekError, match="unexpected paths"):
        release_verify(root, "org-private", target)


def test_release_verify_requires_current_readiness(tmp_path, monkeypatch):
    root, target = materialized_release(tmp_path, monkeypatch)
    git_commit(target, "release")
    mirror_head = git(target, "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
    for kind in ("evidence", "approvals"):
        for path in (root / ".remek/skills/deploy-safely" / kind).glob("*.json"):
            path.unlink()
    with pytest.raises(
        RemekError,
        match=r"release\.(approval|evidence) \.remek/skills/deploy-safely/"
        r"(approvals|evidence).*source and mirror unchanged",
    ):
        release_plan(root, "org-private", mirror=target)
    with pytest.raises(
        RemekError,
        match=r"release\.(approval|evidence) \.remek/skills/deploy-safely/"
        r"(approvals|evidence).*source and mirror unchanged",
    ):
        release_verify(root, "org-private", target)
    assert git(target, "status", "--porcelain=v1", capture_output=True, text=True).stdout == ""
    assert (
        git(target, "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
        == mirror_head
    )


def test_release_verify_rejects_payload_tamper(tmp_path, monkeypatch):
    root, target = materialized_release(tmp_path, monkeypatch)
    (target / "skills" / "deploy-safely" / "SKILL.md").write_text("tampered\n")
    git_commit(target, "tampered payload")
    with pytest.raises(RemekError, match="payload inventory"):
        release_verify(root, "org-private", target)


def test_producer_mirror_verifier_checks_complete_inventory(tmp_path, monkeypatch):
    _, target = materialized_release(tmp_path, monkeypatch)
    script = PROJECT / "tools/verify_release_manifest.py"

    def run(argument=target):
        return subprocess.run([sys.executable, str(script), str(argument)], check=False).returncode

    assert run() == 0
    assert run("--self-test") == 0
    manifest = target / "release-manifest.json"
    canonical = manifest.read_bytes()
    manifest.write_bytes(canonical + b" ")
    assert run() == 2
    manifest.write_bytes(canonical)
    manifest.chmod(0o600)
    assert run() == 0
    verify_materialized_release(target)
    manifest.chmod(0o700)
    assert run() == 2
    with pytest.raises(RemekError, match="mode"):
        verify_materialized_release(target)
    manifest.chmod(0o644)
    document = load_document(manifest, kind="release-manifest")
    document["releaseId"] = 0
    write_input(manifest, document)
    with pytest.raises(RemekError, match="shape"):
        verify_materialized_release(target)
    assert run() == 2
    manifest.write_bytes(canonical)
    document = load_document(manifest, kind="release-manifest")
    document["candidates"][0]["candidate"] = "0" * 64
    write_input(manifest, document)
    with pytest.raises(RemekError, match="shape"):
        verify_materialized_release(target)
    assert run() == 2
    manifest.write_bytes(canonical)
    skill = target / "skills/deploy-safely/SKILL.md"
    skill.chmod(0o600)
    assert run() == 0
    skill.chmod(0o700)
    assert run() == 2
    skill.chmod(0o644)
    extra = target / "skills" / "extra.txt"
    extra.symlink_to(manifest)
    assert run() == 2
    extra.unlink()
    extra.write_text("unmanifested\n")
    assert run() == 2


def test_verifier_rejects_hostile_json_without_traceback(tmp_path, monkeypatch):
    _, target = materialized_release(tmp_path, monkeypatch)
    manifest = target / "release-manifest.json"
    canonical = manifest.read_bytes()
    script = PROJECT / "tools/verify_release_manifest.py"

    def assert_refused():
        with pytest.raises(RemekError):
            verify_materialized_release(target)
        completed = subprocess.run(
            [sys.executable, str(script), str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 2 and completed.stderr == "invalid release mirror\n"

    for malformed in ("audience", "mode"):
        document = load_document(manifest, kind="release-manifest")
        if malformed == "audience":
            document["audience"] = []
        else:
            document["files"][0]["mode"] = {}
        write_input(manifest, document)
        assert_refused()
        manifest.write_bytes(canonical)
    manifest.write_bytes(
        b'{"schema":"remek.1","kind":"release-manifest","value":'
        + b"[" * 2000
        + b"0"
        + b"]" * 2000
        + b"}"
    )
    assert_refused()


def test_first_release_requires_adoption_for_existing_skills(tmp_path, monkeypatch):
    root, target = release_roots(tmp_path, monkeypatch)
    (target / "skills").mkdir()
    (target / "skills" / "foreign.txt").write_text("foreign")
    git_commit(target, "foreign skills")
    with pytest.raises(RemekError, match="--adopt-existing"):
        release_plan(root, "org-private", mirror=target)
    assert release_plan(root, "org-private", mirror=target, adopt=True).changes


def test_existing_manifest_must_belong_to_source(tmp_path, monkeypatch):
    root, target = materialized_release(tmp_path, monkeypatch)
    path = target / "release-manifest.json"
    manifest = load_document(path, kind="release-manifest")
    manifest["sourceRepositoryIdentity"] = "0" * 64
    write_input(path, manifest)
    git_commit(target, "foreign manifest")
    with pytest.raises(RemekError, match="another source"):
        release_plan(root, "org-private", mirror=target)


def test_managed_mirror_cannot_change_audience(tmp_path, monkeypatch):
    root, target = materialized_release(tmp_path, monkeypatch)
    git_commit(target, "private release")

    promote_skill(tmp_path, root, exposure="public-eligible", workspace_name="public-promotion")

    public_distribution = distribution_document()
    public_distribution["audience"] = "public"
    target_definition = public_distribution["target"]
    assert isinstance(target_definition, dict)
    target_definition["expectedVisibility"] = "PUBLIC"
    artifact = write_input(tmp_path / "public-distribution.json", public_distribution)
    apply(distribution_accept_plan(root, artifact))

    record_approval(tmp_path, root, public=True)
    git_commit(root, "public audience")

    manifest_path = target / "release-manifest.json"
    manifest = load_document(manifest_path, kind="release-manifest")
    manifest["audience"] = "public"
    write_input(manifest_path, manifest)
    git_commit(target, "prepared public manifest")

    def unexpected_target_verification(target, _forbidden_roots):
        assert target
        pytest.fail("audience refusal must precede live target verification")

    monkeypatch.setattr("remek_core.workflows.verify_github_target", unexpected_target_verification)

    with pytest.raises(RemekError, match="separate mirror and history"):
        release_plan(root, "org-private", mirror=target)


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
    assert release_plan(root, "org-private", mirror=target).changes == () and not marker.exists()
    document = distribution_document()
    target_definition = document["target"]
    assert isinstance(target_definition, dict)
    replacements = {
        "branch": "review",
        "nameWithOwner": "business-a/other-skills",
        "hostname": "github.example.com",
    }
    target_definition[field] = replacements[field]
    apply(distribution_accept_plan(root, write_input(tmp_path / "moved.json", document)))
    record_approval(tmp_path, root)
    git_commit(root, "changed target")
    if field == "branch":
        git(target, "branch", "-m", "review")
    else:
        host = target_definition["hostname"]
        repository = target_definition["nameWithOwner"]
        git(target, "remote", "set-url", "origin", f"git@{host}:{repository}.git")
    with pytest.raises(RemekError, match="fresh mirror and history"):
        release_plan(root, "org-private", mirror=target)


def test_target_lineage_excludes_remote_alias_and_transport(tmp_path, monkeypatch):
    root, target = materialized_release(tmp_path, monkeypatch)
    first = load_document(target / "release-manifest.json", kind="release-manifest")
    git_commit(target, "first release")

    document = distribution_document()
    target_definition = document["target"]
    assert isinstance(target_definition, dict)
    target_definition["remote"] = "upstream"
    apply(distribution_accept_plan(root, write_input(tmp_path / "alias.json", document)))
    record_approval(tmp_path, root)
    git_commit(root, "renamed remote alias")
    git(target, "remote", "rename", "origin", "upstream")
    apply(release_plan(root, "org-private", mirror=target))
    aliased = load_document(target / "release-manifest.json", kind="release-manifest")
    assert aliased["targetVerificationDigest"] == first["targetVerificationDigest"]
    assert aliased["remoteBinding"] != first["remoteBinding"]
    git_commit(target, "alias-bound release")

    git(
        target,
        "remote",
        "set-url",
        "upstream",
        "https://github.com/business-a/private-skills.git",
    )
    git(root, "commit", "--allow-empty", "-qm", "next source release")
    apply(release_plan(root, "org-private", mirror=target))
    transported = load_document(target / "release-manifest.json", kind="release-manifest")
    assert transported["targetVerificationDigest"] == aliased["targetVerificationDigest"]
    assert transported["remoteBinding"] != aliased["remoteBinding"]


def test_prior_source_commit_must_be_an_ancestor(tmp_path, monkeypatch):
    root = ready_source(tmp_path)
    base = git_commit(root)
    git(root, "commit", "--allow-empty", "-qm", "current")
    target = mirror(tmp_path)
    monkeypatch.setattr("remek_core.workflows.verify_github_target", verified_target)
    apply(release_plan(root, "org-private", mirror=target))
    git_commit(target, "release")
    git(root, "checkout", "-qb", "sibling", base)
    git(root, "commit", "--allow-empty", "-qm", "sibling")
    path = target / "release-manifest.json"
    manifest = load_document(path, kind="release-manifest")
    manifest["sourceCommit"] = base
    write_input(path, manifest)
    git_commit(target, "prepared lineage")
    with pytest.raises(RemekError, match="not an ancestor"):
        release_plan(root, "org-private", mirror=target)


def test_remote_and_push_overrides_refuse_before_materialization(tmp_path, monkeypatch):
    root, target = release_roots(tmp_path, monkeypatch)
    for url in (
        "git@github.com:other/wrong.git",
        "https://github.com:8443/business-a/private-skills.git",
        "git://github.com/business-a/private-skills.git",
    ):
        git(target, "remote", "set-url", "origin", url)
        with pytest.raises(RemekError, match="remote URL"):
            release_plan(root, "org-private", mirror=target)
    valid = "git@github.com:business-a/private-skills.git"
    git(target, "remote", "set-url", "origin", valid)
    git(target, "config", "remote.origin.url", f"{valid}\n{valid}")
    with pytest.raises(RemekError, match="control"):
        release_plan(root, "org-private", mirror=target)
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
        with pytest.raises(RemekError, match="local Git configuration"):
            release_plan(root, "org-private", mirror=target)
        git(target, "config", "--local", "--unset-all", key)
    https = "https://github.com/business-a/private-skills.git"
    git(target, "remote", "set-url", "origin", https)
    git(target, "config", "--local", "http.sslVerify", "false")
    with pytest.raises(RemekError, match="local Git configuration"):
        release_plan(root, "org-private", mirror=target)
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
    with pytest.raises(RemekError, match="unsupported credentials") as caught:
        release_plan(root, "org-private", mirror=target)
    assert secret not in str(caught.value)
    assert not (target / "release-manifest.json").exists()
    git(target, "remote", "set-url", "origin", valid)
    (target / ".git/info/attributes").write_text("skills/** filter=evil\n")
    git(target, "config", "--local", "filter.evil.clean", str(command))
    with pytest.raises(RemekError, match="content filters"):
        release_plan(root, "org-private", mirror=target)
    assert not marker.exists()


def test_identical_release_is_a_no_op(tmp_path, monkeypatch):
    root, target = release_roots(tmp_path, monkeypatch)
    apply(release_plan(root, "org-private", mirror=target))
    git_commit(target, "release")
    assert release_plan(root, "org-private", mirror=target).changes == ()
    git(target, "commit", "--allow-empty", "-qm", "foreign metadata")
    with pytest.raises(RemekError, match="one commit over"):
        release_plan(root, "org-private", mirror=target)


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
        with pytest.raises(RemekError, match=message):
            verify_github_target(distribution_document()["target"], (Path.cwd(),))
    else:
        assert (
            verify_github_target(distribution_document()["target"], (Path.cwd(),))["visibility"]
            == visibility
        )
        result.stdout = '{"x":' + "1" * 5000 + "}"
        with pytest.raises(RemekError, match="invalid JSON"):
            verify_github_target(distribution_document()["target"], (Path.cwd(),))
