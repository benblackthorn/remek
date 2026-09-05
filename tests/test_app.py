import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import remek_core.app as app_module
from helpers import (
    TOOLCHAIN,
    authored,
    authored_distribution,
    completed_evaluation,
    disclosure_document,
    disclosure_entry,
    git_commit,
    initialized,
    mirror,
    ready_source,
    write_input,
)
from remek_core.app import _parser, main
from remek_core.filesystem import fingerprint, portable_path
from remek_core.model import Finding, PlannedChange, RemekError, Result
from remek_core.plans import operation_document
from remek_core.repository import _toolchain
from remek_core.workflows import (
    release_plan,
    verify_materialized_release,
)


def run(arguments):
    return main(arguments, bundle=TOOLCHAIN)


def execute(path, *arguments, cwd=None):
    return subprocess.run(
        [str(path), *arguments], cwd=cwd, check=False, capture_output=True, text=True
    )


def execute_python(path, *arguments, cwd=None):
    return subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(path), *arguments],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def saved_init(tmp_path, capsys):
    root = tmp_path / "source"
    plan = tmp_path.parent / f"{tmp_path.name}-init.json"
    assert run(["--json", "init", str(root), "--output", str(plan)]) == 0
    return root, plan, json.loads(capsys.readouterr().out)


def test_json_result_uses_remek_2(tmp_path, capsys):
    root = initialized(tmp_path)
    for arguments, code, status in ((["check"], 0, "ok"), (["removed-command"], 2, "refused")):
        assert run(["--root", str(root), "--json", *arguments]) == code
        result = json.loads(capsys.readouterr().out)
        assert result["schema"] == "remek.2"
        assert result["status"] == status and result["exitCode"] == code


def test_audit_never_echoes_credentials(tmp_path, capsys):
    secret = "ghp_xxxxxxxxxxxxxxxxxxxx"
    skill = tmp_path / "external"
    skill.mkdir()
    for text, flag in (
        (f'---\nname: "{secret}"\ndescription: x\n---\nx', ()),
        (
            f"---\nname: external\ndescription: x\n{secret}: x\n{secret}: y\n---\nx",
            ("--json",),
        ),
    ):
        (skill / "SKILL.md").write_text(text)
        assert run([*flag, "audit", str(skill)]) == 1
        output = repr(capsys.readouterr())
        assert secret not in output and "credential.github-token" in output


def test_check_redacts_credential_shaped_skill_identity(tmp_path, capsys):
    root = initialized(tmp_path)
    secret = "s" + "k-abcdefghijklmnopqrstuvwxyz"
    authored(tmp_path, root, name=secret)
    for flags in ([], ["--json"]):
        assert run(["--root", str(root), *flags, "check"]) == 1
        output = capsys.readouterr()
        text = output.out + output.err
        leaked = secret in text
        assert not leaked and "[credential-redacted]" in text
        assert "credential.provider-token" in text
        if flags:
            data = json.loads(output.out)["data"]
            assert data["skills"][0]["skill"] == "[credential-redacted]"


@pytest.mark.parametrize("custom", [False, True])
def test_malformed_review_credentials_are_blocked_without_disclosure(tmp_path, capsys, custom):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    authored_distribution(tmp_path, root)
    secret = "private-owner-value" if custom else "gh" + "p_" + "x" * 24
    if custom:
        write_input(
            root / ".remek/disclosure-policy.json",
            disclosure_document(disclosure_entry("owner-credential", secret, "credential")),
        )
    raw = ('{"schema":"remek.2","kind":"release-review",' + f'"{secret}":1,"{secret}":2}}').encode()
    path = root / ".remek/reviews" / (hashlib.sha256(raw).hexdigest() + ".json")
    path.write_bytes(raw)
    before = fingerprint(root)
    inspection = app_module.inspect(root)
    assert inspection.skill("deploy-safely")
    assert any(item.code == "review.malformed" for item in inspection.issues)
    assert any(
        item.code == ("disclosure.credential" if custom else "credential.github-token")
        for item in inspection.issues
    )
    stage = tmp_path / "stage"
    for command, code in (
        (["check"], 1),
        (["eval", "plan", "deploy-safely", "--kind", "behavior"], 2),
        (["review", "plan", "org-private"], 2),
        (["release", "plan", "org-private", "--staging", str(stage)], 2),
    ):
        for flags in ([], ["--json"]):
            assert run(["--root", str(root), *flags, *command]) == code
            output = capsys.readouterr()
            assert secret not in output.out + output.err
            if command == ["check"]:
                assert "review.malformed" in output.out + output.err
                if flags:
                    data = json.loads(output.out)["data"]
                    assert (
                        not data["structuralValid"]
                        and data["skills"][0]["skill"] == "deploy-safely"
                    )
    assert path.read_bytes() == raw and fingerprint(root) == before and not stage.exists()


def test_output_redacts_nested_diagnostics_and_fallback_with_owner_policy(
    tmp_path, capsys, monkeypatch
):
    root = initialized(tmp_path)
    secret, built_in = "private-owner-value", "gh" + "p_" + "x" * 24
    write_input(
        root / ".remek/disclosure-policy.json",
        disclosure_document(disclosure_entry("owner-credential", secret, "credential")),
    )
    finding = Finding("review.malformed", "error", f"invalid {secret}", f"reviews/{built_in}")
    result = Result(
        "review plan",
        "issues",
        f"blocked {built_in}",
        findings=(finding,),
        data={
            "review": {"blockingFindings": [finding.as_dict()]},
            "root": str(root),
            "reviewId": "a" * 64,
            "residue": [{"path": f"/private/{secret}", "reason": built_in}],
        },
    )
    for flags in ([], ["--json"]):
        assert run(["--root", str(root), *flags, secret]) == 2
        output = capsys.readouterr()
        assert secret not in output.out + output.err and "cli.arguments" in output.out + output.err
    monkeypatch.setattr(app_module, "_dispatch", lambda *_: result)
    for flags in ([], ["--json"]):
        assert run(["--root", str(root), *flags, "review", "plan", "org-private"]) == 1
        output = capsys.readouterr()
        assert secret not in output.out + output.err and built_in not in output.out + output.err
        assert "review.malformed" in output.out and "[credential-redacted]" in output.out
        if flags:
            document = json.loads(output.out)
            assert document["data"]["reviewId"] == "a" * 64
            assert (
                document["data"]["review"]["blockingFindings"][0]["path"]
                == "reviews/[credential-redacted]"
            )
    monkeypatch.setattr(app_module, "MAX_RENDERED_BYTES", 1)
    for flags in ([], ["--json"]):
        assert run(["--root", str(root), *flags, "review", "plan", "org-private"]) == 2
        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert secret not in output and built_in not in output
        if flags:
            assert json.loads(output)["data"]["residue"] == [
                {"path": "[credential-redacted]", "reason": "[credential-redacted]"}
            ]
    assert result.findings == (finding,) and result.data["residue"][0]["reason"] == built_in


@pytest.mark.parametrize("custom", [False, True])
def test_record_show_and_duplicate_redact_dynamic_binding_keys(tmp_path, capsys, custom):
    secret = "private-owner-value" if custom else "gh" + "p_" + "x" * 24
    parent = tmp_path / secret
    parent.mkdir()
    root = initialized(parent)
    authored(tmp_path, root)
    if custom:
        write_input(
            root / ".remek/disclosure-policy.json",
            disclosure_document(disclosure_entry("owner-credential", secret, "credential")),
        )
    evidence = completed_evaluation(
        app_module.evaluation_plan(
            app_module.inspect(root), "deploy-safely", "behavior", None
        ).template()
    )
    source = write_input(tmp_path / "evidence.json", evidence)
    plan, duplicate = tmp_path / "record.json", tmp_path / "duplicate.json"
    arguments = [
        "--root",
        str(root),
        "--json",
        "eval",
        "record",
        "deploy-safely",
        "--from",
        str(source),
    ]
    expected = 2 if custom else 0
    for command in ([*arguments, "--output", str(plan)], ["--json", "show", str(plan)]):
        prior_bytes = plan.read_bytes() if plan.exists() else None
        assert run(command) == expected
        if prior_bytes is not None:
            assert plan.read_bytes() == prior_bytes
        output = capsys.readouterr().out
        assert secret not in output
        document = json.loads(output)
        if custom:
            assert document["findings"][0]["code"] == "output.invalid"
        else:
            bindings = document["data"]["bindings"]["source"]
            assert len(bindings) == 3 and all("[credential-redacted]" in key for key in bindings)
    raw = plan.read_bytes()
    document = json.loads(raw)
    assert secret.encode() in raw and len(document["bindings"]["source"]) == 3
    assert document["root"] == str(root) and document["planDigest"]
    assert run(["--json", "apply", str(plan)]) == 0
    output = capsys.readouterr().out
    assert secret not in output and json.loads(output)["changed"]
    before = fingerprint(root)
    assert run([*arguments, "--output", str(duplicate)]) == expected
    output = capsys.readouterr().out
    assert secret not in output and not json.loads(output)["changed"]
    assert not duplicate.exists() and fingerprint(root) == before and plan.read_bytes() == raw


def test_runtime_discriminants_survive_matching_policy_without_exempting_free_text():
    for outcome in ("unchanged", "applied", "restored", "residue", "unknown"):
        policy = app_module.parse_disclosure(
            disclosure_document(disclosure_entry("owner-credential", outcome, "credential"))
        )
        result = Result(
            "apply",
            "ok",
            outcome,
            changed=outcome in {"applied", "residue", "unknown"},
            data={
                "outcome": outcome,
                "root": f"/private/{outcome}",
                "review": {"outcome": outcome},
            },
        )
        projected = app_module._redacted_result(result, policy)
        assert projected.data["outcome"] == outcome and projected.summary == "[credential-redacted]"
        assert projected.data["root"] == "[credential-redacted]"
        assert projected.data["review"]["outcome"] == "[credential-redacted]"
        failed, output = app_module._output_failure(result, json_mode=True, policy=policy)
        assert json.loads(output)["data"]["outcome"] == outcome
        assert failed.changed == result.changed and failed.data["root"] == "[credential-redacted]"
    vocabulary = (
        "apply",
        "write",
        "review.malformed",
        "staging",
        "current",
        "not-performed",
        "remek-text",
        "remek.2",
        "evaluation",
        "behavior",
        "manual-host",
        "regression",
        "unreported",
        "update",
    )
    policy = app_module.parse_disclosure(
        disclosure_document(
            *(
                disclosure_entry(f"word-{index:02}", word, "credential")
                for index, word in enumerate(vocabulary)
            )
        )
    )
    data = {
        "operation": "update",
        "mode": "staging",
        "reviewStatus": "current",
        "execution": "not-performed",
        "profile": "remek-text",
        "template": {
            "schema": "remek.2",
            "kind": "evaluation",
            "evidenceKind": "behavior",
            "profile": {"kind": "manual-host", "claim": "regression"},
            "trials": [{"outcome": "unreported"}],
        },
        "review": {"blockingFindings": [{"code": "review.malformed"}]},
    }
    result = Result(
        "apply",
        "ok",
        "apply",
        findings=(Finding("review.malformed", "error", "apply"),),
        changes=(PlannedChange("write", "/private/apply", "before", "after", "apply"),),
        data=data,
    )
    projected = app_module._redacted_result(result, policy)
    assert projected.command == "apply" and projected.data == data
    assert projected.findings[0].code == "review.malformed"
    assert projected.changes[0].action == "write"
    assert (
        projected.summary
        == projected.findings[0].message
        == projected.changes[0].reason
        == "[credential-redacted]"
    )
    assert projected.changes[0].path == "[credential-redacted]"


def test_external_update_preserves_protocol_outcome(tmp_path):
    root = initialized(tmp_path)
    write_input(
        root / ".remek/disclosure-policy.json",
        disclosure_document(disclosure_entry("owner-credential", "applied", "credential")),
    )
    gate = root / "gate"
    gate.write_bytes(b"damaged\n")
    plan = tmp_path / "update.json"
    bootstrap = TOOLCHAIN.parent / "scripts/cli.py"
    for command in (
        ["--root", str(root), "--json", "update", "--output", str(plan)],
        ["--json", "show", str(plan)],
    ):
        completed = execute_python(bootstrap, *command)
        assert completed.returncode == 0, completed.stderr
    completed = execute_python(bootstrap, "--json", "apply", str(plan))
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["changed"] and result["data"]["outcome"] == "applied" and result["exitCode"] == 0
    assert result["data"]["changedPaths"] == [str(gate)]
    assert gate.read_bytes() == (TOOLCHAIN / "assets/gate").read_bytes()
    assert result["summary"] == "[credential-redacted]"


def test_init_plan_show_apply_through_cli(tmp_path, capsys, monkeypatch, saved_init):
    root, plan, initial = saved_init
    result = initial
    assert plan.is_file() and not root.exists()
    shown = subprocess.run(
        shlex.split(result["nextAction"]),
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert shown.returncode == 0 and "exact plan reconstructed" in shown.stdout
    assert run(["show", str(plan), "--max-bytes", "512"]) == 0
    rendered = capsys.readouterr().out
    assert "exact plan reconstructed" in rendered
    assert rendered.index("  tree ") < rendered.index("\nadd ")
    monkeypatch.setattr("remek_core.app.plan_diff", lambda _plan, *, max_bytes: "\\" * max_bytes)
    assert run(["--json", "show", str(plan)]) == 0
    displayed = json.loads(capsys.readouterr().out)["data"]
    assert {key: value for key, value in displayed.items() if key != "diff"} == initial["data"]
    assert run(["apply", str(plan)]) == 0
    assert "final state changed" in capsys.readouterr().out
    assert (root / "remek.json").is_file()
    ignore = (root / ".gitignore").read_text()
    assert ".DS_Store" in ignore and "/.tmp/" in ignore
    occupied = tmp_path / "occupied"
    (occupied / "skills/foreign").mkdir(parents=True)
    assert run(["init", str(occupied)]) == 2
    assert "--project" in capsys.readouterr().err


def test_apply_reports_final_post_cleanup_findings(tmp_path, capsys, monkeypatch):
    root = tmp_path / "source"
    plan = tmp_path.parent / f"{tmp_path.name}-post-cleanup.json"
    assert run(["init", str(root), "--output", str(plan)]) == 0
    capsys.readouterr()
    calls = 0

    def findings(_inspection):
        nonlocal calls
        calls += 1
        return (
            Finding("evidence.routing", "warning", "missing")
            if calls == 1
            else Finding("transaction.residue", "error", "residue"),
        )

    monkeypatch.setattr("remek_core.app.check", findings)
    assert run(["apply", str(plan)]) == 3
    output = capsys.readouterr().err
    assert "blocking findings remain" in output and "transaction.residue" in output


def test_templates_next_actions_and_explicit_paths(tmp_path, capsys, monkeypatch):
    root = ready_source(tmp_path)
    assert run(["--root", str(root), "--json", "check", "--distribution", "org-private"]) == 0
    data = json.loads(capsys.readouterr().out)["data"]
    assert data["structuralValid"] and data["releaseReady"] and data["reviewStatus"] == "current"
    assert run(["--json", "audit", str(root / "skills/deploy-safely")]) == 0
    audit = json.loads(capsys.readouterr().out)["data"]
    assert audit["profile"] == "remek-text" and audit["target"] == str(
        root / "skills/deploy-safely"
    )
    assert (
        run(["--root", str(root), "--json", "eval", "plan", "deploy-safely", "--kind", "behavior"])
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["data"]["execution"] == "not-performed"
    evidence = completed_evaluation(result["data"]["template"])
    evidence["profile"]["name"] = "focused-test"
    evidence_path = write_input(tmp_path / "evidence.json", evidence)
    evidence_plan = tmp_path / "evidence-plan.json"
    action = result["nextAction"]
    action = action.replace("/absolute/path/to/evidence.json", str(evidence_path)).replace(
        "/absolute/path/to/evidence-plan.json", str(evidence_plan)
    )
    completed = subprocess.run(
        shlex.split(action), cwd=tmp_path, check=False, capture_output=True, text=True
    )
    assert completed.returncode == 0 and evidence_plan.is_file()
    assert run(["--root", str(root), "--json", "review", "plan", "org-private"]) == 0
    result = json.loads(capsys.readouterr().out)
    review = result["data"]["template"]
    assert review["rightsReviewed"] is False and review["evidenceReviewed"] is False
    assert result["data"]["review"]
    review.update(
        rightsReviewed=True,
        evidenceReviewed=True,
        proprietaryContentReviewed=True,
        reviewer="Focused reviewer",
        reviewedOn="2026-09-04",
    )
    review_path = write_input(tmp_path / "review.json", review)
    review_plan = tmp_path / "review-plan.json"
    action = result["nextAction"]
    action = action.replace("/absolute/path/to/review.json", str(review_path)).replace(
        "/absolute/path/to/review-plan.json", str(review_plan)
    )
    completed = subprocess.run(
        shlex.split(action), cwd=tmp_path, check=False, capture_output=True, text=True
    )
    assert completed.returncode == 0 and review_plan.is_file()
    before, observed = fingerprint(root / ".remek"), []

    def refuse_review(inspection, distribution):
        observed.append(inspection.distribution(distribution).active_review)
        return False, "stale"

    with monkeypatch.context() as patch:
        patch.setattr(app_module, "review_status", refuse_review)
        assert run(["--json", "apply", str(review_plan)]) == 2
    refused = json.loads(capsys.readouterr().out)
    assert observed == [refused["data"]["reviewId"]]
    assert refused["data"]["outcome"] == "restored" and not refused["changed"]
    assert refused["findings"][0]["code"] == "apply.postcondition"
    assert fingerprint(root / ".remek") == before
    assert run(["--json", "apply", str(review_plan)]) == 0
    applied = json.loads(capsys.readouterr().out)
    inspection = app_module.inspect(root)
    assert inspection.distribution("org-private").active_review == applied["data"]["reviewId"]
    assert app_module.review_status(inspection, "org-private") == (True, "current")
    for command in ("audit", "verify", "init"):
        assert run(["--root", str(root), "--json", command, str(root)]) == 2
        assert "forbids --root" in json.loads(capsys.readouterr().out)["summary"]


def test_removed_commands_are_refused_without_mutation(tmp_path, capsys):
    root = initialized(tmp_path)
    before = sorted(str(path) for path in root.rglob("*"))
    for command in (
        "scaffold",
        "accept",
        "distribution",
        "disclosure",
        "retire",
        "remove",
        "repair",
        "doctor",
        "approve",
        "plan",
    ):
        assert run(["--root", str(root), "--json", command]) == 2
        assert json.loads(capsys.readouterr().out)["changed"] is False
    assert before == sorted(str(path) for path in root.rglob("*"))


def test_gate_is_root_bound_from_another_directory(tmp_path):
    root = initialized(tmp_path)
    assert (root / "remek").read_bytes() == (TOOLCHAIN.parent / "scripts/cli.py").read_bytes()
    completed = execute(root / "gate", cwd=tmp_path)
    assert completed.returncode == 0 and "check passed" in completed.stdout
    members = [root, *root.rglob("*")]
    for directory_mode, file_mode in ((0o700, 0o600), (0o775, 0o664)):
        for path in members:
            path.chmod(
                directory_mode if path.is_dir() or path.stat().st_mode & 0o100 else file_mode
            )
        assert execute(root / "gate", cwd=tmp_path).returncode == 0
    (root / "skills/remek").mkdir(parents=True)
    shutil.copytree(root / ".remek/toolchain", root / "skills/remek/toolchain")
    completed = execute(root / "remek", "--version")
    assert completed.returncode == 2 and "unsafe toolchain" in completed.stderr


def test_release_verify_subcommand_is_recognized(tmp_path, capsys):
    assert run(["release", "verify", "--help"]) == 0
    assert "--mirror" in capsys.readouterr().out
    root = initialized(tmp_path)
    assert (
        run(["--root", str(root), "release", "verify", "org-private", "--mirror", str(root)]) == 2
    )
    assert "unknown distribution" in capsys.readouterr().err


def test_wrapper_accepts_installer_projection_and_metadata(tmp_path):
    skill = tmp_path / "remek"
    shutil.copytree(TOOLCHAIN.parent, skill)
    skill_md = skill / "SKILL.md"
    skill_md.write_text(skill_md.read_text() + "\ninstaller metadata changed wrapper bytes\n")
    for path in skill.rglob("*"):
        if path.is_file():
            path.chmod(0o644)
    completed = execute_python(skill / "scripts/cli.py", "--version")
    assert completed.returncode == 0 and completed.stdout == "remek 2.0.0\n"


def test_update_repairs_owned_bundle_and_refuses_foreign_governance(tmp_path):
    root = initialized(tmp_path)
    (root / "remek").write_text("damaged\n")
    runtime = root / ".remek/toolchain/runtime/remek_core/model.py"
    damaged = runtime.read_bytes() + b"\n# synthetic damage\n"
    runtime.write_bytes(damaged)
    unknown = root / ".remek/unknown"
    unknown.write_text("foreign\n")
    plan = tmp_path / "update.json"
    bootstrap = TOOLCHAIN.parent / "scripts/cli.py"
    arguments = ["--root", str(root), "--json", "update", "--output", str(plan)]
    completed = execute_python(bootstrap, *arguments)
    assert completed.returncode == 2 and json.loads(completed.stdout)["changed"] is False
    assert not plan.exists() and unknown.read_text() == "foreign\n"
    unknown.unlink()
    unknown = runtime.parent / "owner-notes.txt"
    unknown.write_text("foreign\n")
    assert execute_python(bootstrap, *arguments).returncode == 2
    assert not plan.exists() and unknown.read_text() == "foreign\n"
    unknown.unlink()
    assert execute_python(bootstrap, *arguments).returncode == 0
    assert execute_python(bootstrap, "show", str(plan)).returncode == 0
    runtime.write_bytes(damaged + b"# drift\n")
    assert execute_python(bootstrap, "apply", str(plan)).returncode == 2
    assert runtime.read_bytes() == damaged + b"# drift\n"
    runtime.write_bytes(damaged)
    completed = execute_python(bootstrap, "apply", str(plan))
    assert completed.returncode == 0, completed.stderr
    assert runtime.read_bytes() == (TOOLCHAIN / "runtime/remek_core/model.py").read_bytes()
    assert _toolchain(root)[1] == []


@pytest.mark.parametrize(
    "tamper",
    (
        "modify",
        "unknown",
        "runtime",
        "symlink",
        "hardlink",
        "special",
        "mode",
        "manifest-large",
        "entrypoint",
    ),
)
def test_bootstrap_refuses_toolchain_tamper(tamper, tmp_path):
    skill = tmp_path / "remek"
    shutil.copytree(TOOLCHAIN.parent, skill)
    marker = None
    if tamper == "modify":
        (skill / "toolchain/assets/gate").write_text("tampered\n")
    elif tamper == "unknown":
        (skill / "toolchain" / "unknown.txt").write_text("unknown\n")
    elif tamper == "symlink":
        (skill / "toolchain/assets/gate").unlink()
        (skill / "toolchain/assets/gate").symlink_to("../manifest.json")
    elif tamper == "hardlink":
        os.link(skill / "toolchain/assets/gate", tmp_path / "external-gate")
    elif tamper == "special":
        os.mkfifo(skill / "toolchain/special")
    elif tamper == "mode":
        (skill / "toolchain/manifest.json").chmod(0o755)
    elif tamper == "manifest-large":
        (skill / "toolchain/manifest.json").write_bytes(b" " * ((256 << 10) + 1))
    else:
        marker = tmp_path / "executed"
        relative = "runtime/remek_core/model.py" if tamper == "runtime" else "scripts/cli.py"
        target = skill / "toolchain" / relative
        target.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
        path = skill / "toolchain/manifest.json"
        document = json.loads(path.read_text())
        document["files"][relative][1] = hashlib.sha256(target.read_bytes()).hexdigest()
        path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    completed = execute_python(skill / "scripts/cli.py", "--help")
    assert completed.returncode == 2
    assert "unsafe toolchain" in completed.stderr
    if marker is not None:
        assert not marker.exists()


def test_toolchain_identities_agree_on_unicode(tmp_path):
    root = tmp_path / "repo"
    bundle = root / "skills/remek/toolchain"
    shutil.copytree(TOOLCHAIN, bundle)
    unicode_file = bundle / "runtime/remek_core/café.py"
    unicode_file.write_text("pass\n")
    namespace = {"__file__": str((TOOLCHAIN / "scripts/cli.py").absolute())}
    exec((TOOLCHAIN / "scripts/cli.py").read_text().split("\ntry:\n", 1)[0], namespace)
    build = namespace["_manifest"]
    (bundle / "manifest.json").write_bytes(build(bundle))
    assert {item.code for item in _toolchain(root)[1]} == {"repo.shim"}
    for value in ("café", "café", "CAFÉ"):
        wrapper = namespace["normalize"]("NFD", value).casefold()
        assert wrapper == portable_path(value)
    collision = unicode_file.with_name("café.py")
    collision.write_text("pass\n")
    if not collision.samefile(unicode_file):
        with pytest.raises(RuntimeError):
            build(bundle)
        assert any(item.code == "filesystem.collision" for item in _toolchain(root)[1])
        collision.unlink()
    (bundle / "manifest.json").chmod(0o755)
    assert {item.code for item in _toolchain(root)[1]} == {"toolchain.identity"}


def test_release_apply_rolls_back_failed_postcondition(tmp_path, monkeypatch, capsys):
    root = ready_source(tmp_path)
    git_commit(root)
    target = mirror(tmp_path)
    monkeypatch.setattr(
        "remek_core.workflows.verify_github_target",
        lambda value, _forbidden_roots: {
            "provider": "github",
            "hostname": value["hostname"],
            "nameWithOwner": value["nameWithOwner"],
            "visibility": value["expectedVisibility"],
        },
    )
    plan = release_plan(root, "org-private", mirror=target)
    plan_path = tmp_path / "release-plan.json"
    plan_path.write_bytes(operation_document(plan, TOOLCHAIN)[0])
    plan_path.chmod(0o600)

    def fail(_root):
        raise RemekError("test.postcondition", "forced failure")

    monkeypatch.setattr("remek_core.app.verify_materialized_release", fail)
    assert run(["apply", str(plan_path)]) == 2
    assert "prior state was restored" in capsys.readouterr().err
    assert not (target / "skills").exists() and not (target / "release-manifest.json").exists()
    monkeypatch.setattr("remek_core.app.verify_materialized_release", verify_materialized_release)
    assert run(["apply", str(plan_path)]) == 0


def test_documented_remek_commands_parse():
    files = [
        Path("README.md"),
        Path("skills/remek/references/workflows.md"),
    ]
    commands = []
    for path in files:
        for block in re.findall(r"```bash\n(.*?)```", path.read_text(), re.DOTALL):
            for line in re.sub(r"\\\n\s*", " ", block).splitlines():
                arguments = shlex.split(line)
                if arguments and arguments[0] in {"remek", "./remek"}:
                    commands.append(arguments[1:])
    assert commands
    for arguments in commands:
        if "--version" in arguments or "--help" in arguments:
            with pytest.raises(SystemExit) as caught:
                _parser().parse_args(arguments)
            assert caught.value.code == 0
        else:
            _parser().parse_args(arguments)


def test_local_markdown_links_resolve():
    files = [Path("README.md"), *Path("docs").glob("*.md"), Path("skills/remek/SKILL.md")]
    for path in files:
        for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", path.read_text()):
            if "://" not in target and not target.startswith(("#", "mailto:")):
                assert (path.parent / target.split("#", 1)[0]).exists(), (path, target)


def test_output_failure_preserves_completed_mutation(monkeypatch, capsys, saved_init):
    root, plan, initial = saved_init
    identity = initial["data"]
    monkeypatch.setattr("remek_core.app.MAX_RENDERED_BYTES", 1)
    assert run(["--json", "apply", str(plan)]) == 3
    result = json.loads(capsys.readouterr().out)
    assert root.exists() and result["changed"] is True
    assert result["data"]["outcome"] == "applied" and result["data"]["changedPaths"] == [str(root)]
    assert result["exitCode"] == 3
    assert result["findings"][0]["code"] == "output.invalid"
    assert result["data"]["planDigest"] == identity["planDigest"]
    assert result["data"]["root"] == str(root) and result["data"]["operation"] == "init"


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_post_apply_inspection_failure_preserves_known_outcome(
    monkeypatch, capsys, failure, saved_init
):
    root, plan, _initial = saved_init
    capsys.readouterr()
    calls = 0

    def findings(_inspection):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise failure("fault after transaction")
        return ()

    monkeypatch.setattr("remek_core.app.check", findings)
    assert run(["--json", "apply", str(plan)]) == 3
    result = json.loads(capsys.readouterr().out)
    assert root.exists() and result["data"]["outcome"] == "applied" and result["changed"]


def test_fallback_is_bounded_and_keeps_exact_residue_when_representable():
    residue = [{"path": "/private/backup", "identity": "unknown", "reason": "read failed"}]
    result = Result(
        "apply",
        "refused",
        "failed",
        changed=True,
        data={"outcome": "unknown", "residue": residue, "reportId": "a" * 64},
    )
    failed, output = app_module._output_failure(result, json_mode=True)
    assert failed.exit_code == 3 and json.loads(output)["data"]["residue"] == residue
    assert failed.data["reportId"] == "a" * 64
    result.data["residue"] = [{**residue[0], "path": "x" * app_module._MAX_FALLBACK_BYTES}]
    failed, output = app_module._output_failure(result, json_mode=True)
    assert len(output.encode()) <= app_module._MAX_FALLBACK_BYTES
    assert failed.changed and failed.data["outcome"] == "unknown"
    assert failed.data["outputTruncated"] and failed.data["omittedEntries"] == {
        "changedPaths": 0,
        "residue": 1,
    }


def test_unexpected_renderer_and_failed_fallback_preserve_truth(monkeypatch, capsys):
    result = Result("apply", "ok", "applied", changed=True, data={"outcome": "applied"})
    monkeypatch.setattr(app_module, "_dispatch", lambda *_: result)

    def fail(*_args, **_kwargs):
        raise RuntimeError("synthetic rendering failure")

    monkeypatch.setattr(app_module, "_render", fail)
    assert run(["--json", "check"]) == 3
    assert json.loads(capsys.readouterr().out)["changed"]
    monkeypatch.setattr(app_module.json, "dumps", fail)
    assert run(["--json", "check"]) == 3
    output = json.loads(capsys.readouterr().out)
    assert output["changed"] and output["data"]["outcome"] == "applied" and output["exitCode"] == 3
    monkeypatch.setattr(app_module, "_dispatch", lambda *_: Result("check", "ok", "unchanged"))
    assert run(["--json", "check"]) == 2
    output = json.loads(capsys.readouterr().out)
    assert (
        not output["changed"]
        and output["data"]["outcome"] == "unchanged"
        and output["exitCode"] == 2
    )


def test_broken_process_streams_keep_mutation_exit_code(tmp_path):
    marker = tmp_path / "applied"
    code = f"""
from pathlib import Path
from remek_core import app
from remek_core.model import Result
marker = Path({str(marker)!r})
def dispatch(*_):
    marker.write_text("applied")
    return Result("apply", "ok", "applied", changed=True,
                  data={{"outcome": "applied", "changedPaths": [str(marker)]}})
app._dispatch = dispatch
raise SystemExit(app.main(["--json", "check"], bundle=Path({str(TOOLCHAIN)!r})))
"""
    for both_closed in (False, True):
        process = subprocess.Popen(
            [sys.executable, "-B", "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "PYTHONPATH": str(TOOLCHAIN / "runtime")},
            text=True,
        )
        process.stdout.close()
        if both_closed:
            process.stderr.close()
        assert process.wait(timeout=10) == 3 and marker.read_text() == "applied"
        if not both_closed:
            result = json.loads(process.stderr.read())
            process.stderr.close()
            assert result["data"]["changedPaths"] == [str(marker)]


def test_show_enforces_saved_root_assertion(tmp_path, capsys, saved_init):
    root, plan, _initial = saved_init
    capsys.readouterr()
    assert run(["--root", str(tmp_path), "--json", "show", str(plan)]) == 2
    assert json.loads(capsys.readouterr().out)["data"]["outcome"] == "unchanged"
    assert not root.exists()
