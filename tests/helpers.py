import json
import subprocess
from pathlib import Path

from remek_core.contract import load_document, render_document
from remek_core.frontmatter import render_skill
from remek_core.repository import approval_template, evaluation_plan, inspect_repository
from remek_core.transaction import apply_changes
from remek_core.workflows import (
    accept_plan,
    approve_record_plan,
    distribution_accept_plan,
    eval_record_plan,
    init_plan,
    scaffold_workspace,
)

PROJECT = Path(__file__).resolve().parents[1]
TOOLCHAIN = PROJECT / "skills" / "remek" / "toolchain"
PROFILE = {
    "kind": "manual-host",
    "name": "claude-code",
    "version": "1",
    "claim": "regression",
    "runConfigDigest": "c" * 64,
    "trialCount": 3,
    "minimumPassCount": 3,
}


def _git(root, *arguments, **options):
    return subprocess.run(["git", *arguments], cwd=root, check=True, **options)


def apply(plan):
    apply_changes(plan.changes)


def write_input(path, document):
    kind = document["kind"]
    fields = {key: value for key, value in document.items() if key not in {"schema", "kind"}}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(render_document(kind, fields))
    return path


def initialized(tmp_path, *, project=False):
    root = tmp_path / "source"
    apply(init_plan(root, TOOLCHAIN, "11111111-1111-4111-8111-111111111111", project=project))
    return root


def promote_skill(
    tmp_path, root, *, exposure="private-only", workspace_name="promotion", name="deploy-safely"
):
    workspace = tmp_path / workspace_name
    scaffold_workspace(root, workspace, skill_name=name)
    policy = load_document(workspace / "policy.json", kind="skill-policy")
    policy.update(
        {
            "lifecycle": "ready",
            "exposure": exposure,
            "stateReason": f"Owner reviewed {workspace_name}.",
        }
    )
    write_input(workspace / "policy.json", policy)
    apply(accept_plan(root, workspace))


def authored(tmp_path, root, name="deploy-safely"):
    source = tmp_path / f"{name}-source.md"
    source.write_text("# Observed work\n\nThe workflow completed successfully.\n")
    workspace = tmp_path / f"{name}-new"
    scaffold_workspace(
        root,
        workspace,
        name=name,
        origin="captured",
        source=source,
    )
    (workspace / "candidate" / "SKILL.md").write_bytes(
        render_skill(
            {
                "name": name,
                "description": "Use when a reviewed deployment needs a safe exact procedure.",
                "license": "MIT",
            },
            "# Safe deployment\n\nFollow the reviewed procedure and stop on drift.\n",
        )
    )
    provenance = load_document(workspace / "provenance.json", kind="provenance")
    provenance.update(
        {
            "rights": "owned",
            "rightsBasis": "Authored from owned completed work.",
            "license": "MIT",
        }
    )
    write_input(workspace / "provenance.json", provenance)
    apply(accept_plan(root, workspace))

    promote_skill(tmp_path, root, workspace_name=f"{name}-promotion", name=name)


def distribution_document(name="org-private", skill="deploy-safely"):
    return {
        "schema": "remek.1",
        "kind": "distribution",
        "id": name,
        "audience": "private",
        "skills": [skill],
        "target": {
            "provider": "github",
            "hostname": "github.com",
            "nameWithOwner": "business-a/private-skills",
            "remote": "origin",
            "branch": "main",
            "expectedVisibility": "PRIVATE",
        },
        "delivery": ["gh"],
        "evidencePolicy": {
            "routingProfiles": [dict(PROFILE)],
            "behaviorProfiles": [dict(PROFILE)],
        },
        "privateDisclosure": "block",
    }


def disclosure_entry(identifier, value, kind="public-disclosure", **fields):
    return {"id": identifier, "class": kind, "match": "literal", "value": value, **fields}


def disclosure_document(*entries):
    return {"schema": "remek.1", "kind": "disclosure-policy", "entries": list(entries)}


def accepted_distribution(tmp_path, root, name="org-private"):
    artifact = write_input(tmp_path / f"{name}.json", distribution_document(name))
    apply(distribution_accept_plan(root, artifact))


def record_evidence(tmp_path, root, name="deploy-safely"):
    for kind in ("routing", "behavior"):
        inspection = inspect_repository(root)
        plan = evaluation_plan(
            inspection,
            name,
            kind,
            "org-private" if kind == "routing" else None,
        )
        document = plan.template()
        document["profile"] = PROFILE
        for result in document["results"]:
            assert isinstance(result, dict)
            result["passCount"] = PROFILE["trialCount"]
        document["artifacts"] = [{"label": "evaluation-report", "digest": "d" * 64}]
        artifact = tmp_path / f"{kind}-evidence.json"
        artifact.write_text(json.dumps(document, sort_keys=True))
        apply(eval_record_plan(root, name, artifact))


def approval_document(root, name="deploy-safely", **values):
    document = approval_template(inspect_repository(root), "org-private", name)
    document.update(
        {
            "rightsReviewed": True,
            "proprietaryContentReviewed": True,
            "reviewer": "owner",
            "reviewedOn": "2026-07-15",
            **values,
        }
    )
    return document


def record_approval(tmp_path, root, name="deploy-safely", *, public=False):
    document = approval_document(root, name, publicIrreversibilityAcknowledged=public)
    artifact = write_input(tmp_path / "approval.json", document)
    apply(approve_record_plan(root, "org-private", name, artifact))


def ready_source(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    (root / ".remek/distributions").rmdir()
    accepted_distribution(tmp_path, root)
    records = root / ".remek/skills/deploy-safely"
    for folder in ("evidence", "approvals"):
        (records / folder).rmdir()
    record_evidence(tmp_path, root)
    record_approval(tmp_path, root)
    return root


def git_commit(root, message="checkpoint"):
    if not (root / ".git").exists():
        _git(root, "init", "-q", "--initial-branch", "main")
        _git(root, "config", "user.email", "test@example.com")
        _git(root, "config", "user.name", "Test")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message)
    return _git(root, "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()


def mirror(tmp_path):
    root = tmp_path / "mirror"
    root.mkdir()
    (root / "README.md").write_text("# Private skills\n")
    git_commit(root, "mirror base")
    _git(root, "remote", "add", "origin", "git@github.com:business-a/private-skills.git")
    return root
