import copy
import hashlib
import json
import subprocess
from pathlib import Path

from remek_core.contract import load_document, render_document
from remek_core.repository import evaluation_plan, inspect_repository
from remek_core.review import review_template
from remek_core.transaction import apply_changes
from remek_core.workflows import eval_record_plan, init_plan, review_record_plan

PROJECT = Path(__file__).resolve().parents[1]
TOOLCHAIN = PROJECT / "skills" / "remek" / "toolchain"
RUN_CONFIGURATION = "Synthetic test fixture: fixed offline observations; no provider executed."
PROFILE = {
    "kind": "manual-host",
    "name": "claude-code",
    "version": "1",
    "claim": "regression",
    "runConfigDigest": hashlib.sha256(RUN_CONFIGURATION.encode()).hexdigest(),
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


def render_skill(fields, body):
    lines = ["---"]
    for key, value in fields.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            lines.extend(f"  {name}: {json.dumps(item)}" for name, item in value.items())
        else:
            lines.append(f"{key}: {json.dumps(value)}")
    return ("\n".join([*lines, "---"]) + "\n" + body).encode()


def set_exposure(root, exposure="private-only", name="deploy-safely"):
    path = root / ".remek/skills" / name / "skill.json"
    document = load_document(path, kind="skill-record")
    document["exposure"] = exposure
    write_input(path, document)


def authored(_tmp_path, root, name="deploy-safely"):
    config = load_document(root / "remek.json", kind="repository")
    candidate = root / config["skillsRoot"] / name
    candidate.mkdir(parents=True)
    (candidate / "SKILL.md").write_bytes(
        render_skill(
            {
                "name": name,
                "description": "Use when a reviewed deployment needs a safe exact procedure.",
                "license": "MIT",
            },
            "# Safe deployment\n\nFollow the reviewed procedure and stop on drift.\n",
        )
    )
    write_input(
        root / ".remek/skills" / name / "skill.json",
        {
            "schema": "remek.2",
            "kind": "skill-record",
            "skill": name,
            "exposure": "private-only",
            "provenance": {
                "origin": "captured",
                "source": None,
                "sourceNote": "Synthetic test fixture represents completed owned work.",
                "upstreamRepository": "",
                "upstreamRef": "",
                "rights": "owned",
                "rightsBasis": "Authored from owned completed work.",
                "license": "MIT",
            },
            "cases": {
                "routing": [
                    {
                        "id": "positive",
                        "prompt": "Deploy this reviewed change safely.",
                        "shouldActivate": True,
                    },
                    {"id": "contrast", "prompt": "Write a birthday poem.", "shouldActivate": False},
                ],
                "behavior": [
                    {
                        "id": "safe",
                        "prompt": "Deploy the reviewed change.",
                        "expectations": ["Stop on drift."],
                    }
                ],
            },
        },
    )
    config["governedSkills"] = sorted(set(config["governedSkills"]) | {name})
    write_input(root / "remek.json", config)


def distribution_document(name="org-private", skill="deploy-safely"):
    return {
        "schema": "remek.2",
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
        "activeReview": None,
    }


def disclosure_entry(identifier, value, kind="public-disclosure", **fields):
    return {"id": identifier, "class": kind, "match": "literal", "value": value, **fields}


def disclosure_document(*entries):
    return {"schema": "remek.2", "kind": "disclosure-policy", "entries": list(entries)}


def authored_distribution(_tmp_path, root, name="org-private"):
    write_input(root / ".remek/distributions" / f"{name}.json", distribution_document(name))


def completed_evaluation(template):
    document = copy.deepcopy(template)
    document["profile"] = {key: value for key, value in PROFILE.items() if key != "runConfigDigest"}
    document["runConfiguration"] = RUN_CONFIGURATION
    for trial in document["trials"]:
        trial.update(outcome="pass", observation="Synthetic expected observation.")
    return document


def record_evidence(tmp_path, root, name="deploy-safely"):
    for kind in ("routing", "behavior"):
        plan = evaluation_plan(
            inspect_repository(root), name, kind, "org-private" if kind == "routing" else None
        )
        document = completed_evaluation(plan.template())
        artifact = write_input(tmp_path / f"{kind}-evidence.json", document)
        apply(eval_record_plan(root, name, artifact))


def review_document(root, distribution="org-private", **values):
    document = review_template(inspect_repository(root), distribution)
    document.update(
        {
            "rightsReviewed": True,
            "evidenceReviewed": True,
            "proprietaryContentReviewed": True,
            "reviewer": "test owner",
            "reviewedOn": "2026-09-04",
        }
        | values
    )
    return document


def record_review(tmp_path, root, *, distribution="org-private", public=False):
    document = review_document(root, distribution, publicIrreversibilityAcknowledged=public)
    artifact = write_input(tmp_path / "review.json", document)
    apply(review_record_plan(root, distribution, artifact))


def ready_source(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    authored_distribution(tmp_path, root)
    record_evidence(tmp_path, root)
    record_review(tmp_path, root)
    return root


def git_commit(root, message="checkpoint"):
    if not (root / ".git").exists():
        _git(root, "init", "-q", "--initial-branch", "main")
        _git(root, "config", "user.email", "test@example.com")
        _git(root, "config", "user.name", "Test")
    _git(root, "add", "-A")
    _git(root, "-c", "commit.gpgSign=false", "commit", "-qm", message)
    return _git(root, "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()


def mirror(tmp_path):
    root = tmp_path / "mirror"
    root.mkdir()
    (root / "README.md").write_text("# Private skills\n")
    git_commit(root, "mirror base")
    _git(root, "remote", "add", "origin", "git@github.com:business-a/private-skills.git")
    return root
