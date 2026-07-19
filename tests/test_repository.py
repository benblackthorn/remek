import copy
import hashlib
import json

import pytest
from helpers import (
    PROFILE,
    PROJECT,
    approval_document,
    authored,
    disclosure_document,
    disclosure_entry,
    distribution_document,
    initialized,
    ready_source,
    write_input,
)
from remek_core.contract import load_document, render_document
from remek_core.evaluation import parse_profile, validate_evidence_intrinsic
from remek_core.filesystem import directory_members
from remek_core.frontmatter import render_skill
from remek_core.model import RemekError
from remek_core.repository import (
    INJECTED_METADATA_KEYS,
    audit_repository,
    inspect_repository,
    merge_disclosure,
    new_config,
    parse_disclosure,
    parse_distribution,
    parse_policy,
    parse_provenance,
    readme_change,
    release_findings,
    repository_findings,
    validate_approval,
    validate_approval_intrinsic,
)
from remek_core.transaction import apply_changes
from remek_core.workflows import (
    accept_plan,
    approve_record_plan,
    disclosure_accept_plan,
    distribution_accept_plan,
    scaffold_workspace,
)


def errors(root):
    return [
        item for item in repository_findings(inspect_repository(root)) if item.severity == "error"
    ]


def write_record(directory, document):
    data = render_document(
        document["kind"],
        {key: value for key, value in document.items() if key not in {"schema", "kind"}},
    )
    path = directory / f"{hashlib.sha256(data).hexdigest()}.json"
    path.write_bytes(data)
    return path


def test_project_mode_preserves_foreign_neighbor(tmp_path):
    root = initialized(tmp_path, project=True)
    foreign = root / ".agents" / "skills" / "third-party"
    foreign.mkdir(parents=True)
    (foreign / "SKILL.md").write_text("foreign bytes")
    assert errors(root) == []
    assert (foreign / "SKILL.md").read_text() == "foreign bytes"
    assert not any(item.code == "audit.empty" for item in audit_repository(root))


def test_accepted_payload_is_pure(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    skill = inspect_repository(root).skill("deploy-safely")
    assert skill.policy.lifecycle == "ready"
    assert skill.policy.exposure == "private-only"
    assert "remek-" not in (skill.path / "SKILL.md").read_text()


def test_hostile_record_enums_refuse_as_remek_errors(tmp_path):
    records = ready_source(tmp_path) / ".remek/skills/deploy-safely"
    policy = load_document(records / "policy.json", kind="skill-policy")
    provenance = load_document(records / "provenance.json", kind="provenance")
    evidence = load_document(next((records / "evidence").iterdir()), kind="eval-receipt")
    approval = load_document(next((records / "approvals").iterdir()), kind="approval")
    policy["lifecycle"], provenance["origin"] = {}, {}
    distribution = distribution_document()
    distribution["audience"] = {}
    disclosure = disclosure_document(disclosure_entry("entry", "value"))
    disclosure["entries"][0]["class"] = {}
    calls = (
        lambda: new_config("11111111-1111-4111-8111-111111111111", skills_root={}),
        lambda: parse_policy(policy, "deploy-safely"),
        lambda: parse_provenance(provenance, "deploy-safely"),
        lambda: parse_distribution(distribution),
        lambda: parse_distribution({**distribution_document(), "delivery": [{}]}),
        lambda: parse_disclosure(disclosure, canonical=False),
        lambda: parse_profile({**PROFILE, "kind": []}),
        lambda: validate_evidence_intrinsic({**evidence, "evidenceKind": {}}, stored=True),
        lambda: validate_approval_intrinsic({**approval, "audience": {}}),
        lambda: validate_approval_intrinsic({**approval, "delivery": [{}]}),
    )
    for call in calls:
        with pytest.raises(RemekError):
            call()


def test_description_cannot_inject_readme_markers(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    path = root / "skills/deploy-safely/SKILL.md"
    path.write_bytes(
        render_skill(
            {
                "name": "deploy-safely",
                "description": "Break the inventory <!-- remek-skills:end -->",
                "license": "MIT",
            },
            "# Safe deployment\n",
        )
    )
    assert any(item.code == "skill.description" for item in errors(root))


def test_governance_artifacts_make_payload_incompatible(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    artifact = root / "skills" / "deploy-safely" / "references" / "approval.json"
    artifact.parent.mkdir()
    artifact.write_text('{"schema":"remek.1","kind":"approval"}\n')
    (artifact.parent / "hostile-kind.json").write_text('{"schema":"remek.1","kind":{}}\n')
    (artifact.parent / "integer.json").write_text('{"x":' + "1" * 5000 + "}")
    assert any(item.code == "skill.governance" for item in errors(root))
    assert any(item.code == "audit.remek-incompatible" for item in audit_repository(root))


def test_whole_governance_tree_obeys_per_skill_cap(tmp_path, monkeypatch):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    monkeypatch.setattr("remek_core.repository.MAX_SKILL_GOV", 1)
    assert any(
        item.code == "governance.bounds" and item.path == ".remek/skills/deploy-safely"
        for item in errors(root)
    )


def test_owned_governance_must_remain_canonical(tmp_path, monkeypatch):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    path = root / ".remek/skills/deploy-safely/policy.json"
    canonical = path.read_bytes()
    path.write_text(json.dumps(json.loads(path.read_text())))
    assert any(item.code == "record.canonical" for item in errors(root))
    path.write_bytes(canonical)
    (root / ".remek/unknown").write_text("unknown")
    residue = root / ".remek/skills/deploy-safely/sources/.remek-STAGE-test"
    residue.write_text("residue")
    nested = residue.parent / "nested"
    nested.mkdir()
    (nested / "source.md").write_text("nested")
    assert {"governance.layout", "transaction.residue"} <= {item.code for item in errors(root)}
    monkeypatch.setattr("remek_core.repository.MAX_FINDINGS", 2)
    assert {item.code for item in errors(root)} == {"governance.layout", "repo.findings"}
    (root / "README.md").write_bytes(b"\xff")
    with pytest.raises(RemekError, match="README"):
        readme_change(root, ())


@pytest.mark.parametrize(
    "value",
    [
        "-----BEGIN " + "PRIVATE KEY-----",
        "AK" + "IAABCDEFGHIJKLMNOP",
        "gh" + "p_abcdefghijklmnopqrstuvwxyz",
        "s" + "k-abcdefghijklmnopqrstuvwxyz",
    ],
)
def test_generic_credentials_block_payload(value, tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    skill = root / "skills" / "deploy-safely" / "references"
    skill.mkdir()
    (skill / "secret.md").write_text(value)
    assert any(item.code.startswith("credential.") for item in errors(root))


def test_placeholder_scope_is_narrow(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    base = root / "skills" / "deploy-safely"
    (base / "scripts").mkdir()
    (base / "scripts" / "run.py").write_text("# TODO: advisory\n")
    findings = repository_findings(inspect_repository(root))
    assert any(item.code == "skill.placeholder" and item.severity == "warning" for item in findings)
    (base / "references").mkdir()
    guide = base / "references" / "guide.md"
    guide.write_text("TODO is a project name here.\n")
    assert not any(item.code == "skill.placeholder" for item in errors(root))
    guide.write_text("TBD: resolve\n")
    assert any(item.code == "skill.placeholder" for item in errors(root))


@pytest.mark.parametrize("key", sorted(INJECTED_METADATA_KEYS))
def test_audit_names_each_exact_installer_key(key, tmp_path):
    skill = tmp_path / "external"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\n"
        "description: External skill.\n"
        "metadata:\n"
        f"    {key}: x\n"
        "name: external\n"
        "---\n"
        "# External\n"
    )
    findings = audit_repository(skill)
    assert not any(item.code == "audit.profile-unsupported" for item in findings)
    assert any(item.code == "audit.metadata" and key in item.message for item in findings)
    incompatible = next(item for item in findings if item.code == "audit.remek-incompatible")
    assert incompatible.message == "structurally valid open format is outside remek profile"


def test_near_match_is_not_normalized_by_audit(tmp_path):
    skill = tmp_path / "external"
    skill.mkdir()
    (skill / "SKILL.md").write_bytes(
        render_skill(
            {
                "name": "external",
                "description": "External skill.",
                "metadata": {"github-repository": "x"},
            },
            "# External\n",
        )
    )
    findings = audit_repository(skill)
    assert not any(item.code == "audit.metadata" for item in findings)
    compatible = next(item for item in findings if item.code == "audit.compatible")
    assert compatible.message == "structurally valid under open and remek profiles"


def test_audit_is_read_only_and_handles_empty(tmp_path):
    before = list(tmp_path.iterdir())
    findings = audit_repository(tmp_path)
    assert findings[0].code == "audit.empty"
    assert list(tmp_path.iterdir()) == before
    skill = tmp_path / "external"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: external\ndescription: Valid YAML # comment\n---\n# Instructions\n"
    )
    findings = audit_repository(skill)
    assert any(item.code == "audit.profile-unsupported" for item in findings)
    assert not any(item.code == "audit.open-invalid" for item in findings)
    (skill / "SKILL.md").write_bytes(
        render_skill(
            {"name": "different", "description": "Valid instructions."},
            "# Instructions\n",
        )
    )
    mismatch = next(item for item in audit_repository(skill) if item.code == "audit.open-invalid")
    assert "actual frontmatter name" in mismatch.message and "repair:" in mismatch.message


def test_audit_reports_candidate_count_bound(tmp_path, monkeypatch):
    monkeypatch.setattr("remek_core.repository.MAX_SKILLS", 1)
    for name in ("first", "second"):
        skill = tmp_path / "skills" / name
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_bytes(
            render_skill(
                {"name": name, "description": f"Use the {name} audited skill."},
                f"# {name}\n",
            )
        )
    assert any(item.code == "audit.limit" for item in audit_repository(tmp_path))


def test_disclosure_ids_keep_meaning_and_retire(tmp_path):
    first_path = write_input(
        tmp_path / "first.json",
        disclosure_document(disclosure_entry("client", "Acme")),
    )
    first = parse_disclosure(load_document(first_path, kind="disclosure-policy"), canonical=False)
    merged = merge_disclosure(
        first,
        parse_disclosure(disclosure_document(), canonical=False),
    )
    assert merged.entries[0].retired
    changed = copy.deepcopy(first.entries[0].as_dict())
    changed.pop("retired")
    changed["value"] = "Other"
    authored_policy = parse_disclosure(
        disclosure_document(changed),
        canonical=False,
    )
    with pytest.raises(RemekError, match="changed meaning"):
        merge_disclosure(first, authored_policy)


def test_distribution_context_binds_host_remote_and_evidence():
    first = parse_distribution(distribution_document())
    for key in ("hostname", "remote"):
        document = distribution_document()
        document["target"][key] = "other" if key == "remote" else "ghe.example.com"
        assert parse_distribution(document).context_digest != first.context_digest
    document = distribution_document()
    document["evidencePolicy"]["routingProfiles"][0]["version"] = "2"
    assert parse_distribution(document).context_digest != first.context_digest


@pytest.mark.parametrize(("claim", "trials"), [("smoke", 3), ("regression", 1)])
def test_distribution_rejects_smoke_or_single_host_trial(claim, trials):
    document = distribution_document()
    profile = document["evidencePolicy"]["routingProfiles"][0]
    profile["claim"] = claim
    profile["trialCount"] = trials
    profile["minimumPassCount"] = 1
    with pytest.raises(RemekError, match="three nondeterministic trials"):
        parse_distribution(document)


@pytest.mark.parametrize(
    ("audience", "visibility"),
    [("private", "PUBLIC"), ("private", "INTERNAL"), ("public", "PRIVATE")],
)
def test_distribution_visibility_must_match_audience(audience, visibility):
    document = distribution_document()
    document["audience"] = audience
    document["target"]["expectedVisibility"] = visibility
    with pytest.raises(RemekError, match="visibility differs"):
        parse_distribution(document)


def test_distribution_requires_canonical_target_hostname_and_branch():
    with pytest.raises(RemekError, match="identity"):
        parse_distribution(distribution_document("verify"))
    for branch in ("client release", "bad$ref", "@", "team/.private", "team/release.lock"):
        document = distribution_document()
        document["target"]["branch"] = branch
        with pytest.raises(RemekError, match="target branch"):
            parse_distribution(document)
    document = distribution_document()
    document["target"]["hostname"] = "github.com:443"
    with pytest.raises(RemekError, match="noncanonical GitHub target"):
        parse_distribution(document)
    for repository in ("-R/x", "owner/repo/extra"):
        document = distribution_document()
        document["target"]["nameWithOwner"] = repository
        with pytest.raises(RemekError, match="noncanonical GitHub target"):
            parse_distribution(document)
    document = distribution_document()
    document["target"]["remote"] = "--upload-pack"
    with pytest.raises(RemekError, match="noncanonical GitHub target"):
        parse_distribution(document)


def test_source_only_skill_cannot_enter_distribution(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    policy_path = root / ".remek" / "skills" / "deploy-safely" / "policy.json"
    policy = load_document(policy_path, kind="skill-policy")
    policy.update({"exposure": "source-only", "lifecycle": "draft", "stateReason": "lowered"})
    write_input(policy_path, policy)
    artifact = write_input(tmp_path / "distribution.json", distribution_document())
    with pytest.raises(RemekError, match="audience exceeds"):
        distribution_accept_plan(root, artifact)


@pytest.mark.parametrize(
    ("axis", "expected"),
    [
        ("lifecycle", "release.lifecycle"),
        ("exposure", "release.exposure"),
        ("rights", "release.rights"),
        ("approval", "release.approval"),
        ("routing", "release.evidence.routing"),
        ("behavior", "release.evidence.behavior"),
        ("disclosure", "release.disclosure"),
    ],
)
def test_release_readiness_reports_each_gate(axis, expected, tmp_path):
    root = ready_source(tmp_path)
    base = root / ".remek/skills/deploy-safely"
    if axis in {"lifecycle", "exposure"}:
        path = base / "policy.json"
        document = load_document(path, kind="skill-policy")
        document[axis] = "draft" if axis == "lifecycle" else "source-only"
        write_input(path, document)
    elif axis == "rights":
        path = base / "provenance.json"
        document = load_document(path, kind="provenance")
        document["license"] = ""
        write_input(path, document)
    elif axis == "approval":
        for path in (base / "approvals").glob("*.json"):
            path.unlink()
    elif axis in {"routing", "behavior"}:
        for path in (base / "evidence").glob("*.json"):
            if load_document(path, kind="eval-receipt")["evidenceKind"] == axis:
                path.unlink()
    else:
        write_input(
            root / ".remek/disclosure-policy.json",
            disclosure_document(disclosure_entry("blocked", "reviewed procedure", retired=False)),
        )
    codes = {item.code for item in release_findings(inspect_repository(root), "org-private")}
    assert expected in codes


def test_candidate_change_stales_evidence_and_approval(tmp_path):
    root = ready_source(tmp_path)
    path = root / "skills" / "deploy-safely" / "SKILL.md"
    path.write_bytes(
        render_skill(
            {
                "name": "deploy-safely",
                "description": "Use when a changed deployment procedure is needed.",
                "license": "MIT",
            },
            "# Changed\n",
        )
    )
    codes = {item.code for item in release_findings(inspect_repository(root), "org-private")}
    assert {"release.approval", "release.evidence.routing", "release.evidence.behavior"} <= codes


def test_public_release_requires_exact_consumer_visible_license(tmp_path):
    root = ready_source(tmp_path)
    candidate = root / "skills/deploy-safely/SKILL.md"
    skill = inspect_repository(root).skill("deploy-safely")
    fields = dict(skill.fields)
    fields.pop("license")
    candidate.write_bytes(render_skill(fields, skill.body))
    assert "release.license" not in {
        item.code for item in release_findings(inspect_repository(root), "org-private")
    }

    policy_path = root / ".remek/skills/deploy-safely/policy.json"
    policy = load_document(policy_path, kind="skill-policy")
    policy["exposure"] = "public-eligible"
    write_input(policy_path, policy)
    distribution_path = root / ".remek/distributions/org-private.json"
    distribution = load_document(distribution_path, kind="distribution")
    distribution["audience"] = "public"
    distribution["target"]["expectedVisibility"] = "PUBLIC"
    write_input(distribution_path, distribution)
    finding = next(
        item
        for item in release_findings(inspect_repository(root), "org-private")
        if item.code == "release.license"
    )
    assert "actual candidate license is missing or invalid" in finding.message
    assert "expected 'MIT'" in finding.message and "repair: set SKILL.md" in finding.message

    fields["license"] = "Apache-2.0"
    candidate.write_bytes(render_skill(fields, skill.body))
    finding = next(
        item
        for item in release_findings(inspect_repository(root), "org-private")
        if item.code == "release.license"
    )
    assert "actual candidate license is 'Apache-2.0'" in finding.message
    assert "expected 'MIT'" in finding.message and "through accept" in finding.message
    fields["license"] = "MIT"
    candidate.write_bytes(render_skill(fields, skill.body))
    assert "release.license" not in {
        item.code for item in release_findings(inspect_repository(root), "org-private")
    }


@pytest.mark.parametrize(
    "axis",
    ["audience", "hostname", "repository", "remote", "branch", "delivery", "evidence"],
)
def test_distribution_context_change_stales_approval(axis, tmp_path):
    root = ready_source(tmp_path)
    path = root / ".remek" / "distributions" / "org-private.json"
    document = load_document(path, kind="distribution")
    if axis == "audience":
        document["audience"] = "public"
        document["target"]["expectedVisibility"] = "PUBLIC"
    elif axis == "delivery":
        document["delivery"] = ["npx"]
    elif axis == "evidence":
        document["evidencePolicy"]["routingProfiles"][0]["version"] = "changed"
    else:
        key = {"repository": "nameWithOwner"}.get(axis, axis)
        document["target"][key] = {
            "hostname": "ghe.example.com",
            "nameWithOwner": "business-a/other",
            "remote": "release",
            "branch": "release",
        }[key]
    write_input(path, document)
    assert any(
        item.code == "release.approval"
        for item in release_findings(inspect_repository(root), "org-private")
    )


def test_provenance_change_stales_approval(tmp_path):
    root = ready_source(tmp_path)
    path = root / ".remek" / "skills" / "deploy-safely" / "provenance.json"
    document = load_document(path, kind="provenance")
    document["rightsBasis"] = "A different reviewed rights basis."
    write_input(path, document)
    assert any(
        item.code == "release.approval"
        for item in release_findings(inspect_repository(root), "org-private")
    )


def test_noncanonical_frontmatter_fails(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    path = root / "skills" / "deploy-safely" / "SKILL.md"
    path.write_text(path.read_text().replace('name: "deploy-safely"', "name: deploy-safely"))
    assert any(item.code == "skill.frontmatter-canonical" for item in errors(root))


def test_candidate_modes_project_and_empty_directories_refuse(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    (root / "skills/deploy-safely/SKILL.md").chmod(0o600)
    (root / "skills" / "deploy-safely" / "empty").mkdir()
    (root / "skills" / "deploy-safely" / ".DS_Store").write_bytes(b"finder")
    codes = {item.code for item in errors(root)}
    assert {"skill.empty-directory", "skill.residue"} <= codes and "skill.mode" not in codes


def test_candidate_token_budget_is_enforced(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    path = root / "skills" / "deploy-safely" / "references"
    path.mkdir()
    (path / "oversized.md").write_text("word " * 75001)
    assert any(item.code == "skill.budget" for item in errors(root))


def test_owner_credential_policy_blocks_without_disclosing_match(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    artifact = write_input(
        tmp_path / "policy.json",
        disclosure_document(disclosure_entry("client-token", "Client-Zeta-Internal", "credential")),
    )
    apply_changes(disclosure_accept_plan(root, artifact).changes)
    workspace = tmp_path / "revision"
    scaffold_workspace(root, workspace, skill_name="deploy-safely")
    reference = workspace / "candidate/references/private.md"
    reference.parent.mkdir(exist_ok=True)
    reference.write_text("Client-Zeta-Internal")
    with pytest.raises(RemekError, match=r"disclosure\.credential"):
        accept_plan(root, workspace)
    path = root / "skills" / "deploy-safely" / "references"
    path.mkdir()
    (path / "private.md").write_text("Client-Zeta-Internal")
    finding = next(item for item in errors(root) if item.code == "disclosure.credential")
    assert "client-token" in finding.message
    assert "Client-Zeta-Internal" not in finding.message


def test_credentials_cannot_be_approval_exceptions(tmp_path):
    root = ready_source(tmp_path)
    artifact = write_input(
        tmp_path / "credential-policy.json",
        disclosure_document(
            disclosure_entry("credential-entry", "nonmatching-private-value", "credential")
        ),
    )
    apply_changes(disclosure_accept_plan(root, artifact).changes)
    approval = approval_document(root, exceptions=[{"id": "credential-entry"}])
    approval_path = write_input(tmp_path / "credential-approval.json", approval)
    with pytest.raises(RemekError, match="cannot be excepted"):
        approve_record_plan(root, "org-private", "deploy-safely", approval_path)


def test_approval_rejects_impossible_calendar_date(tmp_path):
    root = ready_source(tmp_path)
    approval = approval_document(root, reviewedOn="2026-99-99")
    with pytest.raises(RemekError, match="YYYY-MM-DD"):
        validate_approval(approval, inspect_repository(root), "org-private", "deploy-safely")


def test_disclosure_policy_screens_exported_skill_paths(tmp_path):
    root = ready_source(tmp_path)
    artifact = write_input(
        tmp_path / "path-policy.json",
        disclosure_document(disclosure_entry("skill-name", "deploy-safely")),
    )
    apply_changes(disclosure_accept_plan(root, artifact).changes)
    codes = {item.code for item in release_findings(inspect_repository(root), "org-private")}
    assert {"release.approval", "release.disclosure"} <= codes


@pytest.mark.parametrize(("field", "stale"), (("results", True), ("evidenceKind", False)))
def test_malformed_receipt_always_blocks(field, stale, tmp_path):
    root = ready_source(tmp_path)
    second = write_input(tmp_path / "second-distribution.json", distribution_document("org-second"))
    apply_changes(distribution_accept_plan(root, second).changes)
    evidence = root / ".remek/skills/deploy-safely/evidence"
    original = next(
        path
        for path in evidence.glob("*.json")
        if load_document(path, kind="eval-receipt")["evidenceKind"] == "routing"
    )
    document = load_document(original, kind="eval-receipt")
    if stale:
        document["candidate"] = "0" * 64
    if field == "results":
        document[field] = [{"invalid": True}]
    else:
        del document[field]
    original.unlink()
    malformed = write_record(evidence, document)
    inspection = inspect_repository(root)
    assert inspection.skill("deploy-safely")
    finding = next(
        item for item in repository_findings(inspection) if item.code == "evidence.malformed"
    )
    assert finding.path == str(malformed.relative_to(root))
    assert {item.code for item in release_findings(inspection, "org-private")} == {
        "evidence.malformed"
    }


def test_stored_approval_requires_normalized_exception_digest(tmp_path):
    root = ready_source(tmp_path)
    policy = write_input(
        tmp_path / "policy.json",
        disclosure_document(disclosure_entry("client", "reviewed procedure")),
    )
    apply_changes(disclosure_accept_plan(root, policy).changes)
    approval = approval_document(root, exceptions=[{"id": "client"}])
    apply_changes(
        approve_record_plan(
            root,
            "org-private",
            "deploy-safely",
            write_input(tmp_path / "approval.json", approval),
        ).changes
    )
    directory = root / ".remek/skills/deploy-safely/approvals"
    original = next(
        path
        for path in directory.glob("*.json")
        if load_document(path, kind="approval")["exceptions"]
    )
    document = load_document(original, kind="approval")
    del document["exceptions"][0]["digest"]
    original.unlink()
    malformed = write_record(directory, document)

    inspection = inspect_repository(root)
    assert inspection.skill("deploy-safely")
    finding = next(item for item in inspection.issues if item.code == "approval.malformed")
    assert finding.path == str(malformed.relative_to(root))
    assert {item.code for item in release_findings(inspection, "org-private")} == {
        "approval.malformed"
    }


def test_malformed_unused_approval_blocks_with_exact_record_path(tmp_path):
    root = ready_source(tmp_path)
    baseline = inspect_repository(root).skill("deploy-safely")
    document = approval_document(root)
    document["unexpected"] = True
    directory = root / ".remek/skills/deploy-safely/approvals"
    malformed = write_record(directory, document)
    invalid_name = directory / "bad\napproval.json"
    invalid_name.write_text("{}")

    with pytest.raises(RemekError, match="control character"):
        directory_members(directory)

    inspection = inspect_repository(root)
    skill = inspection.skill("deploy-safely")
    assert (len(skill.evidence), len(skill.approvals)) == (
        len(baseline.evidence),
        len(baseline.approvals),
    )
    paths = {item.path for item in inspection.issues if item.code == "approval.malformed"}
    assert {str(malformed.relative_to(root)), str(invalid_name.relative_to(root))} <= paths
    assert {item.code for item in release_findings(inspection, "org-private")} == {
        "approval.malformed"
    }


def test_approval_binds_exact_policy_exceptions(
    tmp_path,
):
    root = ready_source(tmp_path)
    client = disclosure_entry("client", "reviewed procedure")
    artifact = write_input(
        tmp_path / "client-policy.json",
        disclosure_document(client),
    )
    apply_changes(disclosure_accept_plan(root, artifact).changes)
    approval = approval_document(root, exceptions=[{"id": "client"}])
    approval_path = write_input(tmp_path / "exception-approval.json", approval)
    apply_changes(approve_record_plan(root, "org-private", "deploy-safely", approval_path).changes)
    assert release_findings(inspect_repository(root), "org-private") == ()

    expanded = write_input(
        tmp_path / "expanded-policy.json",
        disclosure_document(client, disclosure_entry("unrelated", "unrelated policy note", "note")),
    )
    apply_changes(disclosure_accept_plan(root, expanded).changes)
    assert release_findings(inspect_repository(root), "org-private") == ()

    policy_path = root / ".remek/disclosure-policy.json"
    policy = load_document(policy_path, kind="disclosure-policy")
    policy["entries"][0]["value"] = "safe exact procedure"
    write_input(policy_path, policy)
    codes = {item.code for item in release_findings(inspect_repository(root), "org-private")}
    assert {"release.approval", "release.disclosure"} <= codes


def test_producer_governance_is_current():
    inspection = inspect_repository(PROJECT)
    assert (inspection.config.repository_id, inspection.config.governed_skills) == (
        "001c6bd0-744e-422f-8771-14e4068c6769",
        ("remek",),
    )
    skill = inspection.skill("remek")
    assert (skill.policy.lifecycle, skill.policy.exposure) == ("ready", "public-eligible")
    assert not [
        item for item in repository_findings(inspection) if item.code.startswith("evidence.")
    ]
