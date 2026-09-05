import copy
import hashlib
import json

import pytest
from helpers import (
    PROJECT,
    authored,
    authored_distribution,
    disclosure_document,
    disclosure_entry,
    distribution_document,
    initialized,
    ready_source,
    render_skill,
    set_exposure,
    write_input,
)
from remek_core.contract import load_document, render_document
from remek_core.filesystem import directory_members, git_tree, snapshot_tree, tree_digest
from remek_core.model import RemekError
from remek_core.repository import (
    INJECTED_METADATA_KEYS,
    audit_repository,
    evaluation_plan,
    inspect_repository,
    new_config,
    parse_disclosure,
    parse_distribution,
    parse_skill_record,
    repository_findings,
)
from remek_core.review import release_findings

SKILL = "deploy-safely"
DIST = "org-private"


@pytest.fixture
def root(tmp_path):
    source = initialized(tmp_path)
    authored(tmp_path, source)
    return source


def codes(root):
    return {item.code for item in errors(root)}


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
    path.parent.mkdir(parents=True, exist_ok=True)
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


@pytest.mark.parametrize(
    "value",
    [
        "-----BEGIN " + "PRIVATE KEY-----",
        "AK" + "IAABCDEFGHIJKLMNOP",
        "gh" + "p_abcdefghijklmnopqrstuvwxyz",
        "s" + "k-abcdefghijklmnopqrstuvwxyz",
    ],
)
def test_generic_credentials_block_payload(value, root):
    skill = root / "skills" / SKILL / "references"
    skill.mkdir()
    (skill / "secret.md").write_text(value)
    assert any(item.code.startswith("credential.") for item in errors(root))


def test_builtin_credentials_in_exported_names_are_redacted(root):
    secret = "gh" + "p_" + "x" * 24
    base = root / "skills" / SKILL
    resource = base / f"{secret}.txt"
    resource.write_text("ordinary content")
    for path in (resource, base / secret / "ordinary.txt"):
        if path != resource:
            resource.unlink()
            path.parent.mkdir()
            path.write_text("ordinary content")
        for findings in (errors(root), audit_repository(base)):
            matches = [item for item in findings if item.code == "credential.github-token"]
            assert matches and secret not in repr(matches)


def test_placeholder_scope_is_narrow(root):
    base = root / "skills" / SKILL
    (base / "scripts").mkdir()
    (base / "scripts" / "run.py").write_text("# TODO: advisory\n")
    findings = repository_findings(inspect_repository(root))
    assert any(item.code == "skill.placeholder" and item.severity == "warning" for item in findings)
    (base / "references").mkdir()
    guide = base / "references" / "guide.md"
    guide.write_text("TODO is a project name here.\n")
    assert "skill.placeholder" not in codes(root)
    guide.write_text("TBD: resolve\n")
    assert "skill.placeholder" in codes(root)


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
    assert (
        incompatible.message == "parsed supported frontmatter is outside the remek payload profile"
    )


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
    assert compatible.message == "structurally valid under the supported remek profile"


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
    assert next(
        item.message for item in findings if item.code == "audit.profile-unsupported"
    ).endswith("frontmatter")
    assert not any(item.code == "audit.open-invalid" for item in findings)
    (skill / "SKILL.md").write_bytes(
        render_skill(
            {"name": "different", "description": "Valid instructions."}, "# Instructions\n"
        )
    )
    mismatch = next(item for item in audit_repository(skill) if item.code == "audit.open-invalid")
    assert (
        "frontmatter name must match folder" in mismatch.message and "repair:" in mismatch.message
    )


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


def test_candidate_modes_project_and_empty_directories_refuse(root):
    (root / "skills/deploy-safely/SKILL.md").chmod(0o600)
    (root / "skills" / SKILL / "empty").mkdir()
    (root / "skills" / SKILL / ".DS_Store").write_bytes(b"finder")
    found = codes(root)
    assert {"skill.empty-directory", "skill.residue"} <= found and "skill.mode" not in found


def test_candidate_token_budget_is_enforced(root):
    path = root / "skills" / SKILL / "references"
    path.mkdir()
    (path / "oversized.md").write_text("word " * 75001)
    assert "skill.budget" in codes(root)


def test_ordinary_payload_and_authored_json_preserve_exact_bytes(root):
    authored_distribution(root.parent, root)
    paths = [
        root / "remek.json",
        root / ".remek/skills/deploy-safely/skill.json",
        root / ".remek/distributions/org-private.json",
        root / ".remek/disclosure-policy.json",
    ]
    for path in paths:
        path.write_text(json.dumps(json.loads(path.read_text()), indent=4))
    payload = root / "skills/deploy-safely/SKILL.md"
    payload.write_bytes(
        payload.read_bytes()
        .replace(b'name: "deploy-safely"', b"name: deploy-safely")
        .replace(b"\n", b"\r\n")
    )
    readme = root / "README.md"
    readme.write_bytes(b"Owner bytes including invalid UTF-8: \xff\n<!-- remek-skills:end -->")
    before = {path: path.read_bytes() for path in [*paths, payload, readme]}
    assert errors(root) == []
    assert before == {path: path.read_bytes() for path in before}
    skill = inspect_repository(root).skill(SKILL)
    assert skill.record.exposure == "private-only"
    assert skill.tree.files[0].data == payload.read_bytes()


def test_merged_record_accepts_private_unknowns_and_empty_cases(root):
    path = root / ".remek/skills/deploy-safely/skill.json"
    document = load_document(path, kind="skill-record")
    document["provenance"].update(origin="imported", rights="", rightsBasis="", license="")
    document["cases"] = {"routing": [], "behavior": []}
    write_input(path, document)
    inspection = inspect_repository(root)
    assert errors(root) == []
    assert {
        "provenance.unretained",
        "provenance.incomplete",
        "provenance.rights",
        "evidence.routing",
        "evidence.behavior",
    } <= {item.code for item in repository_findings(inspection)}
    with pytest.raises(RemekError, match="empty"):
        evaluation_plan(inspection, SKILL, "routing", None)
    baseline = parse_skill_record(document, SKILL)
    reordered = json.loads(json.dumps(document, sort_keys=True))
    assert parse_skill_record(reordered, SKILL).digest == baseline.digest
    for axis in ("exposure", "source", "origin"):
        changed = copy.deepcopy(document)
        if axis == "exposure":
            changed[axis] = {}
        else:
            changed["provenance"][axis] = {}
        with pytest.raises(RemekError):
            parse_skill_record(changed, SKILL)
    with pytest.raises(RemekError):
        new_config(repository_id="invalid")


def test_retained_source_checks_exact_file_tree_bytes_and_containment(root):
    base = root / ".remek/skills/deploy-safely"
    sources = base / "sources"
    sources.mkdir()
    source = sources / "original.md"
    source.write_bytes(b"Original exact bytes.\r\n")
    path = base / "skill.json"
    document = load_document(path, kind="skill-record")
    document["provenance"]["source"] = {
        "path": "sources/original.md",
        "type": "file",
        "digest": hashlib.sha256(source.read_bytes()).hexdigest(),
    }
    write_input(path, document)
    assert errors(root) == []
    source.write_bytes(b"changed")
    assert "provenance.source" in codes(root)
    tree = sources / "upstream"
    tree.mkdir()
    (tree / "SKILL.md").write_bytes(b"Original upstream description\n")
    document["provenance"]["source"] = {
        "path": "sources/upstream",
        "type": "tree",
        "digest": tree_digest(git_tree(snapshot_tree(tree)), domain=b"remek.candidate.v1\0"),
    }
    write_input(path, document)
    assert errors(root) == []
    for invalid in ("sources", "sources/../skill.json", "../original.md", "/tmp/source"):
        document["provenance"]["source"]["path"] = invalid
        with pytest.raises(RemekError):
            parse_skill_record(document, SKILL)
    linked = sources / "linked"
    linked.symlink_to(source)
    document["provenance"]["source"] = {
        "path": "sources/linked",
        "type": "file",
        "digest": hashlib.sha256(source.read_bytes()).hexdigest(),
    }
    write_input(path, document)
    assert errors(root)


def test_private_governance_fingerprints_survive_schema_cutover(root):
    artifact = root / "skills/deploy-safely/references/record.json"
    artifact.parent.mkdir()
    for schema, kind in (
        ("remek.1", "approval"),
        ("remek.1", "workspace"),
        ("remek.2", "skill-record"),
        ("remek.2", "evaluation"),
        ("remek.2", "release-review"),
    ):
        artifact.write_text(json.dumps({"schema": schema, "kind": kind}))
        assert "skill.governance" in codes(root)
    for text in (
        '{"schema":"remek.2","kind":"toolchain-manifest"}',
        '{"schema":"remek.1","kind":{}}',
        "Docs mention remek.1 approval and remek.2 evaluation.",
    ):
        artifact.write_text(text)
        assert "skill.governance" not in codes(root)
    artifact.write_text('{"x":' + "1" * 5000 + "}")
    assert "skill.governance" not in codes(root)


def test_governance_bounds_unknown_entries_and_residue_remain_visible(root, monkeypatch):
    (root / ".remek/unknown").write_text("unknown")
    residue = root / ".remek/skills/deploy-safely/sources/.remek-STAGE-test"
    residue.parent.mkdir()
    residue.write_text("residue")
    assert {"governance.layout", "transaction.residue"} <= codes(root)
    monkeypatch.setattr("remek_core.repository.MAX_SKILL_GOV", 1)
    assert any(
        item.code == "governance.bounds" and item.path == ".remek/skills/deploy-safely"
        for item in errors(root)
    )
    monkeypatch.setattr("remek_core.repository.MAX_FINDINGS", 2)
    assert "repo.findings" in codes(root)


def test_disclosure_is_editable_whole_policy_and_rejects_tombstones():
    first = parse_disclosure(disclosure_document(disclosure_entry("client", "Acme")))
    changed = parse_disclosure(disclosure_document(disclosure_entry("client", "Other")))
    removed = parse_disclosure(disclosure_document())
    assert len({first.render(), changed.render(), removed.render()}) == 3
    with pytest.raises(RemekError, match="entry fields"):
        parse_disclosure(disclosure_document(disclosure_entry("client", "Acme", retired=True)))


def test_source_only_skill_cannot_enter_distribution(root):
    set_exposure(root, "source-only")
    authored_distribution(root.parent, root)
    assert "distribution.exposure" in codes(root)
    assert any(
        item.code == "release.exposure" for item in release_findings(inspect_repository(root), DIST)
    )


def test_supported_profile_limits_do_not_depend_on_renderer(root):
    payload = root / "skills/deploy-safely/SKILL.md"
    baseline = inspect_repository(root).skill(SKILL)
    for field, value, code in (
        ("compatibility", "x" * 501, "skill.compatibility"),
        ("allowed-tools", ["Read"], "skill.allowed-tools"),
    ):
        fields = {**baseline.fields, field: value}
        payload.write_bytes(render_skill(fields, baseline.body))
        assert any(item.code in {code, "skill.frontmatter"} for item in errors(root))


def test_owner_credential_policy_blocks_without_disclosing_match(root):
    write_input(
        root / ".remek/disclosure-policy.json",
        disclosure_document(disclosure_entry("client-token", "Client-Zeta-Internal", "credential")),
    )
    path = root / "skills/deploy-safely/references/private.md"
    path.parent.mkdir()
    path.write_text("Client-Zeta-Internal")
    finding = next(item for item in errors(root) if item.code == "disclosure.credential")
    assert "client-token" in finding.message and "Client-Zeta-Internal" not in finding.message


def test_malformed_historical_evidence_keeps_skill_visible_and_blocks_release(tmp_path):
    root = ready_source(tmp_path)
    directory = root / ".remek/skills/deploy-safely/evidence"
    document = load_document(next(directory.glob("*.json")), kind="evaluation")
    document["candidate"] = "0" * 64
    document["trials"] = [{"invalid": True}]
    malformed = write_record(directory, document)
    invalid_name = directory / "bad\nevaluation.json"
    invalid_name.write_text("{}")
    with pytest.raises(RemekError, match="control character"):
        directory_members(directory)
    inspection = inspect_repository(root)
    assert inspection.skill(SKILL)
    paths = {item.path for item in inspection.issues if item.code == "evidence.malformed"}
    assert {str(malformed.relative_to(root)), str(invalid_name.relative_to(root))} <= paths
    assert "evidence.malformed" in {item.code for item in release_findings(inspection, DIST)}


def test_machine_evidence_requires_canonical_bytes_and_matching_filename(tmp_path):
    root = ready_source(tmp_path)
    directory = root / ".remek/skills/deploy-safely/evidence"
    original = next(directory.glob("*.json"))
    data = json.dumps(json.loads(original.read_text())).encode()
    original.unlink()
    noncanonical = directory / f"{hashlib.sha256(data).hexdigest()}.json"
    noncanonical.write_bytes(data)
    assert any(
        item.code == "evidence.malformed" and item.path == str(noncanonical.relative_to(root))
        for item in errors(root)
    )


def test_producer_governance_is_truthful_and_release_blocked_without_real_evidence():
    inspection = inspect_repository(PROJECT)
    assert (inspection.config.repository_id, inspection.config.governed_skills) == (
        "001c6bd0-744e-422f-8771-14e4068c6769",
        ("remek",),
    )
    skill = inspection.skill("remek")
    assert skill.record.exposure == "public-eligible"
    assert not skill.evidence and not inspection.reviews
    assert {"evidence.routing", "evidence.behavior"} <= {
        item.code for item in repository_findings(inspection)
    }
    assert inspection.distributions == ()
    with pytest.raises(RemekError, match="unknown distribution"):
        release_findings(inspection, "public")
