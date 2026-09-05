import copy
import json
from dataclasses import replace

import pytest
from helpers import (
    PROFILE,
    TOOLCHAIN,
    apply,
    authored,
    authored_distribution,
    disclosure_document,
    disclosure_entry,
    distribution_document,
    initialized,
    ready_source,
    record_evidence,
    record_review,
    render_skill,
    review_document,
    set_exposure,
    write_input,
)
from remek_core.app import _render, main
from remek_core.contract import document_limit, parse_document, render_document
from remek_core.model import RemekError, Result
from remek_core.repository import inspect_repository, parse_distribution, repository_findings
from remek_core.review import (
    ReviewContext,
    record_id,
    release_findings,
    relevant_evidence,
    review_context,
    review_status,
    review_summary,
    review_template,
    validate_review,
    validate_review_intrinsic,
)
from remek_core.workflows import eval_record_plan, review_record_plan

SKILL = "deploy-safely"
DIST = "org-private"


@pytest.fixture
def root(tmp_path):
    return ready_source(tmp_path)


def status(root):
    return review_status(inspect_repository(root), DIST)


def readiness(root):
    return release_findings(inspect_repository(root), DIST)


def validate(document, root):
    return validate_review(document, inspect_repository(root), DIST)


def exception(entry, reason="Owner reviewed this synthetic disclosure."):
    return {"skill": SKILL, "id": entry.entry_id, "digest": entry.digest, "reason": reason}


def append_report(root, *, passing, required=True):
    directory = root / ".remek/skills/deploy-safely/evidence"
    path = next(
        path
        for path in directory.glob("*.json")
        if json.loads(path.read_text())["evidenceKind"] == "behavior"
    )
    report = json.loads(path.read_text())
    report["trials"][0].update(
        outcome="pass" if passing else "error",
        observation="Synthetic independent rerun observation.",
    )
    if not required:
        report["profile"]["name"] = "experimental profile"
    identifier = record_id(report)
    write_input(directory / f"{identifier}.json", report)
    return identifier, report


def record_review_direct(root, document):
    identifier = record_id(document)
    write_input(root / ".remek/reviews" / f"{identifier}.json", document)
    path = root / ".remek/distributions/org-private.json"
    distribution = json.loads(path.read_text())
    distribution["activeReview"] = identifier
    write_input(path, distribution)
    return identifier


def test_context_excludes_only_pointer_reviews_and_git_identity(root):
    inspection = inspect_repository(root)
    context = review_context(inspection, DIST)
    distribution = inspection.distribution(DIST)
    unselected = replace(
        inspection, distributions=(replace(distribution, active_review=None),), reviews=()
    )
    assert review_context(unselected, DIST) == context
    assert "activeReview" not in context.fields["distribution"]
    assert review_status(inspection, DIST) == (True, "current")
    assert release_findings(inspection, DIST) == ()
    packet = Result(
        "review plan", "ok", "packet", data={"review": review_summary(inspection, DIST)}
    )
    human = _render(packet, json_mode=False)
    assert all(
        text in human
        for text in (
            "sourceCommit",
            "preReleaseHead",
            "sourceRepositoryIdentity",
            "sourceBranchDigest",
            "distributionIdentity",
            "targetVerificationDigest",
            "remoteBinding",
            "expectedCommitPaths",
            "reviewDigest",
            "not confidential redaction",
        )
    )


@pytest.mark.parametrize(("kind", "mode"), [("eval", 0o600), ("review", 0o640)])
def test_identical_record_preserves_permissions_and_active_review_without_plan(
    root, tmp_path, capsys, kind, mode
):
    distribution = root / ".remek/distributions/org-private.json"
    raw = json.dumps(json.loads(distribution.read_text()), separators=(",", ":")).encode()
    distribution.write_bytes(raw)
    distribution.chmod(mode)
    artifact = tmp_path / ("behavior-evidence.json" if kind == "eval" else "review.json")
    folder = "skills/deploy-safely/evidence" if kind == "eval" else "reviews"
    record = root / ".remek" / folder / f"{record_id(json.loads(artifact.read_text()))}.json"
    record.chmod(mode)
    stored = record.read_bytes()
    output = tmp_path / "duplicate-plan.json"
    assert (
        main(
            [
                "--root",
                str(root),
                "--json",
                kind,
                "record",
                SKILL if kind == "eval" else DIST,
                "--from",
                str(artifact),
                "--output",
                str(output),
            ],
            bundle=TOOLCHAIN,
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ok" and result["changed"] is False and result["changes"] == []
    assert not output.exists() and distribution.read_bytes() == raw
    assert record.read_bytes() == stored and record.stat().st_mode & 0o777 == mode
    assert distribution.stat().st_mode & 0o777 == mode and status(root) == (True, "current")


def test_pointer_activation_and_revocation_preserve_authored_bytes_mode_and_history(root, tmp_path):
    path = root / ".remek/distributions/org-private.json"
    document = json.loads(path.read_text())
    document.pop("activeReview")
    document["target"]["branch"] = "activeReview"
    text = json.dumps(dict(reversed(document.items())), indent=3)[:-1].rstrip()
    prefix = text.replace("\n", "\r\n").encode() + b',\r\n "active\\u0052eview"\t:\t '
    suffix = b"\r\n}\r\n"
    path.write_bytes(prefix + b"null" + suffix)
    path.chmod(0o640)
    history = {item.name: item.read_bytes() for item in (root / ".remek/reviews").iterdir()}
    artifact = write_input(tmp_path / "new-review.json", review_document(root))
    review = review_record_plan(root, DIST, artifact)
    apply(review)
    identifier = review.data["reviewId"]
    assert path.read_bytes() == prefix + json.dumps(identifier).encode() + suffix
    assert path.stat().st_mode & 0o777 == 0o640 and status(root) == (True, "current")
    report = json.loads((tmp_path / "behavior-evidence.json").read_text())
    report["trials"][0]["observation"] = "Synthetic new observation after review."
    artifact = write_input(tmp_path / "new-evidence.json", report)
    evidence = eval_record_plan(root, SKILL, artifact)
    assert evidence.data["revokedDistributions"] == [DIST]
    apply(evidence)
    assert path.read_bytes() == prefix + b"null" + suffix
    assert path.stat().st_mode & 0o777 == 0o640
    assert all(
        (root / ".remek/reviews" / name).read_bytes() == data for name, data in history.items()
    )
    assert (root / ".remek/reviews" / f"{identifier}.json").exists()
    (root / ".remek/skills/deploy-safely/evidence" / f"{evidence.data['reportId']}.json").unlink()
    assert status(root) == (False, "missing")


def test_pointer_growth_refuses_authored_distribution_byte_bound(root, tmp_path):
    path = root / ".remek/distributions/org-private.json"
    document = json.loads(path.read_text())
    document["activeReview"] = None
    data = json.dumps(document).encode()
    raw = data + b" " * (document_limit("distribution") - len(data))
    path.write_bytes(raw)
    artifact = write_input(tmp_path / "bounded-review.json", review_document(root))
    with pytest.raises(RemekError, match="byte bound"):
        review_record_plan(root, DIST, artifact)
    assert path.read_bytes() == raw and status(root) == (False, "missing")


def test_current_pass_cannot_hide_required_profile_failure(root):
    failed, _ = append_report(root, passing=False)
    inspection = inspect_repository(root)
    assert review_status(inspection, DIST) == (False, "stale")
    template = review_template(inspection, DIST)
    assert template["failureAcknowledgements"] == [{"report": failed, "reason": ""}]
    assert len(template["selectedEvidence"]) == 2
    current = review_document(root)
    with pytest.raises(RemekError, match="reason"):
        validate_review(current, inspection, DIST)
    current["failureAcknowledgements"] = []
    with pytest.raises(RemekError, match="every current required-profile failure"):
        validate_review(current, inspection, DIST)
    current["failureAcknowledgements"] = [
        {
            "report": failed,
            "reason": "Owner inspected the synthetic failure and accepts its documented limit.",
        }
    ]
    assert validate_review(current, inspection, DIST) == current
    record_review_direct(root, current)
    assert readiness(root) == ()
    assert any(
        item.code == "evidence.failed" for item in repository_findings(inspect_repository(root))
    )
    summary = review_summary(inspection, DIST)
    displayed = next(item for item in summary["reports"] if item["id"] == failed)
    assert displayed["requiredProfile"] and not displayed["reportedPassing"]
    assert displayed["path"].endswith(f"/{failed}.json")


def test_failure_acknowledgement_cannot_replace_passing_coverage(root):
    failed, _ = append_report(root, passing=False)
    directory = root / ".remek/skills/deploy-safely/evidence"
    for path in directory.glob("*.json"):
        report = json.loads(path.read_text())
        if report["evidenceKind"] == "behavior" and path.stem != failed:
            path.unlink()
    document = review_document(root)
    document["failureAcknowledgements"][0]["reason"] = "Owner acknowledged this failed report."
    with pytest.raises(RemekError, match="every required skill/profile slot"):
        validate(document, root)
    assert "release.evidence.behavior" in {item.code for item in readiness(root)}


def test_nonrequired_failures_are_bound_and_disclosed_without_new_profile_veto(root):
    failed, _ = append_report(root, passing=False, required=False)
    inspection = inspect_repository(root)
    assert review_status(inspection, DIST) == (False, "stale")
    document = review_document(root)
    assert document["failureAcknowledgements"] == []
    assert validate_review(document, inspection, DIST) == document
    summary = review_summary(inspection, DIST)
    assert summary["nonRequiredReports"] == 1
    assert any(item["id"] == failed and not item["requiredProfile"] for item in summary["reports"])
    document["selectedEvidence"].append(failed)
    document["selectedEvidence"].sort()
    with pytest.raises(RemekError, match="current, passing, and relevant"):
        validate_review(document, inspection, DIST)


def test_selected_evidence_rejects_fabricated_duplicate_and_unrequired_ids(root):
    inspection = inspect_repository(root)
    document = review_document(root)
    document["selectedEvidence"] = sorted([*document["selectedEvidence"], "0" * 64])
    with pytest.raises(RemekError, match="current, passing, and relevant"):
        validate_review(document, inspection, DIST)
    document["selectedEvidence"] = [document["selectedEvidence"][0]] * 2
    with pytest.raises(RemekError, match="sorted and unique"):
        validate_review_intrinsic(document)
    additional, _ = append_report(root, passing=True, required=False)
    document = review_document(root)
    document["selectedEvidence"] = sorted([*document["selectedEvidence"], additional])
    with pytest.raises(RemekError, match="relevant"):
        validate(document, root)


def test_every_distribution_declaration_and_skill_record_change_stales_review(root):
    distribution_path = root / ".remek/distributions/org-private.json"
    baseline = json.loads(distribution_path.read_text())
    for axis in ("hostname", "remote", "branch", "delivery", "evidence", "selection"):
        document = copy.deepcopy(baseline)
        if axis in {"hostname", "remote", "branch"}:
            document["target"][axis] = "ghe.example.com" if axis == "hostname" else "changed"
        elif axis == "delivery":
            document["delivery"] = ["npx"]
        elif axis == "evidence":
            document["evidencePolicy"]["behaviorProfiles"][0]["version"] = "2"
        else:
            document["skills"] = []
        write_input(distribution_path, document)
        assert status(root) == (False, "stale")
    write_input(distribution_path, baseline)
    path = root / ".remek/skills/deploy-safely/skill.json"
    original = json.loads(path.read_text())
    for axis in ("sourceNote", "rightsBasis", "cases", "exposure"):
        document = copy.deepcopy(original)
        if axis == "cases":
            document["cases"]["behavior"][0]["expectations"] = ["A different observed behavior."]
        elif axis == "exposure":
            document["exposure"] = "public-eligible"
        else:
            document["provenance"][axis] = "A changed owner declaration."
        write_input(path, document)
        inspection = inspect_repository(root)
        assert len(inspection.reviews) == 1
        assert not any(item.code == "review.malformed" for item in inspection.issues)
        assert review_status(inspection, DIST) == (False, "stale")


def test_candidate_and_case_revisions_retain_readable_historical_records(root):
    before = inspect_repository(root)
    payload = root / "skills/deploy-safely/SKILL.md"
    payload.write_bytes(payload.read_bytes() + b"\nNew reviewed instructions.\n")
    path = root / ".remek/skills/deploy-safely/skill.json"
    document = json.loads(path.read_text())
    document["cases"]["behavior"] = [
        {
            "id": "new-case",
            "prompt": "Run the revision.",
            "expectations": ["Use the revised behavior."],
        }
    ]
    write_input(path, document)
    inspection = inspect_repository(root)
    assert inspection.skill(SKILL).evidence == before.skill(SKILL).evidence
    assert inspection.reviews == before.reviews
    codes = {item.code for item in repository_findings(inspection)}
    assert "evidence.stale" in codes and "evidence.malformed" not in codes
    assert {"release.review", "release.evidence.routing", "release.evidence.behavior"} <= {
        item.code for item in release_findings(inspection, DIST)
    }


def test_policy_edits_deletions_and_unrelated_entries_bind_whole_review(root):
    policy_path = root / ".remek/disclosure-policy.json"
    write_input(policy_path, disclosure_document(disclosure_entry("client", "reviewed procedure")))
    document = review_document(root)
    entry = inspect_repository(root).disclosure.entries[0]
    document["disclosureExceptions"] = [exception(entry)]
    validate(document, root)
    record_review_direct(root, document)
    assert readiness(root) == ()
    for entries in (
        (
            disclosure_entry("client", "reviewed procedure"),
            disclosure_entry("unrelated", "Other", "note"),
        ),
        (),
        (disclosure_entry("client", "Changed"),),
    ):
        write_input(policy_path, disclosure_document(*entries))
        assert status(root) == (False, "stale")


def test_credentials_cannot_be_excepted_and_exported_names_are_screened(root):
    policy_path = root / ".remek/disclosure-policy.json"
    write_input(
        policy_path,
        disclosure_document(
            disclosure_entry("credential-entry", "nonmatching-private-value", "credential")
        ),
    )
    document = review_document(root)
    entry = inspect_repository(root).disclosure.entries[0]
    document["disclosureExceptions"] = [exception(entry)]
    with pytest.raises(RemekError, match="cannot be excepted"):
        validate(document, root)
    write_input(policy_path, disclosure_document(disclosure_entry("skill-name", SKILL)))
    summary = review_summary(inspect_repository(root), DIST)
    assert any(item["id"] == "skill-name" for item in summary["disclosureFindings"])
    assert "release.disclosure" in {item.code for item in readiness(root)}


def test_review_dates_flags_failures_and_exceptions_are_strict(root):
    baseline = review_document(root)
    for field, value in (
        ("reviewedOn", "2026-99-99"),
        ("reviewedOn", "2026-9-04"),
        ("reviewer", ""),
        ("rightsReviewed", 1),
        ("evidenceReviewed", False),
        ("proprietaryContentReviewed", "true"),
        ("publicIrreversibilityAcknowledged", 1),
    ):
        document = copy.deepcopy(baseline)
        document[field] = value
        with pytest.raises(RemekError):
            validate_review_intrinsic(document)
    document = copy.deepcopy(baseline)
    document["failureAcknowledgements"] = [{"report": "a" * 64, "reason": ""}]
    with pytest.raises(RemekError, match="reason"):
        validate_review_intrinsic(document)
    document = copy.deepcopy(baseline)
    document["disclosureExceptions"] = [
        {"skill": SKILL, "id": "client", "digest": "a" * 64, "reason": "x" * 1001}
    ]
    with pytest.raises(RemekError, match="reason"):
        validate_review_intrinsic(document)


def test_credential_provenance_is_not_echoed_by_checks_or_templates(root, capsys):
    skill_path = root / ".remek/skills/deploy-safely/skill.json"
    baseline = json.loads(skill_path.read_text())
    baseline["exposure"] = "public-eligible"
    distribution_path = root / ".remek/distributions/org-private.json"
    distribution = json.loads(distribution_path.read_text())
    distribution["audience"] = "public"
    distribution["target"]["expectedVisibility"] = "PUBLIC"
    write_input(distribution_path, distribution)
    secret = "gh" + "p_abcdefghijklmnopqrstuvwxyz"
    for field in ("sourceNote", "license"):
        document = copy.deepcopy(baseline)
        document["provenance"][field] = secret
        write_input(skill_path, document)
        for command, exit_code in (
            (["check"], 1),
            (["check", "--distribution", DIST], 1),
            (["eval", "plan", SKILL, "--kind", "behavior"], 2),
            (["review", "plan", DIST], 2),
        ):
            for flags in ([], ["--json"]):
                assert main(["--root", str(root), *flags, *command], bundle=TOOLCHAIN) == exit_code
                output = capsys.readouterr()
                leaked = secret in output.out + output.err
                assert not leaked


def test_empty_distribution_still_requires_explicit_review(tmp_path):
    root = initialized(tmp_path)
    document = distribution_document()
    document["skills"] = []
    write_input(root / ".remek/distributions/org-private.json", document)
    inspection = inspect_repository(root)
    assert not any(item.severity == "error" for item in repository_findings(inspection))
    assert {item.code for item in release_findings(inspection, DIST)} == {"release.review"}
    template = review_template(inspection, DIST)
    assert template["context"]["members"] == [] and template["selectedEvidence"] == []
    with pytest.raises(RemekError, match="actual completed"):
        validate_review(template, inspection, DIST)
    record_review(tmp_path, root)
    assert readiness(root) == ()


def test_missing_pointer_target_and_malformed_unused_review_do_not_hide_skill(root):
    path = root / ".remek/distributions/org-private.json"
    distribution = json.loads(path.read_text())
    distribution["activeReview"] = "0" * 64
    write_input(path, distribution)
    inspection = inspect_repository(root)
    assert any(item.code == "review.missing" for item in inspection.issues)
    assert review_status(inspection, DIST) == (False, "invalid")
    distribution["activeReview"] = None
    write_input(path, distribution)
    assert not any(item.severity == "error" for item in inspect_repository(root).issues)
    document = review_document(root)
    document["unexpected"] = True
    malformed = write_input(root / ".remek/reviews" / f"{record_id(document)}.json", document)
    inspection = inspect_repository(root)
    assert inspection.skill(SKILL)
    assert any(
        item.code == "review.malformed" and item.path == str(malformed.relative_to(root))
        for item in inspection.issues
    )
    assert "review.malformed" in {item.code for item in release_findings(inspection, DIST)}


def test_public_review_requires_visible_license_rights_and_irreversibility(tmp_path):
    root = initialized(tmp_path)
    authored(tmp_path, root)
    set_exposure(root, "public-eligible")
    authored_distribution(tmp_path, root)
    path = root / ".remek/distributions/org-private.json"
    distribution = json.loads(path.read_text())
    distribution["audience"] = "public"
    distribution["target"]["expectedVisibility"] = "PUBLIC"
    write_input(path, distribution)
    record_evidence(tmp_path, root)
    document = review_document(root)
    with pytest.raises(RemekError, match="irreversibility"):
        validate(document, root)
    document["publicIrreversibilityAcknowledged"] = True
    validate(document, root)
    record_review_direct(root, document)
    skill = inspect_repository(root).skill(SKILL)
    fields = dict(skill.fields)
    payload = skill.path / "SKILL.md"
    for license_value in (None, "Apache-2.0"):
        if license_value is None:
            fields.pop("license", None)
        else:
            fields["license"] = license_value
        payload.write_bytes(render_skill(fields, skill.body))
        finding = next(item for item in readiness(root) if item.code == "release.license")
        assert "expected 'MIT'" in finding.message and "repair: set SKILL.md" in finding.message


def test_whole_source_routing_cannot_cover_named_distribution_slot(root):
    directory = root / ".remek/skills/deploy-safely/evidence"
    routing = next(
        path
        for path in directory.glob("*.json")
        if json.loads(path.read_text())["evidenceKind"] == "routing"
    )
    document = json.loads(routing.read_text())
    document["distribution"] = None
    routing.unlink()
    write_input(directory / f"{record_id(document)}.json", document)
    inspection = inspect_repository(root)
    assert len(relevant_evidence(inspection, DIST, SKILL)) == 1
    assert "release.evidence.routing" in {item.code for item in release_findings(inspection, DIST)}


def test_full_batch_review_uses_only_its_explicit_larger_parser_envelope(tmp_path):
    root = initialized(tmp_path)
    empty = distribution_document()
    empty["skills"] = []
    write_input(root / ".remek/distributions/org-private.json", empty)
    document = review_document(root)
    distribution = distribution_document()
    distribution["skills"] = [f"skill-{index:03}" for index in range(128)]
    profiles = [{**PROFILE, "name": f"profile-{index}"} for index in range(16)]
    distribution["evidencePolicy"] = {"routingProfiles": profiles, "behaviorProfiles": profiles}
    subject = parse_distribution(distribution).subject_fields()
    context = {
        "distribution": subject,
        "members": [
            {
                "skill": name,
                "candidateDigest": "a" * 64,
                "skillRecordDigest": "b" * 64,
                "routingCaseDigest": "c" * 64,
                "behaviorCaseDigest": "d" * 64,
                "evidenceSetDigest": "e" * 64,
            }
            for name in distribution["skills"]
        ],
        "disclosurePolicyDigest": "f" * 64,
    }
    document.update(
        context=context,
        contextDigest=ReviewContext(context).digest,
        selectedEvidence=[f"{index:064x}" for index in range(4096)],
    )
    validate_review_intrinsic(document)
    data = render_document(
        "release-review",
        {key: value for key, value in document.items() if key not in {"schema", "kind"}},
    )
    assert len(data) < 512 << 10
    assert parse_document(data, kind="release-review") == document
