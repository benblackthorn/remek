# ruff: noqa: D101, D102, D103, I001
"""One evidence-bound owner review of a complete distribution release subject."""

import hashlib
import re
from dataclasses import dataclass
from datetime import date
from typing import cast

from .contract import SCHEMA, JSONObject, JSONValue, render_document as render
from .evaluation import evaluation_status, profile_key, report_profile
from .model import Error, Finding, valid_skill_name
from .repository import (
    DISCLOSURE_PATH,
    Distribution,
    RepositoryInspection,
    _digest,
    _f,
    _text,
    disclosure_matches,
    evaluation_plan,
    parse_distribution,
    redact_credential_text,
    repository_findings,
)


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_id(document: JSONObject) -> str:
    return _hash(
        render(
            cast(str, document["kind"]),
            {key: value for key, value in document.items() if key not in {"schema", "kind"}},
        )
    )


def relevant_evidence(
    inspection: RepositoryInspection, dist: str, skill: str
) -> tuple[tuple[str, JSONObject, bool, str], ...]:
    distribution = inspection.distribution(dist)
    if skill not in distribution.skills:
        raise Error("review.skill", "skill is outside the distribution")
    member = inspection.skill(skill)
    result: list[tuple[str, JSONObject, bool, str]] = []
    for report in member.evidence:
        kind = cast(str, report["evidenceKind"])
        try:
            plan = evaluation_plan(inspection, skill, kind, dist if kind == "routing" else None)
            _, passed, profile = evaluation_status(report, plan)
        except Error:
            continue
        result.append((record_id(report), report, passed, profile))
    return tuple(sorted(result, key=lambda item: item[0]))


@dataclass(frozen=True)
class ReviewContext:
    fields: JSONObject

    @property
    def digest(self) -> str:
        return _hash(b"remek.review-context.v2\0" + render("review-context", self.fields))


def review_context(inspection: RepositoryInspection, dist: str) -> ReviewContext:
    distribution = inspection.distribution(dist)
    if inspection.disclosure is None:
        raise Error("review.disclosure", "missing disclosure policy; restore it before review")
    members: list[JSONValue] = []
    for name in distribution.skills:
        skill = inspection.skill(name)
        reports: list[JSONValue] = [item[0] for item in relevant_evidence(inspection, dist, name)]
        members.append(
            {
                "skill": name,
                "candidateDigest": skill.digest,
                "skillRecordDigest": skill.record.digest,
                "routingCaseDigest": skill.routing_cases.digest,
                "behaviorCaseDigest": skill.behavior_cases.digest,
                "evidenceSetDigest": _hash(
                    b"remek.evidence-set.v2\0" + render("evidence-set", {"reports": reports})
                ),
            }
        )
    return ReviewContext(
        {
            "distribution": distribution.subject_fields(),
            "members": members,
            "disclosurePolicyDigest": _hash(inspection.disclosure.render()),
        }
    )


def _required(distribution: Distribution) -> set[tuple[str, str, str]]:
    return {
        (name, kind, profile_key(profile))
        for name in distribution.skills
        for kind, profiles in (
            ("routing", distribution.routing_profiles),
            ("behavior", distribution.behavior_profiles),
        )
        for profile in profiles
    }


def _inventory(
    inspection: RepositoryInspection, dist: str
) -> dict[str, tuple[str, str, str, bool, JSONObject]]:
    return {
        identifier: (name, cast(str, report["evidenceKind"]), key, passed, report)
        for name in inspection.distribution(dist).skills
        for identifier, report, passed, key in relevant_evidence(inspection, dist, name)
    }


def review_template(inspection: RepositoryInspection, dist: str) -> JSONObject:
    context = review_context(inspection, dist)
    required = _required(inspection.distribution(dist))
    inventory = _inventory(inspection, dist)
    selected: set[str] = set()
    failures: list[JSONValue] = []
    for slot in sorted(required):
        passing = [
            identifier
            for identifier, (name, kind, key, passed, _) in inventory.items()
            if (name, kind, key) == slot and passed
        ]
        if passing:
            selected.add(min(passing))
    for identifier, (name, kind, key, passed, _) in sorted(inventory.items()):
        if not passed and (name, kind, key) in required:
            failures.append({"report": identifier, "reason": ""})
    return {
        "schema": SCHEMA,
        "kind": "release-review",
        "context": context.fields,
        "contextDigest": context.digest,
        "selectedEvidence": list(sorted(selected)),
        "failureAcknowledgements": failures,
        "disclosureExceptions": [],
        "reviewer": "",
        "reviewedOn": "",
        "rightsReviewed": False,
        "evidenceReviewed": False,
        "proprietaryContentReviewed": False,
        "publicIrreversibilityAcknowledged": False,
    }


def _ids(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(_digest(item) for item in value):
        raise Error("review.identity", f"{label} must contain SHA-256 identities")
    ids = cast(list[str], value)
    if ids != sorted(set(ids)):
        raise Error("review.identity", f"{label} must be sorted and unique")
    return ids


def validate_review_intrinsic(document: JSONObject) -> JSONObject:  # noqa: PLR0912, PLR0915
    keys = {
        "schema",
        "kind",
        "context",
        "contextDigest",
        "selectedEvidence",
        "failureAcknowledgements",
        "disclosureExceptions",
        "reviewer",
        "reviewedOn",
        "rightsReviewed",
        "evidenceReviewed",
        "proprietaryContentReviewed",
        "publicIrreversibilityAcknowledged",
    }
    if (
        document.get("schema") != SCHEMA
        or document.get("kind") != "release-review"
        or set(document) != keys
    ):
        raise Error("review.shape", "invalid release review fields")
    context = document.get("context")
    if not isinstance(context, dict) or set(context) != {
        "distribution",
        "members",
        "disclosurePolicyDigest",
    }:
        raise Error("review.context", "invalid review context fields")
    subject = context.get("distribution")
    if not isinstance(subject, dict):
        raise Error("review.context", "invalid distribution subject")
    distribution = parse_distribution(
        {"schema": SCHEMA, "kind": "distribution", **subject, "activeReview": None}
    )
    if subject != distribution.subject_fields():
        raise Error("review.context", "distribution subject must be complete and normalized")
    members = context.get("members")
    member_keys = {
        "skill",
        "candidateDigest",
        "skillRecordDigest",
        "routingCaseDigest",
        "behaviorCaseDigest",
        "evidenceSetDigest",
    }
    if not isinstance(members, list) or len(members) != len(distribution.skills):
        raise Error("review.context", "review members must match the exact distribution selection")
    names: list[str] = []
    for member in members:
        if (
            not isinstance(member, dict)
            or set(member) != member_keys
            or not valid_skill_name(member.get("skill"))
            or not all(_digest(member.get(key)) for key in member_keys - {"skill"})
        ):
            raise Error("review.context", "invalid review member identity")
        names.append(cast(str, member["skill"]))
    if tuple(names) != distribution.skills or not _digest(context.get("disclosurePolicyDigest")):
        raise Error("review.context", "members must be ordered and policy digest valid")
    if document.get("contextDigest") != ReviewContext(context).digest:
        raise Error("review.context", "review context digest differs")
    _ids(document.get("selectedEvidence"), "selected evidence")
    failures = document.get("failureAcknowledgements")
    if not isinstance(failures, list):
        raise Error("review.failures", "invalid failure acknowledgements")
    failure_ids: list[JSONValue] = []
    for value in failures:
        if not isinstance(value, dict) or set(value) != {"report", "reason"}:
            raise Error("review.failures", "failure acknowledgement requires report and reason")
        failure_ids.append(value["report"])
        _text(value.get("reason"), "failure acknowledgement reason", 1000)
    _ids(failure_ids, "failure acknowledgements")
    exceptions = document.get("disclosureExceptions")
    if not isinstance(exceptions, list):
        raise Error("review.exceptions", "invalid disclosure exceptions")
    exception_keys: list[tuple[str, str]] = []
    for value in exceptions:
        if (
            not isinstance(value, dict)
            or set(value) != {"skill", "id", "digest", "reason"}
            or not isinstance(value.get("skill"), str)
            or value["skill"] not in distribution.skills
            or not valid_skill_name(value.get("id"))
            or not _digest(value.get("digest"))
        ):
            raise Error("review.exceptions", "invalid disclosure exception identity")
        _text(value.get("reason"), "disclosure exception reason", 1000)
        exception_keys.append((value["skill"], cast(str, value["id"])))
    if exception_keys != sorted(set(exception_keys)) or any(
        sum(name == skill for name, _ in exception_keys) > 64 for skill in distribution.skills
    ):
        raise Error(
            "review.exceptions", "exceptions must be sorted, unique, and at most 64 per skill"
        )
    for field in ("rightsReviewed", "evidenceReviewed", "proprietaryContentReviewed"):
        if document.get(field) is not True:
            raise Error("review.incomplete", f"{field} must record actual completed owner review")
    public = document.get("publicIrreversibilityAcknowledged")
    if type(public) is not bool or (distribution.audience == "public" and public is not True):
        raise Error("review.incomplete", "public review requires irreversibility acknowledgement")
    _text(document.get("reviewer"), "reviewer declaration", 128)
    reviewed_on = _text(document.get("reviewedOn"), "review date", 10)
    try:
        date.fromisoformat(reviewed_on)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", reviewed_on) is None:
            raise ValueError
    except ValueError:
        raise Error("review.date", "reviewedOn invalid; use YYYY-MM-DD") from None
    return document


def _subject_findings(inspection: RepositoryInspection, dist: str) -> list[Finding]:
    issues = [item for item in repository_findings(inspection) if item.severity == "error"]
    if any(
        item.code.startswith("credential.") or item.code == "disclosure.credential"
        for item in issues
    ):
        return issues
    distribution = inspection.distribution(dist)
    for name in distribution.skills:
        try:
            skill = inspection.skill(name)
        except Error:
            continue
        path = f".remek/skills/{name}/skill.json"
        if skill.record.exposure == "source-only" or (
            distribution.audience == "public" and skill.record.exposure != "public-eligible"
        ):
            issues.append(
                _f(
                    "release.exposure",
                    "distribution audience exceeds declared skill exposure",
                    path,
                )
            )
        if not all(
            (
                skill.provenance.rights.strip(),
                skill.provenance.rights_basis.strip(),
                skill.provenance.license.strip(),
            )
        ):
            issues.append(
                _f(
                    "release.rights",
                    "rights, rights basis, and license are required before release",
                    path,
                )
            )
        candidate_license = skill.fields.get("license")
        if distribution.audience == "public" and (
            not isinstance(candidate_license, str)
            or not candidate_license.strip()
            or candidate_license != skill.provenance.license
        ):
            actual = (
                repr(candidate_license)
                if isinstance(candidate_license, str) and len(candidate_license) <= 128
                else "missing or invalid"
            )
            actual = redact_credential_text(actual, inspection.disclosure)
            expected = redact_credential_text(repr(skill.provenance.license), inspection.disclosure)
            issues.append(
                _f(
                    "release.license",
                    f"actual candidate license is {actual}; expected {expected}; "
                    "repair: set SKILL.md license to the reviewed value "
                    "or correct the skill record",
                    str(skill.path.relative_to(inspection.root) / "SKILL.md"),
                )
            )
    if inspection.disclosure is None:
        issues.append(_f("release.disclosure", "missing disclosure policy", DISCLOSURE_PATH))
    return issues


def _evidence_findings(inspection: RepositoryInspection, dist: str) -> list[Finding]:
    distribution = inspection.distribution(dist)
    inventory = _inventory(inspection, dist)
    passing = {(name, kind, key) for name, kind, key, passed, _ in inventory.values() if passed}
    return [
        _f(
            f"release.evidence.{kind}",
            f"required profile {key} has no current reported-passing evaluation",
            f".remek/skills/{name}/evidence",
        )
        for name, kind, key in sorted(_required(distribution) - passing)
    ]


def validate_review(
    document: JSONObject, inspection: RepositoryInspection, dist: str
) -> JSONObject:
    validated = validate_review_intrinsic(document)
    context = review_context(inspection, dist)
    if document["context"] != context.fields or document["contextDigest"] != context.digest:
        raise Error(
            "review.stale",
            "review subject differs from current selection, declarations, policy, or evidence",
        )
    issues = _subject_findings(inspection, dist)
    if issues:
        raise Error(
            "review.blocked", "source has blocking findings; repair them before recording review"
        )
    required = _required(inspection.distribution(dist))
    inventory = _inventory(inspection, dist)
    covered: set[tuple[str, str, str]] = set()
    for identifier in cast(list[str], document["selectedEvidence"]):
        selected_entry = inventory.get(identifier)
        if selected_entry is None or not selected_entry[3] or selected_entry[:3] not in required:
            raise Error(
                "review.evidence",
                "selected evidence must be current, passing, and relevant to a required slot",
            )
        covered.add(selected_entry[:3])
    if covered != required:
        raise Error(
            "review.evidence", "selected evidence does not cover every required skill/profile slot"
        )
    failures = {
        identifier
        for identifier, (name, kind, key, passed, _) in inventory.items()
        if not passed and (name, kind, key) in required
    }
    acknowledged = {
        cast(str, value["report"])
        for value in cast(list[JSONObject], document["failureAcknowledgements"])
    }
    if failures != acknowledged:
        raise Error(
            "review.failures",
            "every current required-profile failure needs exactly one owner-reviewed reason",
        )
    policy = inspection.disclosure
    assert policy is not None
    entries = policy.active()
    exceptions: set[tuple[str, str]] = set()
    for value in cast(list[JSONObject], document["disclosureExceptions"]):
        identifier, name = cast(str, value["id"]), cast(str, value["skill"])
        entry = entries.get(identifier)
        if entry is None or entry.digest != value["digest"]:
            raise Error("review.exceptions", "disclosure exception is unknown or stale")
        if entry.entry_class == "credential":
            raise Error("review.exceptions", "credentials cannot be excepted")
        exceptions.add((name, identifier))
    distribution = inspection.distribution(dist)
    for name in distribution.skills:
        for entry, _ in disclosure_matches(inspection.skill(name), policy, distribution):
            if entry.entry_class == "credential" or (name, entry.entry_id) not in exceptions:
                raise Error(
                    "review.disclosure",
                    "disclosure matches need redaction or an explicit noncredential exception",
                )
    return validated


def review_status(inspection: RepositoryInspection, dist: str) -> tuple[bool, str]:
    identifier = inspection.distribution(dist).active_review
    if identifier is None:
        return False, "missing"
    document = next((value for value in inspection.reviews if record_id(value) == identifier), None)
    if document is None:
        return False, "invalid"
    try:
        validate_review(document, inspection, dist)
    except Error as exc:
        return False, "stale" if exc.code == "review.stale" else "invalid"
    return True, "current"


def release_findings(inspection: RepositoryInspection, dist: str) -> tuple[Finding, ...]:
    issues = _subject_findings(inspection, dist)
    if any(item.code in {"evidence.malformed", "review.malformed"} for item in issues):
        return tuple(sorted(set(issues)))
    # Missing members prevent context construction; structural findings already name their paths.
    if any(
        name not in {skill.name for skill in inspection.skills}
        for name in inspection.distribution(dist).skills
    ):
        return tuple(sorted(set(issues)))
    issues.extend(_evidence_findings(inspection, dist))
    current, status = review_status(inspection, dist)
    if not current:
        messages = {
            "missing": "no active review is selected",
            "stale": "selected review no longer matches the complete release subject",
            "invalid": "selected review is missing, malformed, or cannot authorize this release",
        }
        issues.append(_f("release.review", messages[status], f".remek/distributions/{dist}.json"))
    distribution, policy = inspection.distribution(dist), inspection.disclosure
    exceptions: set[tuple[str, str]] = set()
    if current:
        document = next(
            value for value in inspection.reviews if record_id(value) == distribution.active_review
        )
        exceptions = {
            (cast(str, value["skill"]), cast(str, value["id"]))
            for value in cast(list[JSONObject], document["disclosureExceptions"])
        }
    if policy:
        for name in distribution.skills:
            skill = inspection.skill(name)
            for entry, path in disclosure_matches(skill, policy, distribution):
                if entry.entry_class == "credential" or (name, entry.entry_id) not in exceptions:
                    issues.append(
                        _f(
                            "release.disclosure",
                            f"entry {entry.entry_id} requires redaction or a reviewed "
                            "noncredential exception",
                            str(skill.path.relative_to(inspection.root) / path),
                        )
                    )
    return tuple(sorted(set(issues)))


def review_summary(inspection: RepositoryInspection, dist: str) -> JSONObject:
    if any(
        item.code.startswith("credential.") or item.code == "disclosure.credential"
        for item in inspection.issues
    ):
        raise Error(
            "review.credentials", "remove source credential findings before preparing a packet"
        )
    distribution = inspection.distribution(dist)
    inventory = _inventory(inspection, dist)
    required = _required(distribution)
    template = review_template(inspection, dist)
    selected = set(cast(list[str], template["selectedEvidence"]))
    reports: list[JSONValue] = []
    for identifier, (name, kind, key, passed, report) in sorted(inventory.items()):
        reports.append(
            {
                "id": identifier,
                "path": f".remek/skills/{name}/evidence/{identifier}.json",
                "skill": name,
                "evidenceKind": kind,
                "profile": report_profile(report),
                "reportedPassing": passed,
                "requiredProfile": (name, kind, key) in required,
                "selected": identifier in selected,
            }
        )
    disclosure: list[JSONValue] = []
    if inspection.disclosure:
        for name in distribution.skills:
            for entry, path in disclosure_matches(
                inspection.skill(name), inspection.disclosure, distribution
            ):
                disclosure.append(
                    {
                        "skill": name,
                        "id": entry.entry_id,
                        "digest": entry.digest,
                        "class": entry.entry_class,
                        "path": path,
                    }
                )
    return {
        "distribution": distribution.subject_fields(),
        "reports": reports,
        "additionalPassingReports": sum(
            passed and identifier not in selected
            for identifier, (_, _, _, passed, _) in inventory.items()
        ),
        "nonRequiredReports": sum(
            (name, kind, key) not in required for name, kind, key, _, _ in inventory.values()
        ),
        "provenance": [
            {"skill": name, **inspection.skill(name).provenance.as_dict()}
            for name in distribution.skills
        ],
        "disclosureFindings": disclosure,
        "publishedManifestMetadata": [
            "audience; candidate names and digests; directory/file paths, modes and digests; "
            "expectedCommitPaths",
            "sourceCommit and preReleaseHead Git identifiers",
            "sourceRepositoryIdentity, sourceBranchDigest and distributionIdentity hashes",
            "targetVerificationDigest and remoteBinding hashes of target identity, visibility, "
            "remote name and fetch/push URLs; staging records no target verification",
            "releaseId, releaseSetDigest, payloadDigest and reviewDigest",
            "Hashes of guessable private labels are not confidential redaction. Inspect exact "
            "release-manifest.json bytes in the release plan diff before applying it.",
        ],
        "blockingFindings": [
            {"code": item.code, "message": item.message, "path": item.path}
            for item in sorted(
                set(_subject_findings(inspection, dist) + _evidence_findings(inspection, dist))
            )
        ],
        "claimLimit": (
            "These are caller-reported observations and declared review; execution "
            "and reviewer identity are not authenticated. External artifact bytes "
            "and availability were not checked."
        ),
    }
