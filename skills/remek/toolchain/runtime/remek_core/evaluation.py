# ruff: noqa: D101, D102, D103, I001
"""Evidence."""

import hashlib
from dataclasses import dataclass
from typing import cast

from .contract import SCHEMA, JSONObject, JSONValue, render_document as render
from .model import Error, valid_skill_name

_HEX = set("0123456789abcdef")
_EVIDENCE_KEYS = {
    "schema",
    "kind",
    "evidenceKind",
    "skill",
    "candidate",
    "caseSetDigest",
    "routingCatalogDigest",
    "distribution",
    "profile",
    "results",
    "artifacts",
}


@dataclass(frozen=True)
class Case:
    case_id: str
    prompt: str
    expected: bool | tuple[str, ...]


@dataclass(frozen=True)
class CaseSet:
    kind: str
    cases: tuple[Case, ...]

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.render()).hexdigest()

    def render(self) -> bytes:
        outcome = "shouldActivate" if self.kind == "routing" else "expectations"
        values: list[JSONValue] = [
            {
                "id": case.case_id,
                "prompt": case.prompt,
                outcome: case.expected if isinstance(case.expected, bool) else list(case.expected),
            }
            for case in self.cases
        ]
        return render(f"{self.kind}-cases", {"cases": values})


@dataclass(frozen=True)
class EvidencePlan:
    skill: str
    candidate: str
    case_set: CaseSet
    routing_catalog_digest: str | None
    distribution: str | None = None

    def template(self) -> JSONObject:
        return {
            "schema": SCHEMA,
            "kind": "eval-evidence",
            "evidenceKind": self.case_set.kind,
            "skill": self.skill,
            "candidate": self.candidate,
            "caseSetDigest": self.case_set.digest,
            "routingCatalogDigest": self.routing_catalog_digest,
            "distribution": self.distribution,
            "profile": {
                "kind": "manual-host",
                "name": "",
                "version": "",
                "claim": "regression",
                "runConfigDigest": "",
                "trialCount": 3,
                "minimumPassCount": 3,
            },
            "results": [{"caseId": case.case_id, "passCount": 0} for case in self.case_set.cases],
            "artifacts": [{"label": "evaluation-report", "digest": ""}],
        }


def _text(value: object, label: str, limit: int = 2000, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()):
        raise Error("evidence.shape", f"invalid {label}")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or set(value) - _HEX:
        raise Error("evidence.identity", f"{label} must be one sha256 digest")
    return value


def parse_case_set(document: JSONObject, kind: str) -> CaseSet:
    expected_kind = f"{kind}-cases"
    values = document.get("cases")
    if (
        kind not in {"routing", "behavior"}
        or document.get("kind") != expected_kind
        or set(document) != {"schema", "kind", "cases"}
        or not isinstance(values, list)
        or not 1 <= len(values) <= 50
    ):
        raise Error("cases.shape", f"invalid {expected_kind} document")
    result: list[Case] = []
    for value in values:
        outcome = "shouldActivate" if kind == "routing" else "expectations"
        keys = {"id", "prompt", outcome}
        if not isinstance(value, dict) or set(value) != keys:
            raise Error("cases.shape", "invalid case fields")
        identifier = _text(value.get("id"), "case id", 64)
        prompt = _text(value.get("prompt"), "case prompt")
        expected = value.get(outcome)
        if not valid_skill_name(identifier) or (
            kind == "routing" and not isinstance(expected, bool)
        ):
            raise Error("cases.value", "invalid case id or expectation")
        parsed: bool | tuple[str, ...]
        if kind == "behavior":
            if (
                not isinstance(expected, list)
                or not 1 <= len(expected) <= 12
                or len(expected) != len(set(item for item in expected if isinstance(item, str)))
            ):
                raise Error("cases.value", "behavior needs unique expectations")
            parsed = tuple(_text(item, "behavior expectation", 500) for item in expected)
        else:
            parsed = cast(bool, expected)
        result.append(Case(identifier, prompt, parsed))
    if len({case.case_id for case in result}) != len(result) or len(
        {case.prompt for case in result}
    ) != len(result):
        raise Error("cases.duplicate", "case ids and prompts must be unique")
    if kind == "routing" and {case.expected for case in result} != {False, True}:
        raise Error("cases.contrast", "routing needs positive and contrastive cases")
    return CaseSet(kind, tuple(result))


def routing_catalog_digest(catalog: tuple[tuple[str, str], ...]) -> str:
    digest = hashlib.sha256(b"remek.routing-catalog.v1\0")
    for pair in catalog:
        for value in pair:
            data = value.encode()
            digest.update(len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


def parse_profile(value: object) -> JSONObject:
    keys = {
        "kind",
        "name",
        "version",
        "claim",
        "runConfigDigest",
        "trialCount",
        "minimumPassCount",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise Error("evidence.profile", "invalid evaluator profile")
    kind = value.get("kind")
    claim = value.get("claim")
    trials, minimum = value.get("trialCount"), value.get("minimumPassCount")
    if (
        not isinstance(kind, str)
        or kind not in ("manual-host", "test-suite", "external")
        or not isinstance(claim, str)
        or claim not in ("smoke", "regression", "comparative")
        or type(trials) is not int
        or type(minimum) is not int
        or not 1 <= minimum <= trials <= 10
    ):
        raise Error("evidence.profile", "unsupported evaluator profile")
    return {
        "kind": kind,
        "name": _text(value.get("name"), "profile name", 128),
        "version": _text(value.get("version"), "profile version", 128),
        "claim": claim,
        "runConfigDigest": _digest(value.get("runConfigDigest"), "run configuration"),
        "trialCount": trials,
        "minimumPassCount": minimum,
    }


def profile_key(profile: JSONObject) -> str:
    fields = {
        "profileKind": profile["kind"],
        "name": profile["name"],
        "version": profile["version"],
        "claim": profile["claim"],
        "runConfigDigest": profile["runConfigDigest"],
        "trialCount": profile["trialCount"],
        "minimumPassCount": profile["minimumPassCount"],
    }
    return hashlib.sha256(render("evaluator-profile", fields)).hexdigest()


def validate_evidence_intrinsic(
    document: JSONObject, *, stored: bool = False
) -> tuple[JSONObject, bool]:
    expected_kind = "eval-receipt" if stored else "eval-evidence"
    evidence_kind = document.get("evidenceKind")
    skill = document.get("skill")
    distribution = document.get("distribution")
    routing = document.get("routingCatalogDigest")
    if (
        document.get("schema") != SCHEMA
        or document.get("kind") != expected_kind
        or set(document) != _EVIDENCE_KEYS
        or not isinstance(evidence_kind, str)
        or evidence_kind not in ("routing", "behavior")
        or not valid_skill_name(skill)
        or (distribution is not None and not valid_skill_name(distribution))
    ):
        raise Error("evidence.shape", "invalid evidence fields")
    _digest(document.get("candidate"), "candidate")
    _digest(document.get("caseSetDigest"), "case set")
    if routing is not None:
        _digest(routing, "routing catalog")
    if (evidence_kind == "routing") != (routing is not None) or (
        evidence_kind == "behavior" and distribution is not None
    ):
        raise Error("evidence.shape", "invalid evidence bindings")
    profile = parse_profile(document.get("profile"))
    trial_count = cast(int, profile["trialCount"])
    minimum = cast(int, profile["minimumPassCount"])
    values = document.get("results")
    if not isinstance(values, list) or not 1 <= len(values) <= 50:
        raise Error("evidence.results", "invalid result list")
    passed, case_ids = True, set()
    for value in values:
        if not isinstance(value, dict) or set(value) != {"caseId", "passCount"}:
            raise Error("evidence.results", "results must follow case order")
        case_id, pass_count = value.get("caseId"), value.get("passCount")
        if (
            not valid_skill_name(case_id)
            or case_id in case_ids
            or type(pass_count) is not int
            or not 0 <= pass_count <= trial_count
        ):
            raise Error("evidence.results", "invalid or repeated result")
        case_ids.add(cast(str, case_id))
        passed = passed and pass_count >= minimum
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 32:
        raise Error("evidence.artifacts", "invalid artifact list")
    labels: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"label", "digest"}:
            raise Error("evidence.artifacts", "invalid artifact entry")
        label = _text(artifact.get("label"), "artifact label", 128)
        _digest(artifact.get("digest"), "artifact")
        if label in labels:
            raise Error("evidence.artifacts", "artifact labels must be unique")
        labels.add(label)
    if "evaluation-report" not in labels:
        raise Error("evidence.artifacts", "evaluation-report artifact required")
    return {**document, "profile": profile}, passed


def validate_evidence(document: JSONObject, plan: EvidencePlan) -> tuple[JSONObject, bool]:
    normalized, passed = validate_evidence_intrinsic(document)
    routing = normalized.get("routingCatalogDigest")
    bindings = (
        normalized.get("skill") == plan.skill,
        normalized.get("evidenceKind") == plan.case_set.kind,
        normalized.get("candidate") == plan.candidate,
        normalized.get("caseSetDigest") == plan.case_set.digest,
        routing == plan.routing_catalog_digest,
        normalized.get("distribution") == plan.distribution,
    )
    if not all(bindings):
        raise Error(
            "evidence.stale", "current bound inputs differ; nothing recorded; plan fresh evidence"
        )
    values = cast(list[JSONObject], normalized["results"])
    if len(values) != len(plan.case_set.cases):
        raise Error("evidence.results", "result count differs from case set")
    for case, value in zip(plan.case_set.cases, values, strict=True):
        if value.get("caseId") != case.case_id:
            raise Error("evidence.results", "results must follow case order")
    return normalized, passed


def receipt_document(document: JSONObject, plan: EvidencePlan) -> bytes:
    normalized, _ = validate_evidence(document, plan)
    return render(
        "eval-receipt",
        {key: value for key, value in normalized.items() if key not in {"schema", "kind"}},
    )


def receipt_status(document: JSONObject, plan: EvidencePlan) -> tuple[bool, bool, str]:
    normalized, passed = validate_evidence({**document, "kind": "eval-evidence"}, plan)
    return True, passed, profile_key(cast(JSONObject, normalized["profile"]))
