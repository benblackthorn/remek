# ruff: noqa: D101, D102, D103, I001
"""Retained caller-reported evaluation observations and current-context matching."""

import hashlib
from dataclasses import dataclass
from typing import cast

from .contract import SCHEMA, JSONObject, JSONValue, render_document as render
from .model import Error, valid_skill_name

_HEX = set("0123456789abcdef")
_EVALUATION_KEYS = {
    "schema",
    "kind",
    "evidenceKind",
    "skill",
    "candidate",
    "caseSetDigest",
    "routingCatalogDigest",
    "distribution",
    "profile",
    "runConfiguration",
    "trials",
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
class EvaluationPlan:
    skill: str
    candidate: str
    case_set: CaseSet
    routing_catalog_digest: str | None
    distribution: str | None = None

    def template(self) -> JSONObject:
        return {
            "schema": SCHEMA,
            "kind": "evaluation",
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
                "trialCount": 3,
                "minimumPassCount": 3,
            },
            "runConfiguration": "",
            "trials": [
                {"caseId": case.case_id, "trial": trial, "outcome": "unreported", "observation": ""}
                for case in self.case_set.cases
                for trial in range(1, 4)
            ],
            "artifacts": [],
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
        or len(values) > 50
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
    if result and kind == "routing" and {case.expected for case in result} != {False, True}:
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


def report_profile(document: JSONObject) -> JSONObject:
    configuration = _text(document.get("runConfiguration"), "run configuration", 16384)
    try:
        data = configuration.encode("utf-8")
    except UnicodeError:
        raise Error("evidence.configuration", "run configuration must be UTF-8") from None
    if len(data) > 16384:
        raise Error("evidence.configuration", "run configuration exceeds 16 KiB")
    value = document.get("profile")
    if not isinstance(value, dict) or "runConfigDigest" in value:
        raise Error(
            "evidence.profile", "report profile must omit the computed configuration digest"
        )
    return parse_profile({**value, "runConfigDigest": hashlib.sha256(data).hexdigest()})


def _observation(value: object) -> str:
    text = _text(value, "trial observation", 500)
    # Hygiene only: a credible-looking declaration is not authenticated execution.
    if text.strip().casefold() in {
        "todo",
        "tbd",
        "placeholder",
        "observation",
        "<actual observed behavior>",
    }:
        raise Error("evidence.observation", "trial observation is a placeholder")
    return text


def validate_evaluation_intrinsic(  # noqa: PLR0912, PLR0915
    document: JSONObject,
) -> tuple[JSONObject, bool]:
    evidence_kind = document.get("evidenceKind")
    skill = document.get("skill")
    distribution = document.get("distribution")
    routing = document.get("routingCatalogDigest")
    if (
        document.get("schema") != SCHEMA
        or document.get("kind") != "evaluation"
        or set(document) not in (_EVALUATION_KEYS, _EVALUATION_KEYS - {"artifacts"})
        or not isinstance(evidence_kind, str)
        or evidence_kind not in ("routing", "behavior")
        or not valid_skill_name(skill)
        or (distribution is not None and not valid_skill_name(distribution))
    ):
        raise Error("evidence.shape", "invalid evaluation fields")
    _digest(document.get("candidate"), "candidate")
    _digest(document.get("caseSetDigest"), "case set")
    if routing is not None:
        _digest(routing, "routing catalog")
    if (evidence_kind == "routing") != (routing is not None) or (
        evidence_kind == "behavior" and distribution is not None
    ):
        raise Error("evidence.shape", "invalid evaluation bindings")
    profile = report_profile(document)
    trial_count = cast(int, profile["trialCount"])
    minimum = cast(int, profile["minimumPassCount"])
    trials = document.get("trials")
    if not isinstance(trials, list) or not trials or len(trials) > 50 * trial_count:
        raise Error("evidence.trials", "invalid trial list")
    case_ids: set[str] = set()
    previous: str | None = None
    expected_trial, pass_count, passed = 1, 0, True
    for row in trials:
        if not isinstance(row, dict) or set(row) != {"caseId", "trial", "outcome", "observation"}:
            raise Error(
                "evidence.trials", "each trial needs caseId, trial, outcome, and observation"
            )
        identifier, trial, outcome = row.get("caseId"), row.get("trial"), row.get("outcome")
        if not valid_skill_name(identifier) or type(trial) is not int:
            raise Error("evidence.trials", "invalid case id or trial index")
        case_id = cast(str, identifier)
        if case_id != previous:
            if case_id in case_ids or (previous is not None and expected_trial != trial_count + 1):
                raise Error("evidence.trials", "trials must form complete ordered case groups")
            if previous is not None:
                passed = passed and pass_count >= minimum
            case_ids.add(case_id)
            previous, expected_trial, pass_count = case_id, 1, 0
        if trial != expected_trial or trial > trial_count:
            raise Error("evidence.trials", "trial indices must be exactly 1 through trialCount")
        if not isinstance(outcome, str) or outcome not in {"pass", "fail", "error"}:
            raise Error(
                "evidence.trials", "only reported pass, fail, or error outcomes may be recorded"
            )
        _observation(row.get("observation"))
        pass_count += outcome == "pass"
        expected_trial += 1
    if expected_trial != trial_count + 1:
        raise Error("evidence.trials", "last case trial group is incomplete")
    passed = passed and pass_count >= minimum
    artifacts = document.get("artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) > 32:
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
    return document, passed


def validate_evaluation(document: JSONObject, plan: EvaluationPlan) -> tuple[JSONObject, bool]:
    normalized, passed = validate_evaluation_intrinsic(document)
    bindings = (
        normalized.get("skill") == plan.skill,
        normalized.get("evidenceKind") == plan.case_set.kind,
        normalized.get("candidate") == plan.candidate,
        normalized.get("caseSetDigest") == plan.case_set.digest,
        normalized.get("routingCatalogDigest") == plan.routing_catalog_digest,
        normalized.get("distribution") == plan.distribution,
    )
    if not all(bindings):
        raise Error(
            "evidence.stale", "current bound inputs differ; nothing recorded; plan fresh evidence"
        )
    profile = report_profile(normalized)
    trial_count = cast(int, profile["trialCount"])
    expected = [
        (case.case_id, trial) for case in plan.case_set.cases for trial in range(1, trial_count + 1)
    ]
    actual = [(row["caseId"], row["trial"]) for row in cast(list[JSONObject], normalized["trials"])]
    if actual != expected:
        raise Error("evidence.trials", "trials must exactly follow current case order")
    return normalized, passed


def evaluation_document(document: JSONObject, plan: EvaluationPlan) -> bytes:
    normalized, _ = validate_evaluation(document, plan)
    return render(
        "evaluation",
        {key: value for key, value in normalized.items() if key not in {"schema", "kind"}},
    )


def evaluation_status(document: JSONObject, plan: EvaluationPlan) -> tuple[bool, bool, str]:
    normalized, passed = validate_evaluation(document, plan)
    return True, passed, profile_key(report_profile(normalized))
