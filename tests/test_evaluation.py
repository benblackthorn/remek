import copy
import json
from pathlib import Path

import pytest
from remek_core.contract import parse_document, render_document
from remek_core.evaluation import (
    EvidencePlan,
    parse_case_set,
    parse_profile,
    profile_key,
    receipt_document,
    receipt_status,
    routing_catalog_digest,
    validate_evidence,
    validate_evidence_intrinsic,
)
from remek_core.model import RemekError


def cases(kind="routing"):
    if kind == "routing":
        document = parse_document(
            render_document(
                "routing-cases",
                {
                    "cases": [
                        {"id": "yes", "prompt": "deploy safely", "shouldActivate": True},
                        {"id": "no", "prompt": "write a poem", "shouldActivate": False},
                    ]
                },
            ),
            kind="routing-cases",
        )
    else:
        document = parse_document(
            render_document(
                "behavior-cases",
                {
                    "cases": [
                        {
                            "id": "run",
                            "prompt": "run it",
                            "expectations": ["safe output", "no unrelated mutation"],
                        }
                    ]
                },
            ),
            kind="behavior-cases",
        )
    return parse_case_set(document, kind)


def evidence_plan(kind="routing"):
    return EvidencePlan(
        "deploy-safely",
        "a" * 64,
        cases(kind),
        "b" * 64 if kind == "routing" else None,
        "org-private" if kind == "routing" else None,
    )


def completed(plan):
    document = plan.template()
    document["profile"] = {
        "kind": "manual-host",
        "name": "claude",
        "version": "1",
        "claim": "regression",
        "runConfigDigest": "c" * 64,
        "trialCount": 3,
        "minimumPassCount": 3,
    }
    for result in document["results"]:
        result["passCount"] = 3
    document["artifacts"] = [{"label": "evaluation-report", "digest": "d" * 64}]
    return document


def test_case_digests_are_canonical_and_kind_specific():
    assert cases().digest != cases("behavior").digest


def test_routing_catalog_ignores_implementation_bytes():
    catalog = (("a", "first"), ("b", "second"))
    assert routing_catalog_digest(catalog) != routing_catalog_digest(
        ((*catalog[0],), ("b", "changed"))
    )


@pytest.mark.parametrize("kind", ["manual-host", "test-suite", "external"])
def test_profiles_round_trip(kind):
    parsed = parse_profile(
        {
            "kind": kind,
            "name": "profile",
            "version": "1",
            "claim": "comparative",
            "runConfigDigest": "c" * 64,
            "trialCount": 3,
            "minimumPassCount": 2,
        }
    )
    assert parsed["kind"] == kind and len(profile_key(parsed)) == 64


@pytest.mark.parametrize(
    "key", ["candidate", "caseSetDigest", "routingCatalogDigest", "distribution"]
)
def test_stale_binding_refuses(key):
    plan = evidence_plan()
    document = completed(plan)
    document[key] = "c" * 64 if key != "distribution" else "other"
    with pytest.raises(RemekError, match="current bound inputs"):
        validate_evidence(document, plan)


def test_failed_evidence_is_recordable_but_not_passing():
    plan = evidence_plan()
    document = completed(plan)
    document["results"][0]["passCount"] = 2
    receipt = parse_document(receipt_document(document, plan), kind="eval-receipt")
    current, passed, _ = receipt_status(receipt, plan)
    assert current and not passed


def test_identical_receipt_is_content_identical():
    plan = evidence_plan("behavior")
    document = completed(plan)
    assert receipt_document(document, plan) == receipt_document(copy.deepcopy(document), plan)


def test_result_order_and_artifact_digest_are_strict():
    plan = evidence_plan()
    document = completed(plan)
    document["results"].reverse()
    with pytest.raises(RemekError, match="case order"):
        validate_evidence(document, plan)
    document = completed(plan)
    document["artifacts"] = [{"label": "evaluation-report", "digest": "bad"}]
    with pytest.raises(RemekError, match="sha256"):
        validate_evidence(document, plan)


def test_receipt_keeps_trial_details_in_external_report():
    plan = evidence_plan()
    document = completed(plan)
    document["results"][0]["observed"] = "raw detail"
    with pytest.raises(RemekError, match="case order"):
        validate_evidence(document, plan)


def test_intrinsic_evidence_rejects_invalid_results_artifacts_and_keys():
    plan = evidence_plan()
    baseline = completed(plan)
    invalid = []
    extra = copy.deepcopy(baseline)
    extra["unexpected"] = True
    invalid.append(extra)
    repeated = copy.deepcopy(baseline)
    repeated["results"][1]["caseId"] = repeated["results"][0]["caseId"]
    invalid.append(repeated)
    overflow = copy.deepcopy(baseline)
    overflow["results"][0]["passCount"] = 4
    invalid.append(overflow)
    artifacts = copy.deepcopy(baseline)
    artifacts["artifacts"] = [
        {"label": "evaluation-report", "digest": "d" * 64},
        {"label": "evaluation-report", "digest": "e" * 64},
    ]
    invalid.append(artifacts)

    for document in invalid:
        with pytest.raises(RemekError):
            validate_evidence_intrinsic(document)


def test_contextual_evidence_distinguishes_order_stale_failed_and_current():
    plan = evidence_plan()
    current = completed(plan)
    assert validate_evidence(current, plan)[1] is True

    failed = copy.deepcopy(current)
    failed["results"][0]["passCount"] = 0
    assert validate_evidence(failed, plan)[1] is False

    reordered = copy.deepcopy(current)
    reordered["results"].reverse()
    assert validate_evidence_intrinsic(reordered)[1] is True
    with pytest.raises(RemekError, match="case order"):
        validate_evidence(reordered, plan)

    truncated = copy.deepcopy(current)
    truncated["results"].pop()
    assert validate_evidence_intrinsic(truncated)[1] is True
    with pytest.raises(RemekError, match="result count differs"):
        validate_evidence(truncated, plan)

    stale = copy.deepcopy(current)
    stale["candidate"] = "0" * 64
    with pytest.raises(RemekError, match="bound inputs differ"):
        validate_evidence(stale, plan)


def test_profile_rigor_and_report_are_required():
    plan = evidence_plan()
    document = completed(plan)
    document["profile"]["minimumPassCount"] = 4
    with pytest.raises(RemekError, match="unsupported evaluator profile"):
        validate_evidence(document, plan)
    document = completed(plan)
    document["artifacts"] = [{"label": "trace", "digest": "d" * 64}]
    with pytest.raises(RemekError, match="evaluation-report"):
        validate_evidence(document, plan)


def test_behavior_cases_require_specific_unique_expectations():
    document = parse_document(
        render_document(
            "behavior-cases",
            {
                "cases": [
                    {
                        "id": "run",
                        "prompt": "run it",
                        "expectations": ["safe output", "safe output"],
                    }
                ]
            },
        ),
        kind="behavior-cases",
    )
    with pytest.raises(RemekError, match="unique expectations"):
        parse_case_set(document, "behavior")


def test_routing_requires_positive_and_contrastive_cases():
    document = parse_document(
        render_document(
            "routing-cases",
            {"cases": [{"id": "yes", "prompt": "always", "shouldActivate": True}]},
        ),
        kind="routing-cases",
    )
    with pytest.raises(RemekError, match="positive and contrastive"):
        parse_case_set(document, "routing")


def test_packaged_routing_evals_match_governed_cases():
    root = Path(__file__).parents[1]
    governed = json.loads((root / ".remek/skills/remek/routing-cases.json").read_text())
    packaged = json.loads((root / "skills/remek/evals/evals.json").read_text())
    assert [(item["prompt"], item["shouldActivate"]) for item in governed["cases"]] == [
        (item["prompt"], item["shouldTrigger"]) for item in packaged["cases"]
    ]
