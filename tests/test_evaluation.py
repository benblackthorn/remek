import copy
import hashlib
import json

import pytest
from helpers import completed_evaluation
from remek_core.contract import SCHEMA, parse_document
from remek_core.evaluation import (
    EvaluationPlan,
    evaluation_document,
    evaluation_status,
    parse_case_set,
    report_profile,
    routing_catalog_digest,
    validate_evaluation,
    validate_evaluation_intrinsic,
)
from remek_core.model import RemekError


def cases(kind="routing"):
    values = (
        [
            {"id": "yes", "prompt": "deploy safely", "shouldActivate": True},
            {"id": "no", "prompt": "write a poem", "shouldActivate": False},
        ]
        if kind == "routing"
        else [{"id": "run", "prompt": "run it", "expectations": ["safe output", "no mutation"]}]
    )
    return parse_case_set({"schema": SCHEMA, "kind": f"{kind}-cases", "cases": values}, kind)


def evidence_plan(kind="routing"):
    return EvaluationPlan(
        "deploy-safely",
        "a" * 64,
        cases(kind),
        "b" * 64 if kind == "routing" else None,
        "org-private" if kind == "routing" else None,
    )


def test_case_and_catalog_identities_bind_order_and_descriptions():
    assert cases().digest != cases("behavior").digest
    catalog = (("a", "first"), ("b", "second"))
    assert routing_catalog_digest(catalog) != routing_catalog_digest(
        (("a", "first"), ("b", "changed"))
    )
    document = json.loads(cases().render())
    document["cases"].reverse()
    assert parse_case_set(document, "routing").digest != cases().digest


@pytest.mark.parametrize(
    "key", ["candidate", "caseSetDigest", "routingCatalogDigest", "distribution"]
)
def test_stale_binding_refuses_without_reclassifying_history(key):
    plan = evidence_plan()
    document = completed_evaluation(plan.template())
    document[key] = "c" * 64 if key != "distribution" else "other"
    assert validate_evaluation_intrinsic(document)[1]
    with pytest.raises(RemekError, match="current bound inputs"):
        validate_evaluation(document, plan)


def test_failed_and_error_trials_are_retained_with_derived_counts():
    plan = evidence_plan()
    document = completed_evaluation(plan.template())
    document["trials"][0].update(outcome="error", observation="Synthetic host unavailable.")
    encoded = evaluation_document(document, plan)
    recorded = parse_document(encoded, kind="evaluation")
    assert recorded == document
    assert evaluation_status(recorded, plan)[:2] == (True, False)
    recorded["profile"]["minimumPassCount"] = 2
    assert validate_evaluation(recorded, plan)[1]
    recorded["trials"][1]["outcome"] = "fail"
    assert not validate_evaluation(recorded, plan)[1]


def test_report_retains_actual_configuration_and_changes_identity():
    plan = evidence_plan("behavior")
    document = completed_evaluation(plan.template())
    data = evaluation_document(document, plan)
    assert data == evaluation_document(copy.deepcopy(document), plan)
    actual = report_profile(document)
    assert (
        actual["runConfigDigest"]
        == hashlib.sha256(document["runConfiguration"].encode()).hexdigest()
    )
    document["runConfiguration"] += " Host temperature: 0.1."
    assert evaluation_document(document, plan) != data
    assert report_profile(document)["runConfigDigest"] != actual["runConfigDigest"]
    document["profile"]["runConfigDigest"] = actual["runConfigDigest"]
    with pytest.raises(RemekError, match="computed configuration digest"):
        validate_evaluation(document, plan)


def test_templates_require_actual_reported_observations():
    plan = evidence_plan()
    template = plan.template()
    assert {row["outcome"] for row in template["trials"]} == {"unreported"}
    assert template["runConfiguration"] == "" and template["profile"]["name"] == ""
    with pytest.raises(RemekError):
        evaluation_document(template, plan)
    for invalid in ("", "   ", "TODO", "<actual observed behavior>"):
        document = completed_evaluation(plan.template())
        document["trials"][0]["observation"] = invalid
        with pytest.raises(RemekError):
            evaluation_document(document, plan)


def test_trial_grid_refuses_omissions_duplicates_boolean_and_aggregate_overrides():
    baseline = completed_evaluation(evidence_plan().template())
    invalid = []
    for field, value in (
        ("trial", True),
        ("trial", 4),
        ("outcome", "unreported"),
        ("passCount", 3),
    ):
        document = copy.deepcopy(baseline)
        document["trials"][0][field] = value
        invalid.append(document)
    missing = copy.deepcopy(baseline)
    missing["trials"].pop()
    invalid.append(missing)
    duplicate = copy.deepcopy(baseline)
    duplicate["trials"][1] = duplicate["trials"][0]
    invalid.append(duplicate)
    extra = copy.deepcopy(baseline)
    extra["passed"] = True
    invalid.append(extra)
    for document in invalid:
        with pytest.raises(RemekError):
            validate_evaluation_intrinsic(document)


def test_intrinsic_history_and_current_case_order_are_distinct():
    plan = evidence_plan()
    document = completed_evaluation(plan.template())
    document["trials"] = document["trials"][3:] + document["trials"][:3]
    assert validate_evaluation_intrinsic(document)[1]
    with pytest.raises(RemekError, match="current case order"):
        validate_evaluation(document, plan)
    document["trials"] = document["trials"][:3]
    assert validate_evaluation_intrinsic(document)[1]
    with pytest.raises(RemekError, match="current case order"):
        validate_evaluation(document, plan)


def test_optional_artifacts_are_only_unique_digest_references():
    plan = evidence_plan()
    document = completed_evaluation(plan.template())
    del document["artifacts"]
    assert validate_evaluation(document, plan)[1]
    document["artifacts"] = [{"label": "transcript", "digest": "d" * 64}]
    assert validate_evaluation(document, plan)[1]
    document["artifacts"].append({"label": "transcript", "digest": "e" * 64})
    with pytest.raises(RemekError, match="unique"):
        validate_evaluation(document, plan)
    document["artifacts"] = [{"label": "transcript", "digest": "bad"}]
    with pytest.raises(RemekError, match="sha256"):
        validate_evaluation(document, plan)


def test_profile_and_case_types_remain_strict():
    document = completed_evaluation(evidence_plan().template())
    for kind in ("manual-host", "test-suite", "external"):
        document["profile"]["kind"] = kind
        assert validate_evaluation_intrinsic(document)[1]
    for field, value in (("trialCount", True), ("minimumPassCount", 4), ("kind", {})):
        changed = copy.deepcopy(document)
        changed["profile"][field] = value
        with pytest.raises(RemekError):
            validate_evaluation_intrinsic(changed)
    behavior = json.loads(cases("behavior").render())
    behavior["cases"][0]["expectations"] *= 2
    with pytest.raises(RemekError, match="unique expectations"):
        parse_case_set(behavior, "behavior")
    routing = json.loads(cases().render())
    routing["cases"].pop()
    with pytest.raises(RemekError, match="positive and contrastive"):
        parse_case_set(routing, "routing")
    routing["cases"] = []
    assert parse_case_set(routing, "routing").cases == ()


def test_large_report_keeps_every_observation_with_explicit_bounds():
    case_set = parse_case_set(
        {
            "schema": SCHEMA,
            "kind": "behavior-cases",
            "cases": [
                {
                    "id": f"case-{index}",
                    "prompt": f"Check behavior {index}.",
                    "expectations": ["Observed expected result."],
                }
                for index in range(50)
            ],
        },
        "behavior",
    )
    plan = EvaluationPlan("deploy-safely", "a" * 64, case_set, None)
    document = completed_evaluation(plan.template())
    document["profile"].update(trialCount=10, minimumPassCount=10)
    document["trials"] = [
        {"caseId": case.case_id, "trial": trial, "outcome": "pass", "observation": "x" * 500}
        for case in case_set.cases
        for trial in range(1, 11)
    ]
    data = evaluation_document(document, plan)
    assert 65536 < len(data) < 512 << 10
    assert parse_document(data, kind="evaluation")["trials"] == document["trials"]
    document["runConfiguration"] = "é" * 8193
    with pytest.raises(RemekError, match="16 KiB"):
        evaluation_document(document, plan)
    document["runConfiguration"] = "actual settings"
    for row in document["trials"]:
        row["observation"] = "界" * 500
    with pytest.raises(RemekError, match=r"byte limit|bytes|size"):
        evaluation_document(document, plan)


def test_evaluation_value_budget_does_not_inherit_review_limit():
    document = completed_evaluation(evidence_plan().template())
    document["unexpected"] = [0] * 4096
    data = json.dumps(document).encode()
    with pytest.raises(RemekError, match="values"):
        parse_document(data, kind="evaluation")
