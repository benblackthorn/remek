# ruff: noqa: D103, I001
"""Command interface."""

import argparse
import json
import os
import shlex
import sys
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn, cast, get_args

from .contract import SCHEMA, JSONObject, load_document, parse_document, render_document as render
from .filesystem import (
    checked_path,
    checked_root as checked,
    entry_exists as exists,
    write_artifact,
)
from .model import Error, Finding, MutationOutcome, Result, Status, safe_text
from .plans import (
    MAX_DIFF_BYTES,
    Plan,
    load_operation_plan,
    operation_document,
    plan_diff,
    reconstruct_plan,
    validate_output_path,
    verify_operation_plan,
)
from .repository import (
    DisclosurePolicy,
    audit_repository,
    evaluation_plan,
    inspect_repository as inspect,
    parse_disclosure,
    redact_credential_text,
    repository_findings as check,
)
from .review import release_findings, review_status, review_summary, review_template
from .transaction import apply_changes
from .workflows import (
    eval_record_plan,
    review_record_plan,
    init_plan,
    release_plan,
    release_verify,
    update_plan,
    verify_materialized_release,
)

MAX_RENDERED_BYTES = 1024 * 1024
_MAX_FALLBACK_BYTES = 1024 * 1024


def _next_command(bundle: Path, root: Path | None, *arguments: str) -> str:
    fallback = bundle.parent / "scripts/cli.py"
    bootstrap = Path(os.environ.get("REMEK_BOOTSTRAP", str(fallback))).expanduser().absolute()
    command = (
        [str(bootstrap)]
        if bootstrap.name == "remek"
        else ["python3", "-I", "-S", "-B", str(bootstrap)]
    )
    if root is not None:
        command.extend(("--root", str(root)))
    return shlex.join([*command, *arguments])


class _Parser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> NoReturn:
        if "argument command: invalid choice" in message:
            message += (
                "; use --help for v2 commands and ordinary file/Git authoring; "
                "v1 sources require the producer tools/migrate_v1.py rehearsal"
            )
        raise Error("cli.arguments", message)


def _output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path, help="save the exact operation plan")


def _parser() -> _Parser:
    parser = _Parser(
        prog="remek",
        description=(
            "Govern and release owned Agent Skills. Put --root and --json before the command."
        ),
    )
    parser.add_argument("--root", type=Path, help="governed source root; default current directory")
    parser.add_argument("--json", action="store_true", help="emit one canonical JSON result")
    parser.add_argument("--version", action="version", version="remek 2.0.0")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="initialize a governed source")
    init.add_argument("target", type=Path)
    init.add_argument("--project", action="store_true", help="govern .agents/skills")
    _output(init)
    check_parser = commands.add_parser(
        "check", help="check source and optional distribution readiness"
    )
    check_parser.add_argument("--distribution")
    for name, help_text in (
        ("audit", "inspect an untrusted payload"),
        ("verify", "verify a materialized artifact"),
    ):
        commands.add_parser(name, help=help_text).add_argument("target", type=Path)
    evaluation = commands.add_parser("eval", help="prepare or record offline observations")
    actions = evaluation.add_subparsers(dest="eval_action", required=True)
    item = actions.add_parser("plan")
    item.add_argument("skill")
    item.add_argument("--kind", required=True, choices=("routing", "behavior"))
    item.add_argument("--distribution")
    item = actions.add_parser("record")
    item.add_argument("skill")
    item.add_argument("--from", dest="evidence", type=Path, required=True)
    _output(item)
    review = commands.add_parser("review", help="prepare or record a complete distribution review")
    actions = review.add_subparsers(dest="review_action", required=True)
    for action in ("plan", "record"):
        item = actions.add_parser(action)
        item.add_argument("distribution")
        if action == "record":
            item.add_argument("--from", dest="review", type=Path, required=True)
            _output(item)
    release = commands.add_parser("release", help="plan or verify an exact release")
    actions = release.add_subparsers(dest="release_action", required=True)
    item = actions.add_parser("plan")
    item.add_argument("distribution")
    destination = item.add_mutually_exclusive_group(required=True)
    destination.add_argument("--mirror", type=Path)
    destination.add_argument("--staging", type=Path)
    item.add_argument("--adopt-existing", action="store_true")
    _output(item)
    item = actions.add_parser("verify")
    item.add_argument("distribution")
    item.add_argument("--mirror", type=Path, required=True)
    show = commands.add_parser("show", help="reconstruct and inspect an exact saved plan")
    show.add_argument("plan", type=Path)
    show.add_argument(
        "--max-bytes", type=int, default=MAX_DIFF_BYTES, help="only lower the 768 KiB diff ceiling"
    )
    commands.add_parser("apply", help="apply an exact saved plan").add_argument("plan", type=Path)
    _output(commands.add_parser("update", help="replace the embedded trusted toolchain"))
    return parser


def _plan_data(plan: Plan, document: JSONObject, artifact: str | None) -> dict[str, object]:
    return {
        **plan.data,
        "root": str(plan.root),
        "planDigest": document["planDigest"],
        "planOutput": artifact,
        "bundleIdentity": document["bundleIdentity"],
        "bindings": plan.bindings,
        "sources": [item.as_dict() for item in plan.sources],
    }


def _plan_result(plan: Plan, destination: Path | None, bundle: Path) -> Result:
    output, _digest = operation_document(plan, bundle)
    artifact = None
    if destination is not None and plan.changes:
        artifact = str(write_artifact(validate_output_path(destination, plan, bundle), output))
    data = _plan_data(plan, parse_document(output, kind="operation-plan"), artifact)
    if not plan.changes:
        return Result(plan.command, "ok", "already current; no plan file written", data=data)
    summary = (
        "exact plan saved; review it with show before apply"
        if artifact
        else "preview only; rerun with --output to save an applicable plan"
    )
    return Result(
        plan.command,
        "planned",
        summary,
        changes=plan.project(),
        data=data,
        next_action=(
            _next_command(
                bundle,
                None if plan.command == "init" else plan.root,
                "show",
                artifact,
            )
            if artifact
            else None
        ),
    )


def _findings_result(
    command: str, findings: tuple[Finding, ...], data: dict[str, object]
) -> Result:
    errors = sum(item.severity == "error" for item in findings)
    return Result(
        command,
        "issues" if errors else "ok",
        f"found {errors} blocking issue(s)" if errors else "check passed",
        findings=findings,
        data=data,
    )


def _assert_plan_root(selected: Path | None, root: Path) -> None:
    if selected is not None:
        absolute = selected.expanduser().absolute()
        canonical = (
            checked(absolute) if exists(absolute) else checked(absolute.parent) / absolute.name
        )
        if canonical != root:
            raise Error("plan.root", "root differs; use the saved plan root")


def _apply_result(arguments: argparse.Namespace, bundle: Path) -> Result:
    loaded = load_operation_plan(arguments.plan)
    _assert_plan_root(arguments.root, loaded.root)
    arguments.source_root = loaded.root
    plan = reconstruct_plan(loaded, bundle)
    digest = verify_operation_plan(loaded, plan, bundle)
    findings: tuple[Finding, ...] = ()

    def verify() -> None:
        nonlocal findings
        if plan.command == "release":
            destination = plan.inputs.get("mirror") or plan.inputs.get("staging")
            if not isinstance(destination, str):
                raise Error("apply.postcondition", "release destination is unavailable")
            verify_materialized_release(Path(destination))
            return
        inspection = inspect(plan.root)
        inspection = replace(
            inspection,
            issues=tuple(item for item in inspection.issues if item.code != "transaction.residue"),
        )
        findings = tuple(item for item in check(inspection) if item.code != "transaction.residue")
        if any(item.severity == "error" for item in findings):
            raise Error("apply.postcondition", "applied state failed repository checking")
        if plan.command == "review-record":
            distribution = cast(str, plan.inputs["distribution"])
            if (
                inspection.distribution(distribution).active_review != plan.data["reviewId"]
                or not review_status(inspection, distribution)[0]
            ):
                raise Error(
                    "apply.postcondition", "recorded review failed current-context checking"
                )

    identity = {
        **plan.data,
        "root": str(plan.root),
        "planDigest": digest,
        "operation": plan.command,
    }
    try:
        outcome = apply_changes(plan.changes, verify=verify)
    except Error as exc:
        return _error_result(arguments, "refused", exc, data=identity)
    if plan.command != "release":
        try:
            findings = check(inspect(plan.root))
        except (Exception, KeyboardInterrupt):
            return _error_result(
                arguments,
                "refused",
                Error(
                    "apply.final-check",
                    "applied changes but final inspection failed",
                    outcome=outcome.outcome,
                    changed_paths=outcome.changed_paths,
                ),
                data=identity,
            )
    errors = any(item.severity == "error" for item in findings)
    status: Status = "refused" if errors and outcome.changed else "issues" if errors else "ok"
    if errors and outcome.changed:
        summary = (
            "exact reviewed changes were applied; final state changed and blocking findings remain"
        )
    elif errors:
        summary = "final state is unchanged but blocking findings remain"
    elif outcome.changed:
        summary = f"applied {len(plan.changes)} exact reviewed change(s); final state changed"
    else:
        summary = "exact plan was already current; final state unchanged"
    return Result(
        "apply",
        status,
        summary,
        changed=outcome.changed,
        findings=findings,
        changes=plan.project(),
        data={
            **identity,
            "outcome": outcome.outcome,
            "changedPaths": list(outcome.changed_paths),
            "residue": [],
        },
    )


def _template_result(
    command: str,
    summary: str,
    template: JSONObject,
    *,
    next_action: str,
    **data: object,
) -> Result:
    return Result(
        command,
        "ok",
        summary,
        data={**data, "template": template},
        next_action=next_action,
    )


def _dispatch(  # noqa: PLR0911, PLR0912, PLR0915
    arguments: argparse.Namespace, bundle: Path
) -> Result:
    command = arguments.command
    if arguments.root is not None and command in {"init", "audit", "verify"}:
        raise Error("cli.arguments", f"{command} takes an explicit path and forbids --root")
    if command == "apply":
        return _apply_result(arguments, bundle)
    if command == "init":
        return _plan_result(
            init_plan(
                arguments.target,
                bundle,
                project=arguments.project,
            ),
            arguments.output,
            bundle,
        )
    root = (
        checked(arguments.root or Path.cwd())
        if command not in {"audit", "verify", "show"}
        else Path.cwd()
    )
    output = getattr(arguments, "output", None)

    def planned(value: Plan) -> Result:
        return _plan_result(value, output, bundle)

    if command == "check":
        inspection = inspect(root)
        distribution = arguments.distribution
        structural = check(inspection)
        findings = (
            release_findings(inspection, distribution) if distribution is not None else structural
        )
        _ready, review_state = (
            review_status(inspection, distribution) if distribution is not None else (None, None)
        )

        return _findings_result(
            "check",
            findings,
            {
                "root": str(root),
                "structuralValid": not any(item.severity == "error" for item in structural),
                "skills": [
                    {
                        "skill": item.name,
                        "candidateDigest": item.digest,
                        "exposure": item.record.exposure,
                    }
                    for item in inspection.skills
                ],
                "distribution": distribution,
                "releaseReady": (not any(item.severity == "error" for item in findings))
                if distribution is not None
                else None,
                "reviewStatus": review_state,
            },
        )
    if command == "eval":
        inspection = inspect(root)
        skill = arguments.skill
        if arguments.eval_action == "plan":
            blocking = next(
                (item for item in check(inspection) if item.severity == "error"),
                None,
            )
            if blocking:
                raise Error(
                    "eval.preflight",
                    f"repository check failed: {blocking.code}: {blocking.message}",
                )
            kind, distribution = arguments.kind, arguments.distribution
            evidence = evaluation_plan(inspection, skill, kind, distribution)
            selected = inspection.skill(skill)
            return _template_result(
                "eval plan",
                "offline evidence template prepared",
                evidence.template(),
                next_action=_next_command(
                    bundle,
                    root,
                    "eval",
                    "record",
                    skill,
                    "--from",
                    "/absolute/path/to/evidence.json",
                    "--output",
                    "/absolute/path/to/evidence-plan.json",
                ),
                candidate=selected.digest,
                routingCaseSetDigest=selected.routing_cases.digest,
                behaviorCaseSetDigest=selected.behavior_cases.digest,
                routingCatalogDigest=evidence.routing_catalog_digest,
                execution="not-performed",
            )
        return planned(eval_record_plan(root, skill, arguments.evidence))
    if command == "review":
        distribution = arguments.distribution
        if arguments.review_action == "plan":
            inspection = inspect(root)
            template = review_template(inspection, distribution)
            summary = review_summary(inspection, distribution)
            findings = release_findings(inspection, distribution)
            return Result(
                "review plan",
                "issues" if any(item.severity == "error" for item in findings) else "ok",
                "complete distribution review packet prepared; declarations require actual review",
                findings=findings,
                data={"template": template, "review": summary},
                next_action=_next_command(
                    bundle,
                    root,
                    "review",
                    "record",
                    distribution,
                    "--from",
                    "/absolute/path/to/review.json",
                    "--output",
                    "/absolute/path/to/review-plan.json",
                ),
            )
        return planned(review_record_plan(root, distribution, arguments.review))
    if command == "release":
        if arguments.release_action == "verify":
            return Result(
                "release verify",
                "ok",
                "artifact, source readiness, target, and commit lineage verified at this time",
                data=release_verify(root, arguments.distribution, arguments.mirror),
            )
        return planned(
            release_plan(
                root,
                arguments.distribution,
                mirror=arguments.mirror,
                staging=arguments.staging,
                adopt=arguments.adopt_existing,
            )
        )
    if command == "verify":
        manifest = verify_materialized_release(arguments.target)
        return Result(
            "verify",
            "ok",
            "materialized artifact matches its declared inventory",
            data={
                "artifactVerified": True,
                "reviewDigest": manifest["reviewDigest"],
                "releaseId": manifest["releaseId"],
                "sourceReadinessVerified": False,
                "targetVerified": False,
                "publicationPerformed": False,
            },
        )
    if command == "show":
        loaded = load_operation_plan(arguments.plan)
        _assert_plan_root(arguments.root, loaded.root)
        arguments.source_root = loaded.root
        plan = reconstruct_plan(loaded, bundle)
        verify_operation_plan(loaded, plan, bundle)
        max_bytes = arguments.max_bytes
        if arguments.json:
            max_bytes = min(max_bytes, MAX_RENDERED_BYTES // 3)
        diff = plan_diff(plan, max_bytes=max_bytes)
        return Result(
            "show",
            "ok",
            f"exact plan reconstructed; {len(plan.changes)} change(s) and content diff follow",
            changes=plan.project(),
            data={
                **_plan_data(plan, loaded.document, str(arguments.plan.expanduser().absolute())),
                "diff": diff,
            },
        )
    if command == "audit":
        target = checked(arguments.target)
        findings = audit_repository(target)
        error_count = sum(item.severity == "error" for item in findings)
        return Result(
            "audit",
            "issues" if error_count else "ok",
            (
                f"audited {target}; found {error_count} structural blocker(s)"
                if error_count
                else f"audited {target}; payload is structurally compatible"
            ),
            findings=findings,
            data={"target": str(target), "profile": "remek-text", "supported": not error_count},
        )
    if command == "update":
        return planned(update_plan(root, bundle))
    raise Error("cli.command", f"unsupported command: {command}")


def _error_result(
    arguments: argparse.Namespace | None,
    status: Status,
    error: Error,
    *,
    data: dict[str, object] | None = None,
) -> Result:
    command = cast(str, arguments.command) if arguments is not None else "remek"
    return Result(
        command,
        status,
        error.message,
        changed=error.changed,
        findings=(Finding(error.code, "error", error.message),),
        exit_override=error.exit_code,
        data={
            **(data or {}),
            "outcome": error.outcome,
            "changedPaths": list(error.changed_paths),
            "residue": list(error.residue),
        },
    )


def _diagnostic_policy(arguments: argparse.Namespace | None) -> DisclosurePolicy | None:
    if arguments is None:
        return None
    root = getattr(arguments, "source_root", arguments.root or Path.cwd())
    if arguments.command in {"init", "audit", "verify"}:
        root = getattr(arguments, "target", root)
    try:
        root = checked(root)
        return parse_disclosure(
            load_document(
                checked_path(root, root / ".remek/disclosure-policy.json"), kind="disclosure-policy"
            )
        )
    except (Error, OSError):
        return None


def _redacted_result(result: Result, policy: DisclosurePolicy | None) -> Result:
    # Redact only the output projection; canonical records and saved plans retain their bytes.
    def visible(value: object, path: tuple[str, ...] = ()) -> Any:
        if isinstance(value, str):
            match path, value:
                case ("outcome",), _ if value in get_args(MutationOutcome):
                    return value
                case (
                    (
                        ("operation",),
                        "init" | "eval-record" | "review-record" | "release" | "update",
                    )
                    | (("mode",), "managed" | "staging")
                    | (("reviewStatus",), "missing" | "invalid" | "stale" | "current")
                    | (("execution",), "not-performed")
                    | (("profile",), "remek-text")
                    | (("template", "schema"), "remek.2")
                    | (("template", "kind"), "evaluation" | "release-review")
                    | (("template", "evidenceKind"), "routing" | "behavior")
                    | (("template", "profile", "kind"), "manual-host")
                    | (("template", "profile", "claim"), "regression")
                    | (("template", "trials", "[]", "outcome"), "unreported")
                    | (("review", "blockingFindings", "[]", "code"), _)
                ):
                    return value
            return redact_credential_text(value, policy)
        if isinstance(value, dict):
            projected = {}
            for key, item in value.items():
                label = visible(key) if path == ("bindings", "source") else key
                if label in projected:
                    raise Error(
                        "output.redaction", "redaction would merge distinct source bindings"
                    )
                projected[label] = visible(item, (*path, key))
            return projected
        if isinstance(value, (list, tuple)):
            return [visible(item, (*path, "[]")) for item in value]
        return value

    return replace(
        result,
        summary=visible(result.summary),
        findings=tuple(
            replace(item, message=visible(item.message), path=visible(item.path))
            for item in result.findings
        ),
        changes=tuple(
            replace(
                item,
                path=visible(item.path),
                before=visible(item.before),
                after=visible(item.after),
                reason=visible(item.reason),
            )
            for item in result.changes
        ),
        data=visible(result.data),
        next_action=visible(result.next_action),
    )


def _render(result: Result, *, json_mode: bool) -> str:
    if json_mode:
        projection = result.as_dict()
        fields = {key: value for key, value in projection.items() if key not in {"schema", "kind"}}
        output = render("command-result", cast(JSONObject, fields)).decode()
    else:
        lines = [f"{safe_text(result.command)}: {safe_text(result.summary)}"]
        for key, label in (
            ("root", "root"),
            ("planDigest", "plan digest"),
            ("planOutput", "plan file"),
            ("releaseId", "release id"),
        ):
            value = result.data.get(key)
            if value is not None:
                lines.append(f"  {label}: {safe_text(value)}")
        for key in ("template", "review"):
            value = result.data.get(key)
            if isinstance(value, dict):
                lines.append(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2))
        for change in result.changes:
            lines.append(
                f"  {safe_text(change.action)} {safe_text(change.path)}: "
                f"{safe_text(change.before)} -> {safe_text(change.after)}"
            )
        diff = result.data.get("diff")
        if isinstance(diff, str):
            lines.extend(["", diff.rstrip("\n")])
        for finding in result.findings:
            path = f" {safe_text(finding.path)}" if finding.path else ""
            lines.append(
                f"  {finding.severity.upper()} {safe_text(finding.code)}{path}: "
                f"{safe_text(finding.message)}"
            )
        if result.next_action:
            lines.append(f"  next: {safe_text(result.next_action)}")
        output = "\n".join(lines) + "\n"
    if len(output.encode()) > MAX_RENDERED_BYTES:
        raise Error("output.limit", f"command output exceeds {MAX_RENDERED_BYTES} bytes")
    return output


def _output_failure(
    result: Result, *, json_mode: bool, policy: DisclosurePolicy | None = None
) -> tuple[Result, str]:
    outcome = result.data.get("outcome", "unknown" if result.changed else "unchanged")
    if not isinstance(outcome, str) or outcome not in get_args(MutationOutcome):
        outcome = "unknown" if result.changed else "unchanged"
    changed = result.changed or outcome in {"applied", "residue", "unknown"}
    data: dict[str, object] = {
        key: result.data[key]
        for key in (
            "operation",
            "root",
            "planDigest",
            "planOutput",
            "bundleIdentity",
            "reportId",
            "reviewId",
            "contextDigest",
            "releaseId",
            "distribution",
            "mode",
        )
        if key in result.data and isinstance(result.data[key], (str, bool, type(None)))
    }
    data.update(
        outcome=outcome,
        changedPaths=result.data.get("changedPaths", []),
        residue=result.data.get("residue", []),
    )
    failed = Result(
        result.command,
        "failed",
        "command output failed; inspect the recorded mutation outcome",
        changed=changed,
        exit_override=3 if changed else 2,
        findings=(
            Finding("output.invalid", "error", "normal command output could not be delivered"),
        ),
        data=data,
    )
    # Bound independently; do not retry the normal renderer or truncate review packets.
    try:
        failed = _redacted_result(failed, policy)
        data = failed.data

        def encode(value: Result) -> str:
            return (
                json.dumps(
                    value.as_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
                )
                if json_mode
                else f"output.invalid: {safe_text(value.command)}; "
                + json.dumps(value.data, ensure_ascii=True)
            ) + "\n"

        output = encode(failed)
        if len(output.encode()) > _MAX_FALLBACK_BYTES:
            omitted = {
                key: len(value)
                for key, value in data.items()
                if key in {"changedPaths", "residue"} and isinstance(value, (list, tuple))
            }
            data = {
                key: value for key, value in data.items() if key not in {"changedPaths", "residue"}
            }
            data.update(changedPaths=[], residue=[], outputTruncated=True, omittedEntries=omitted)
            failed = replace(
                failed,
                data=data,
                summary=(
                    "output identifiers exceed the fallback limit; "
                    "omitted entries require filesystem inspection"
                ),
            )
            output = encode(failed)
            if len(output.encode()) > _MAX_FALLBACK_BYTES:
                failed = replace(
                    failed,
                    command="remek",
                    data={
                        "outcome": outcome,
                        "changedPaths": [],
                        "residue": [],
                        "outputTruncated": True,
                        "identityFieldsOmitted": True,
                    },
                )
                output = encode(failed)
        return failed, output
    except (Exception, KeyboardInterrupt):
        # Even a failed fallback encoder cannot erase a known transaction outcome.
        output = (
            (
                f'{{"schema":"{SCHEMA}","kind":"command-result","command":"remek",'
                f'"status":"failed","changed":{str(changed).lower()},'
                '"summary":"fallback encoder failed; outcome identifiers unavailable",'
                '"findings":[{"code":"output.invalid","severity":"error",'
                '"message":"fallback encoder failed","path":null,"repairable":false}],'
                f'"changes":[],"data":{{"outcome":"{outcome}","identityFieldsOmitted":true}},'
                f'"nextAction":null,"exitCode":{failed.exit_code}}}\n'
            )
            if json_mode
            else (
                f"output.invalid: outcome={outcome}; changed={str(changed).lower()}; "
                f"exitCode={failed.exit_code}; outcome identifiers could not be rendered\n"
            )
        )
        return failed, output


def main(argv: list[str] | None = None, *, bundle: Path) -> int:
    raw = sys.argv[1:] if argv is None else argv
    stop = raw.index("--") if "--" in raw else len(raw)
    json_mode = "--json" in raw[:stop]
    arguments: argparse.Namespace | None = None
    try:
        selected_toolchain = checked(bundle)
        arguments = argparse.Namespace(root=None, command="remek")
        _parser().parse_args(raw, namespace=arguments)
        result = _dispatch(arguments, selected_toolchain)
    except SystemExit as exc:
        return int(exc.code or 0)
    except KeyboardInterrupt:
        result = _error_result(
            arguments,
            "failed",
            Error("operation.interrupted", "operation interrupted", exit_code=130),
        )
    except Error as exc:
        result = _error_result(arguments, "refused", exc)
    except Exception:
        result = _error_result(
            arguments,
            "failed",
            Error("internal.error", "unexpected internal failure", exit_code=70),
        )
    policy = None
    try:
        policy = _diagnostic_policy(arguments)
        result = _redacted_result(result, policy)
        output = _render(result, json_mode=json_mode)
    except (Exception, KeyboardInterrupt):
        result, output = _output_failure(result, json_mode=json_mode, policy=policy)
    stream = sys.stderr if result.status in {"failed", "refused"} and not json_mode else sys.stdout
    try:
        stream.write(output)
        stream.flush()
    except (OSError, UnicodeError, KeyboardInterrupt):
        result, output = _output_failure(result, json_mode=json_mode, policy=policy)
        with suppress(OSError, UnicodeError, KeyboardInterrupt):
            stream.close()
        if stream is not sys.stderr:
            try:
                sys.stderr.write(output)
                sys.stderr.flush()
            except (OSError, UnicodeError, KeyboardInterrupt):
                with suppress(OSError, UnicodeError, KeyboardInterrupt):
                    sys.stderr.close()
    return result.exit_code
