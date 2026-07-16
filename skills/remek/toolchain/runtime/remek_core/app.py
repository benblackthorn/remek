# ruff: noqa: D103, I001
"""Command interface."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, NoReturn, cast

from .contract import JSONObject, parse_document, render_document as render
from .filesystem import checked_root as checked, entry_exists as exists, write_artifact
from .model import Error, Finding, Result, Status, safe_text
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
    approval_template,
    audit_repository,
    evaluation_plan,
    inspect_repository as inspect,
    repository_findings as check,
    release_findings,
)
from .transaction import apply_changes
from .workflows import (
    accept_plan,
    approve_record_plan,
    disclosure_accept_plan,
    distribution_accept_plan,
    eval_record_plan,
    init_plan,
    release_plan,
    release_verify,
    remove_plan,
    repair_plan,
    retire_plan,
    scaffold_workspace,
    update_plan,
    verify_materialized_release,
)

MAX_RENDERED_BYTES = 1024 * 1024


class _Parser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> NoReturn:
        raise Error("cli.arguments", message)


def _output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path, help="save the exact operation plan")


def _parser() -> _Parser:  # noqa: PLR0915
    parser = _Parser(
        prog="remek",
        description=(
            "Govern and release owned Agent Skills. Put --root and --json before the command."
        ),
    )
    parser.add_argument("--root", type=Path, help="governed source root; default current directory")
    parser.add_argument("--json", action="store_true", help="emit one canonical JSON result")
    parser.add_argument("--version", action="version", version="remek 1.0.1")
    commands = parser.add_subparsers(dest="command", required=True)

    def command(name: str, help_text: str) -> argparse.ArgumentParser:
        return commands.add_parser(name, help=help_text)

    init = command("init", "initialize or wire a governed source")
    init.add_argument("target", type=Path)
    init.add_argument("--project", action="store_true", help="govern .agents/skills")
    _output(init)

    scaffold = command("scaffold", "create a disposable authoring workspace")
    selection = scaffold.add_mutually_exclusive_group(required=True)
    selection.add_argument("--name", help="new skill name")
    selection.add_argument("--skill", help="governed skill to revise")
    scaffold.add_argument("--origin", choices=("captured", "designed", "imported"))
    scaffold.add_argument("--source", type=Path, help="completed work, design, or reviewed skill")
    scaffold.add_argument(
        "--workspace", type=Path, required=True, help="absent path outside the source and Git"
    )

    accept = command("accept", "plan acceptance of a complete workspace")
    accept.add_argument("--workspace", type=Path, required=True)
    _output(accept)

    for name, help_text in (
        ("distribution", "govern distribution definitions"),
        ("disclosure", "govern repository disclosure policy"),
    ):
        owner = command(name, help_text)
        accept = owner.add_subparsers(dest=f"{name}_action", required=True).add_parser("accept")
        accept.add_argument("--from", dest="source", type=Path, required=True)
        _output(accept)

    retire = command("retire", "retire a skill while retaining history")
    retire.add_argument("skill")
    retire.add_argument("--reason", required=True)
    _output(retire)
    remove = command("remove", "remove an unselected skill and its record")
    remove.add_argument("skill")
    _output(remove)

    check = command("check", "run deterministic offline contracts")
    check.add_argument("--release", metavar="DISTRIBUTION")
    for name, help_text in (
        ("repair", "plan safe mechanical corrections"),
        ("update", "replace the embedded trusted toolchain"),
    ):
        _output(command(name, help_text))

    eval_command = command("eval", "prepare or record offline evidence")
    eval_actions = eval_command.add_subparsers(dest="eval_action", required=True)
    eval_plan_parser = eval_actions.add_parser("plan")
    eval_plan_parser.add_argument("skill")
    eval_plan_parser.add_argument("--distribution")
    eval_plan_parser.add_argument("--kind", choices=("routing", "behavior"), default="routing")
    eval_record = eval_actions.add_parser("record")
    eval_record.add_argument("skill")
    eval_record.add_argument("--from", dest="evidence", type=Path, required=True)
    _output(eval_record)

    approve = command("approve", "prepare or record release approval")
    approve_actions = approve.add_subparsers(dest="approve_action", required=True)
    for action in ("plan", "record"):
        item = approve_actions.add_parser(action)
        item.add_argument("distribution")
        item.add_argument("--skill", required=True)
        if action == "record":
            item.add_argument("--from", dest="approval", type=Path, required=True)
            _output(item)

    release = commands.add_parser(
        "release",
        help="plan or verify one exact release",
        usage=(
            "remek release DIST (--mirror ABS | --staging-only ABS)\n"
            "       remek release verify DIST --mirror ABS"
        ),
    )
    release.add_argument(
        "distribution", metavar="DIST", help="distribution id; use 'verify DIST' to verify"
    )
    release.add_argument("verify_distribution", nargs="?", help=argparse.SUPPRESS)
    release_destination = release.add_mutually_exclusive_group(required=True)
    release_destination.add_argument(
        "--mirror", type=Path, metavar="ABS", help="managed mirror path"
    )
    release_destination.add_argument(
        "--staging-only", dest="staging", type=Path, metavar="ABS", help="unverified staging path"
    )
    release.add_argument(
        "--adopt-existing", action="store_true", help="adopt unmanifested skills on first release"
    )
    _output(release)

    show = (
        command("plan", "inspect a saved operation plan")
        .add_subparsers(dest="plan_action", required=True)
        .add_parser("show")
    )
    show.add_argument("plan", type=Path)
    show.add_argument("--max-bytes", type=int, default=MAX_DIFF_BYTES)

    audit = command("audit", "inspect an untrusted skill payload read-only")
    audit.add_argument("target", type=Path)
    command("doctor", "diagnose source and trusted toolchain")
    apply = command("apply", "apply one exact reviewed operation plan")
    apply.add_argument("plan", type=Path)
    return parser


def _plan_result(plan: Plan, destination: Path | None, bundle: Path) -> Result:
    output, digest = operation_document(plan, bundle)
    artifact = None
    if destination is not None and plan.changes:
        artifact = str(write_artifact(validate_output_path(destination, plan, bundle), output))
    data = {
        **plan.data,
        "root": str(plan.root),
        "planDigest": digest,
        "planOutput": artifact,
        "bundleIdentity": parse_document(output, kind="operation-plan").get("bundleIdentity"),
        "bindings": plan.bindings,
        "sources": [item.as_dict() for item in plan.sources],
    }
    if not plan.changes:
        return Result(plan.command, "ok", "already current; no plan file written", data=data)
    summary = (
        "exact plan saved; review it with plan show before apply"
        if artifact
        else "preview only; rerun with --output to save an applicable plan"
    )
    return Result(
        plan.command,
        "planned",
        summary,
        changes=plan.project(),
        data=data,
        next_action=f"remek plan show {artifact}" if artifact else None,
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


def _apply_result(arguments: argparse.Namespace, bundle: Path) -> Result:
    loaded = load_operation_plan(arguments.plan)
    selected = arguments.root
    if selected is not None:
        absolute = selected.expanduser().absolute()
        canonical = (
            checked(absolute) if exists(absolute) else checked(absolute.parent) / absolute.name
        )
        if canonical != loaded.root:
            raise Error("plan.root", "root differs; nothing applied; use plan root")
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
        findings = tuple(
            item for item in check(inspect(plan.root)) if item.code != "transaction.residue"
        )
        if any(item.severity == "error" for item in findings):
            raise Error("apply.postcondition", "applied state failed repository checking")

    outcome = apply_changes(plan.changes, verify=verify)
    if plan.command != "release":
        findings = check(inspect(plan.root))
    errors = any(item.severity == "error" for item in findings)
    return Result(
        "apply",
        "issues" if errors else "ok",
        f"applied {len(plan.changes)} exact reviewed change(s)",
        changed=outcome.changed,
        findings=findings,
        changes=plan.project(),
        data={"root": str(plan.root), "planDigest": digest, "operation": plan.command},
    )


def _template_result(command: str, summary: str, template: JSONObject, **data: object) -> Result:
    return Result(command, "ok", summary, data={**data, "template": template})


def _dispatch(  # noqa: PLR0911, PLR0912, PLR0915
    arguments: argparse.Namespace, bundle: Path
) -> Result:
    command = arguments.command
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
    root = checked(arguments.root or Path.cwd())
    output = getattr(arguments, "output", None)

    def planned(value: Plan) -> Result:
        return _plan_result(value, output, bundle)

    if command == "scaffold":
        data = scaffold_workspace(
            root,
            arguments.workspace,
            name=arguments.name,
            origin=arguments.origin,
            source=arguments.source,
            skill_name=arguments.skill,
            bundle=bundle,
        )
        return Result("scaffold", "ok", "disposable workspace created", changed=True, data=data)
    if command == "accept":
        return planned(accept_plan(root, arguments.workspace))
    if command == "distribution":
        return planned(distribution_accept_plan(root, arguments.source))
    if command == "disclosure":
        return planned(disclosure_accept_plan(root, arguments.source))
    if command == "retire":
        return planned(retire_plan(root, arguments.skill, arguments.reason))
    if command == "remove":
        return planned(remove_plan(root, arguments.skill))
    if command == "check":
        inspection = inspect(root)
        distribution = arguments.release
        findings = (
            release_findings(inspection, distribution)
            if distribution is not None
            else check(inspection)
        )
        return _findings_result(
            "check",
            findings,
            {"root": str(root), "release": distribution},
        )
    if command == "repair":
        findings = check(inspect(root))
        errors = tuple(item for item in findings if item.severity == "error")
        if any(not item.repairable for item in errors):
            return _findings_result("repair", findings, {"root": str(root)})
        plan = repair_plan(root)
        if errors and not plan.changes:
            return _findings_result("repair", findings, {"root": str(root)})
        return planned(plan)
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
                candidate=selected.digest,
                routingCaseSetDigest=selected.routing_cases.digest,
                behaviorCaseSetDigest=selected.behavior_cases.digest,
                routingCatalogDigest=evidence.routing_catalog_digest,
            )
        return planned(eval_record_plan(root, skill, arguments.evidence))
    if command == "approve":
        distribution, skill = arguments.distribution, arguments.skill
        if arguments.approve_action == "plan":
            return _template_result(
                "approve plan",
                "reviewer-owned approval template prepared",
                approval_template(inspect(root), distribution, skill),
            )
        return planned(approve_record_plan(root, distribution, skill, arguments.approval))
    if command == "release":
        if arguments.distribution == "verify":
            distribution, mirror = arguments.verify_distribution, arguments.mirror
            if (
                distribution is None
                or mirror is None
                or arguments.staging is not None
                or arguments.output is not None
                or arguments.adopt_existing
            ):
                raise Error("cli.arguments", "release verify requires exactly DIST --mirror ABS")
            data = release_verify(root, distribution, mirror)
            return Result(
                "release verify",
                "ok",
                "release is push-ready at this point in time",
                data=data,
            )
        if arguments.verify_distribution is not None:
            raise Error("cli.arguments", "release accepts one distribution name")
        return planned(
            release_plan(
                root,
                arguments.distribution,
                mirror=arguments.mirror,
                staging=arguments.staging,
                adopt=arguments.adopt_existing,
            )
        )
    if command == "plan":
        loaded = load_operation_plan(arguments.plan)
        plan = reconstruct_plan(loaded, bundle)
        digest = verify_operation_plan(loaded, plan, bundle)
        max_bytes = arguments.max_bytes
        if arguments.json:
            max_bytes = min(max_bytes, MAX_RENDERED_BYTES // 3)
        diff = plan_diff(plan, max_bytes=max_bytes)
        return Result(
            "plan show",
            "ok",
            "plan reconstructed exactly; content diff follows",
            changes=plan.project(),
            data={"root": str(plan.root), "planDigest": digest, "diff": diff},
        )
    if command == "audit":
        target = checked(arguments.target)
        findings = audit_repository(target)
        return _findings_result("audit", findings, {"root": str(target)})
    if command == "doctor":
        inspection = inspect(root)
        findings = check(inspection)
        return _findings_result(
            "doctor",
            findings,
            {
                "root": str(root),
                "skills": [item.name for item in inspection.skills],
                "toolchain": str(bundle),
            },
        )
    if command == "update":
        return planned(update_plan(root, bundle))
    raise Error("cli.command", f"unsupported command: {command}")


def _error_result(arguments: argparse.Namespace | None, status: Status, error: Error) -> Result:
    command = cast(str, arguments.command) if arguments is not None else "remek"
    return Result(
        command,
        status,
        error.message,
        changed=error.changed,
        findings=(Finding(error.code, "error", error.message),),
        exit_override=error.exit_code,
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
        template = result.data.get("template")
        if isinstance(template, dict):
            lines.append(json.dumps(template, ensure_ascii=True, sort_keys=True, indent=2))
        diff = result.data.get("diff")
        if isinstance(diff, str):
            lines.extend(["", diff.rstrip("\n")])
        for change in result.changes:
            lines.append(
                f"  {safe_text(change.action)} {safe_text(change.path)}: "
                f"{safe_text(change.before)} -> {safe_text(change.after)}"
            )
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


def main(argv: list[str] | None = None, *, bundle: Path) -> int:
    raw = sys.argv[1:] if argv is None else argv
    stop = raw.index("--") if "--" in raw else len(raw)
    json_mode = "--json" in raw[:stop]
    arguments: argparse.Namespace | None = None
    try:
        selected_toolchain = checked(bundle)
        arguments = _parser().parse_args(raw)
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
    try:
        output = _render(result, json_mode=json_mode)
    except (Error, UnicodeError) as exc:
        result = _error_result(None, "refused", Error("output.invalid", str(exc)))
        output = _render(result, json_mode=json_mode)
    stream = sys.stderr if result.status in {"failed", "refused"} and not json_mode else sys.stdout
    stream.write(output)
    return result.exit_code
