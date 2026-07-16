# ruff: noqa: D101, D102, D103, I001
"""Plans."""

import difflib
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from .contract import (
    JSONObject,
    JSONValue,
    parse_canonical_document,
    parse_document,
    render_document as render,
)
from .filesystem import (
    ABSENT,
    Tree,
    checked_root as checked,
    paths_related,
    read_artifact,
    read_regular as read,
    snapshot_tree as snapshot,
)
from .model import Error, PlannedChange, safe_text
from .transaction import Change

MAX_DIFF_BYTES = 768 * 1024


@dataclass(frozen=True)
class SourceBinding:
    path: Path
    identity: str

    def as_dict(self) -> JSONObject:
        return {"path": str(self.path), "identity": self.identity}


@dataclass(frozen=True)
class Plan:
    command: str
    root: Path
    changes: tuple[Change, ...]
    inputs: JSONObject = field(default_factory=dict)
    generated: JSONObject = field(default_factory=dict)
    bindings: JSONObject = field(default_factory=dict)
    sources: tuple[SourceBinding, ...] = ()
    data: dict[str, object] = field(default_factory=dict)

    def project(self) -> tuple[PlannedChange, ...]:
        return tuple(change.project() for change in self.changes)


@dataclass(frozen=True)
class LoadedPlan:
    document: JSONObject
    root: Path
    command: str
    inputs: JSONObject
    generated: JSONObject
    bundle_identity: str


def bundle_identity(bundle: Path) -> str:
    tree = snapshot(checked(bundle), reject_bytecode=True)
    return f"tree:{tree.digest}"


def _fields(plan: Plan, bundle: Path) -> JSONObject:
    return {
        "root": str(plan.root),
        "command": plan.command,
        "inputs": plan.inputs,
        "generated": plan.generated,
        "bundleIdentity": bundle_identity(bundle),
        "sources": [cast(JSONValue, item.as_dict()) for item in plan.sources],
        "changes": [cast(JSONValue, item.as_dict()) for item in plan.project()],
        "bindings": plan.bindings,
    }


def operation_document(plan: Plan, bundle: Path) -> tuple[bytes, str]:
    fields = _fields(plan, bundle)
    digest = hashlib.sha256(render("operation-plan", fields)).hexdigest()
    return render("operation-plan", {**fields, "planDigest": digest}), digest


def _object(document: JSONObject, key: str) -> JSONObject:
    value = document.get(key)
    if not isinstance(value, dict):
        raise Error("plan.shape", f"operation plan {key} must be one object")
    return value


def _string(document: JSONObject, key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str):
        raise Error("plan.shape", f"operation plan {key} must be one string")
    return value


def _validate_entries(document: JSONObject) -> None:
    sources = document.get("sources")
    if not isinstance(sources, list):
        raise Error("plan.sources", "operation plan sources must be one list")
    for value in sources:
        if (
            not isinstance(value, dict)
            or set(value) != {"path", "identity"}
            or not isinstance(value.get("path"), str)
            or not Path(cast(str, value["path"])).is_absolute()
            or not isinstance(value.get("identity"), str)
        ):
            raise Error("plan.sources", "operation plan source entry is invalid")
    changes = document.get("changes")
    keys = {"action", "path", "before", "after", "reason"}
    if not isinstance(changes, list):
        raise Error("plan.changes", "operation plan changes must be one list")
    for value in changes:
        if (
            not isinstance(value, dict)
            or set(value) != keys
            or not all(isinstance(value.get(key), str) for key in keys)
            or not Path(cast(str, value["path"])).is_absolute()
        ):
            raise Error("plan.changes", "operation plan change entry is invalid")


def load_operation_plan(path: Path) -> LoadedPlan:
    document = parse_canonical_document(
        read_artifact(path.expanduser().absolute()).data, kind="operation-plan"
    )
    expected_keys = {
        "schema",
        "kind",
        "root",
        "command",
        "inputs",
        "generated",
        "bundleIdentity",
        "sources",
        "changes",
        "bindings",
        "planDigest",
    }
    if set(document) != expected_keys:
        raise Error("plan.keys", "operation plan has unknown or missing keys")
    root_text = _string(document, "root")
    command = _string(document, "command")
    identity = _string(document, "bundleIdentity")
    digest = _string(document, "planDigest")
    if not Path(root_text).is_absolute() or not command or not identity.startswith("tree:"):
        raise Error("plan.identity", "operation plan identity is invalid")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise Error("plan.digest", "operation plan digest is invalid")
    _validate_entries(document)
    inputs = _object(document, "inputs")
    generated = _object(document, "generated")
    _object(document, "bindings")
    fields = {
        key: value for key, value in document.items() if key not in {"schema", "kind", "planDigest"}
    }
    if hashlib.sha256(render("operation-plan", fields)).hexdigest() != digest:
        raise Error("plan.digest", "operation plan digest does not match its contents")
    return LoadedPlan(document, Path(root_text), command, inputs, generated, identity)


def _input_path(inputs: JSONObject, key: str) -> Path:
    value = inputs.get(key)
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise Error("plan.inputs", f"plan input {key} must be an absolute path")
    return Path(value)


def _input_text(inputs: JSONObject, key: str) -> str:
    value = inputs.get(key)
    if not isinstance(value, str) or not value:
        raise Error("plan.inputs", f"plan input {key} must be one string")
    return value


def _input_bool(inputs: JSONObject, key: str) -> bool:
    value = inputs.get(key)
    if not isinstance(value, bool):
        raise Error("plan.inputs", f"plan input {key} must be boolean")
    return value


def _keys(values: JSONObject, expected: set[str], command: str) -> None:
    if set(values) != expected:
        raise Error("plan.inputs", f"{command} plan inputs are invalid")


def reconstruct_plan(loaded: LoadedPlan, bundle: Path) -> Plan:  # noqa: PLR0911
    from .workflows import (  # noqa: PLC0415
        accept_plan,
        approve_record_plan,
        disclosure_accept_plan,
        distribution_accept_plan,
        eval_record_plan,
        init_plan,
        release_plan,
        remove_plan,
        repair_plan,
        retire_plan,
        update_plan,
    )

    command, inputs, root = loaded.command, loaded.inputs, loaded.root
    _keys(loaded.generated, {"repositoryId"} if command == "init" else set(), command)
    if command == "init":
        _keys(inputs, {"target", "project"}, command)
        return init_plan(
            _input_path(inputs, "target"),
            bundle,
            _input_text(loaded.generated, "repositoryId"),
            project=_input_bool(inputs, "project"),
        )
    if command == "accept":
        _keys(inputs, {"workspace"}, command)
        return accept_plan(root, _input_path(inputs, "workspace"))
    if command in {"distribution-accept", "disclosure-accept"}:
        _keys(inputs, {"source"}, command)
        function = (
            distribution_accept_plan
            if command.startswith("distribution")
            else disclosure_accept_plan
        )
        return function(root, _input_path(inputs, "source"))
    if command in {"retire", "remove"}:
        _keys(inputs, {"skill", "reason"} if command == "retire" else {"skill"}, command)
        if command == "retire":
            return retire_plan(root, _input_text(inputs, "skill"), _input_text(inputs, "reason"))
        return remove_plan(root, _input_text(inputs, "skill"))
    if command == "eval-record":
        _keys(inputs, {"skill", "evidence"}, command)
        return eval_record_plan(root, _input_text(inputs, "skill"), _input_path(inputs, "evidence"))
    if command == "approve-record":
        _keys(inputs, {"distribution", "skill", "approval"}, command)
        return approve_record_plan(
            root,
            _input_text(inputs, "distribution"),
            _input_text(inputs, "skill"),
            _input_path(inputs, "approval"),
        )
    if command == "release":
        _keys(inputs, {"distribution", "mirror", "staging", "adopt"}, command)
        mirror = inputs.get("mirror")
        staging = inputs.get("staging")
        if mirror is not None and (not isinstance(mirror, str) or not Path(mirror).is_absolute()):
            raise Error("plan.inputs", "release mirror input is invalid")
        if staging is not None and (
            not isinstance(staging, str) or not Path(staging).is_absolute()
        ):
            raise Error("plan.inputs", "release staging input is invalid")
        return release_plan(
            root,
            _input_text(inputs, "distribution"),
            mirror=Path(mirror) if isinstance(mirror, str) else None,
            staging=Path(staging) if isinstance(staging, str) else None,
            adopt=_input_bool(inputs, "adopt"),
        )
    if command == "repair":
        _keys(inputs, set(), command)
        return repair_plan(root)
    if command == "update":
        _keys(inputs, set(), command)
        return update_plan(root, bundle)
    raise Error("plan.command", f"unsupported operation plan command: {command}")


def _first_difference(  # noqa: PLR0911
    left: JSONValue, right: JSONValue, path: str = "plan"
) -> str:
    if type(left) is not type(right):
        return path
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                return f"{path}.{key}"
            difference = _first_difference(left[key], right[key], f"{path}.{key}")
            if difference:
                return difference
        return ""
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return f"{path}.length"
        for index, (first, second) in enumerate(zip(left, right, strict=True)):
            difference = _first_difference(first, second, f"{path}[{index}]")
            if difference:
                return difference
        return ""
    return "" if left == right else path


def verify_operation_plan(loaded: LoadedPlan, plan: Plan, bundle: Path) -> str:
    if bundle_identity(bundle) != loaded.bundle_identity:
        raise Error("plan.bundle-stale", "toolchain differs; nothing applied; recreate plan")
    output, digest = operation_document(plan, bundle)
    current = parse_document(output, kind="operation-plan")
    if loaded.document != current:
        difference = _first_difference(loaded.document, current)
        raise Error(
            "plan.stale",
            f"plan differs at {difference or 'plan'}; nothing applied; recreate and review",
        )
    return digest


def validate_output_path(output: Path, plan: Plan, bundle: Path) -> Path:
    selected = output.expanduser().absolute()
    canonical = checked(selected.parent) / selected.name
    protected = {plan.root, checked(bundle)}
    protected.update(source.path for source in plan.sources)
    protected.update(change.path for change in plan.changes)
    protected.update(change.boundary for change in plan.changes)

    def absolute_paths(value: JSONValue) -> set[Path]:
        if isinstance(value, str):
            return {Path(value)} if Path(value).is_absolute() else set()
        if isinstance(value, list):
            return set().union(*(absolute_paths(item) for item in value)) if value else set()
        if isinstance(value, dict):
            return (
                set().union(*(absolute_paths(item) for item in value.values())) if value else set()
            )
        return set()

    protected.update(absolute_paths(plan.inputs))
    for path in protected:
        if paths_related(canonical, path):
            raise Error(
                "artifact.related",
                f"output related to {path}; nothing written; choose external path",
            )
    return canonical


def _tree_index(tree: Tree, prefix: str = "") -> dict[str, tuple[str, int, bytes | None]]:
    base = f"{prefix}/" if prefix else ""
    values: dict[str, tuple[str, int, bytes | None]] = {
        base.rstrip("/") or ".": ("directory", tree.root_mode, None)
    }
    values.update({base + item.path: ("directory", item.mode, None) for item in tree.directories})
    values.update({base + item.path: ("file", item.mode, item.data) for item in tree.files})
    return values


def _current_index(change: Change) -> dict[str, tuple[str, int, bytes | None]]:
    if change.expected == ABSENT:
        return {}
    if change.expected.startswith("file:"):
        try:
            data = read(change.path).data
        except Error:
            return {".": ("other", 0, None)}
        mode = int(change.expected.split(":", 2)[1], 8)
        return {".": ("file", mode, data)}
    try:
        return _tree_index(snapshot(change.path))
    except Error:
        return {".": ("other", 0, None)}


def _desired_index(change: Change) -> dict[str, tuple[str, int, bytes | None]]:
    if change.kind == "delete":
        return {}
    if change.kind == "write":
        return {".": ("file", change.mode, change.data)}
    if change.kind == "tree" and change.tree is not None:
        return _tree_index(change.tree)
    raise Error("plan.diff", "planned change lacks reconstructable content")


def _file_diff(path: str, before: bytes, after: bytes) -> list[str]:
    try:
        old = "\n".join(safe_text(part) for part in before.decode().split("\n")).splitlines(
            keepends=True
        )
        new = "\n".join(safe_text(part) for part in after.decode().split("\n")).splitlines(
            keepends=True
        )
    except UnicodeDecodeError:
        return [
            f"binary {path}: {len(before)} -> {len(after)} bytes; "
            f"sha256 {hashlib.sha256(before).hexdigest()} -> {hashlib.sha256(after).hexdigest()}\n"
        ]
    return list(difflib.unified_diff(old, new, fromfile=f"a/{path}", tofile=f"b/{path}"))


def plan_diff(plan: Plan, *, max_bytes: int = MAX_DIFF_BYTES) -> str:  # noqa: PLR0912
    if not 1 <= max_bytes <= MAX_DIFF_BYTES:
        raise Error("plan.diff-limit", f"--max-bytes must be 1 to {MAX_DIFF_BYTES}")
    lines: list[str] = []
    for change in plan.changes:
        old, new = _current_index(change), _desired_index(change)
        for relative in sorted(set(old) | set(new)):
            before, after = old.get(relative), new.get(relative)
            path = safe_text(str(change.path) if relative == "." else f"{change.path}/{relative}")
            if before == after:
                continue
            if before is None:
                if after is None:
                    raise AssertionError("diff union produced two absent entries")
                lines.append(f"add {path} mode {after[1]:04o}\n")
                if after[0] == "file":
                    lines.extend(_file_diff(path, b"", cast(bytes, after[2])))
            elif after is None:
                lines.append(f"remove {path} mode {before[1]:04o}\n")
                if before[0] == "file":
                    lines.extend(_file_diff(path, cast(bytes, before[2]), b""))
            elif before[0] != after[0]:
                lines.append(f"type {path}: {before[0]} -> {after[0]}\n")
                if before[0] == "file":
                    lines.extend(_file_diff(path, cast(bytes, before[2]), b""))
                if after[0] == "file":
                    lines.extend(_file_diff(path, b"", cast(bytes, after[2])))
            elif before[0] == after[0] == "file" and before[2] != after[2]:
                lines.extend(_file_diff(path, cast(bytes, before[2]), cast(bytes, after[2])))
            if before is not None and after is not None and before[1] != after[1]:
                lines.append(f"mode {path}: {before[1]:04o} -> {after[1]:04o}\n")
    output = "".join(lines) or "no changes\n"
    encoded = output.encode("utf-8")
    if len(encoded) <= max_bytes:
        return output
    marker = b"\n[diff truncated by remek]\n"
    prefix = encoded[: max(0, max_bytes - len(marker))].decode("utf-8", errors="ignore")
    return prefix + marker.decode()
