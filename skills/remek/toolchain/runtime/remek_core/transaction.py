# ruff: noqa: D101, D102, D103, I001
"""Transactions."""

import hashlib
import os
import secrets
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from .filesystem import (
    ABSENT,
    OpenedBoundary,
    Tree,
    checked_path,
    checked_root as checked,
    fingerprint,
    fingerprint_at as probe,
    portable_path,
    remove_at,
    snapshot_tree as snapshot,
    write_file_at,
    write_tree_at,
)
from .model import Error, PlannedChange

ChangeKind = Literal["write", "delete", "tree"]


@dataclass(frozen=True)
class Change:
    boundary: Path
    relative: str
    kind: ChangeKind
    expected: str
    after: str
    reason: str
    data: bytes | None = None
    tree: Tree | None = None
    mode: int = 0o644

    @property
    def path(self) -> Path:
        return self.boundary / self.relative

    def project(self) -> PlannedChange:
        return PlannedChange(
            self.kind,
            str(self.path),
            self.expected,
            self.after,
            self.reason,
        )


def _change_target(boundary: Path, path: Path) -> tuple[Path, str, Path]:
    canonical = checked(boundary)
    target = checked_path(canonical, path)
    relative = target.relative_to(canonical).as_posix()
    portable_path(relative)
    return canonical, relative, target


def write_change(
    boundary: Path,
    path: Path,
    data: bytes,
    reason: str,
    *,
    mode: int = 0o644,
) -> Change:
    canonical, relative, target = _change_target(boundary, path)
    after = f"file:{mode:o}:{hashlib.sha256(data).hexdigest()}"
    return Change(
        canonical, relative, "write", fingerprint(target), after, reason, data=data, mode=mode
    )


def delete_change(boundary: Path, path: Path, reason: str) -> Change:
    canonical, relative, target = _change_target(boundary, path)
    return Change(canonical, relative, "delete", fingerprint(target), ABSENT, reason)


def tree_change(boundary: Path, path: Path, source: Path | Tree, reason: str) -> Change:
    canonical, relative, destination = _change_target(boundary, path)
    tree = source if isinstance(source, Tree) else snapshot(source)
    return Change(
        canonical,
        relative,
        "tree",
        fingerprint(destination),
        f"tree:{tree.digest}",
        reason,
        tree=tree,
    )


@dataclass(frozen=True)
class Residue:
    path: str
    identity: str
    reason: str


@dataclass(frozen=True)
class ApplyOutcome:
    changed: bool


@dataclass
class _State:
    change: Change
    boundary: OpenedBoundary
    parent: int
    name: str
    stage: str | None
    backup: str
    rollback: str
    stage_identity: str | None = None


def _private_name(purpose: str, token: str, relative: str) -> str:
    suffix = hashlib.sha256(relative.encode()).hexdigest()[:12]
    return f".remek-{purpose}-{token}-{suffix}"


def _validate_changes(changes: tuple[Change, ...]) -> None:
    logical: set[str] = set()
    absolute: list[Path] = []
    for change in changes:
        canonical = checked(change.boundary)
        if canonical != change.boundary:
            raise Error("transaction.boundary", "change boundary is not canonical")
        portable = portable_path(change.relative)
        target = canonical / change.relative
        global_key = f"{os.path.normcase(str(canonical)).casefold()}\0{portable}"
        if global_key in logical:
            raise Error("transaction.overlap", f"mutation plan repeats a destination: {target}")
        logical.add(global_key)
        absolute.append(target)
    for index, left in enumerate(absolute):
        for right in absolute[index + 1 :]:
            if left == right or left in right.parents or right in left.parents:
                raise Error(
                    "transaction.overlap",
                    f"mutation destinations overlap: {left} and {right}",
                )


def _open_states(
    changes: tuple[Change, ...], token: str
) -> tuple[list[_State], list[OpenedBoundary]]:
    boundaries: dict[Path, OpenedBoundary] = {}
    states: list[_State] = []
    try:
        for change in changes:
            boundary = boundaries.get(change.boundary)
            if boundary is None:
                boundary = OpenedBoundary(change.boundary)
                boundaries[change.boundary] = boundary
            parent, name = boundary.open_parent(change.relative)
            stage = (
                None if change.kind == "delete" else _private_name("stage", token, change.relative)
            )
            states.append(
                _State(
                    change,
                    boundary,
                    parent,
                    name,
                    stage,
                    _private_name("backup", token, change.relative),
                    _private_name("rollback", token, change.relative),
                    change.after if stage is not None else None,
                )
            )
        return states, list(boundaries.values())
    except BaseException:
        _close(states, boundaries.values())
        raise


def _stage(state: _State) -> None:
    if state.stage is None:
        return
    if probe(state.parent, state.stage) != ABSENT:
        raise Error("transaction.residue", f"staging path already exists: {state.change.path}")
    change = state.change
    if change.kind == "write":
        if change.data is None:
            raise AssertionError("write change lacks data")
        write_file_at(state.parent, state.stage, change.data, change.mode)
    elif change.kind == "tree":
        if change.tree is None:
            raise AssertionError("tree change lacks tree")
        write_tree_at(state.parent, state.stage, change.tree)
    else:
        raise AssertionError("delete change cannot have a stage")
    identity = probe(state.parent, state.stage)
    if identity != change.after:
        raise Error("transaction.stage", f"staged object does not match plan: {change.path}")


def _residue(state: _State, name: str, reason: str) -> Residue | None:
    try:
        identity = probe(state.parent, name)
    except Error as exc:
        return Residue(str(state.change.path.parent / name), "unknown", f"{reason}: {exc}")
    if identity == ABSENT:
        return None
    return Residue(str(state.change.path.parent / name), identity, reason)


def _remove_expected(state: _State, name: str, expected: str) -> Residue | None:
    current = probe(state.parent, name)
    if current == ABSENT:
        return None
    if current != expected:
        return Residue(str(state.change.path.parent / name), current, "object changed; preserved")
    try:
        remove_at(state.parent, name, expected)
    except BaseException as exc:
        detail = str(exc) or type(exc).__name__
        return Residue(
            str(state.change.path.parent / name),
            probe(state.parent, name),
            f"cleanup failed: {detail}",
        )
    return None


def _stage_residue(states: Iterable[_State]) -> list[Residue]:
    residue: list[Residue] = []
    for state in states:
        if state.stage is None:
            continue
        item = _remove_expected(state, state.stage, cast(str, state.stage_identity))
        if item is not None:
            residue.append(item)
    return residue


def _replace(state: _State, source: str, destination: str) -> None:
    os.replace(
        source,
        destination,
        src_dir_fd=state.parent,
        dst_dir_fd=state.parent,
    )


def _classify_and_restore(state: _State) -> list[Residue]:  # noqa: PLR0912
    change = state.change
    residue: list[Residue] = []
    destination = probe(state.parent, state.name)
    backup = probe(state.parent, state.backup)
    rollback = probe(state.parent, state.rollback)

    if rollback != ABSENT:
        residue.append(
            Residue(str(change.path.parent / state.rollback), rollback, "rollback path occupied")
        )
        return residue

    if destination == change.after and change.after != ABSENT:
        try:
            _replace(state, state.name, state.rollback)
        except BaseException:
            destination = probe(state.parent, state.name)
            rollback = probe(state.parent, state.rollback)
            if not (destination == ABSENT and rollback == change.after):
                residue.append(
                    Residue(str(change.path), destination, "could not quarantine desired state")
                )
                item = _residue(state, state.rollback, "rollback residue")
                if item is not None:
                    residue.append(item)
                return residue
        destination = probe(state.parent, state.name)
        rollback = probe(state.parent, state.rollback)

    if destination == ABSENT and backup == change.expected and change.expected != ABSENT:
        try:
            _replace(state, state.backup, state.name)
        except BaseException:
            destination = probe(state.parent, state.name)
            backup = probe(state.parent, state.backup)
            if not (destination == change.expected and backup == ABSENT):
                residue.append(
                    Residue(str(change.path), destination, "prior state could not be restored")
                )
                item = _residue(state, state.backup, "prior state preserved")
                if item is not None:
                    residue.append(item)
                return residue
        destination = probe(state.parent, state.name)
        backup = probe(state.parent, state.backup)

    if destination != change.expected:
        residue.append(Residue(str(change.path), destination, "destination is not prior state"))

    if backup != ABSENT:
        if destination == change.expected and backup == change.expected:
            item = _remove_expected(state, state.backup, change.expected)
            if item is not None:
                residue.append(item)
        else:
            residue.append(
                Residue(str(change.path.parent / state.backup), backup, "backup preserved")
            )

    rollback = probe(state.parent, state.rollback)
    if rollback != ABSENT:
        if rollback == change.after and destination == change.expected:
            item = _remove_expected(state, state.rollback, change.after)
            if item is not None:
                residue.append(item)
        else:
            residue.append(
                Residue(
                    str(change.path.parent / state.rollback), rollback, "desired state preserved"
                )
            )
    return residue


def _rollback(states: Iterable[_State]) -> list[Residue]:
    residue: list[Residue] = []
    for state in reversed(tuple(states)):
        try:
            residue.extend(_classify_and_restore(state))
        except BaseException as exc:
            detail = str(exc) or type(exc).__name__
            item = _residue(state, state.name, f"rollback interrupted: {detail}")
            if item is not None:
                residue.append(item)
            for name, reason in (
                (state.backup, "backup preserved"),
                (state.rollback, "rollback object preserved"),
            ):
                item = _residue(state, name, reason)
                if item is not None:
                    residue.append(item)
    residue.extend(_stage_residue(states))
    return residue


def _close(states: Iterable[_State], boundaries: Iterable[OpenedBoundary]) -> None:
    for state in states:
        with suppress(OSError):
            os.close(state.parent)
    for boundary in boundaries:
        boundary.close()


def _transaction_error(
    code: str,
    message: str,
    *,
    changed: bool,
    residue: Iterable[Residue] = (),
    exit_code: int | None = None,
) -> Error:
    details = tuple(residue)
    if details:
        output = "; ".join(f"{item.path}: {item.reason}" for item in details)
        message = f"{message}: {output}"
    return Error(code, message, changed=changed, exit_code=exit_code)


def apply_changes(  # noqa: PLR0912, PLR0915
    changes: Iterable[Change], *, verify: Callable[[], None] | None = None
) -> ApplyOutcome:
    planned = tuple(changes)
    if not planned:
        return ApplyOutcome(False)
    _validate_changes(planned)
    token = secrets.token_hex(8)
    states: list[_State] = []
    boundaries: list[OpenedBoundary] = []
    try:
        states, boundaries = _open_states(planned, token)
        for state in states:
            current = probe(state.parent, state.name)
            if current != state.change.expected:
                raise Error(
                    "transaction.stale",
                    f"changed since planning: {state.change.path}; nothing applied; recreate plan",
                )
            for private in (state.stage, state.backup, state.rollback):
                if private is not None and probe(state.parent, private) != ABSENT:
                    raise Error(
                        "transaction.residue",
                        f"private transaction path already exists beside {state.change.path}",
                    )
        try:
            for state in states:
                _stage(state)
        except BaseException as exc:
            residue = _stage_residue(states)
            if residue:
                raise _transaction_error(
                    "transaction.stage-residue",
                    "staging failed and residue was preserved",
                    changed=True,
                    residue=residue,
                ) from exc
            if isinstance(exc, Error):
                raise
            if isinstance(exc, KeyboardInterrupt):
                raise _transaction_error(
                    "transaction.interrupted",
                    "mutation was interrupted before commit",
                    changed=False,
                    exit_code=130,
                ) from None
            raise Error("transaction.stage", f"cannot stage mutation: {exc}") from None

        try:
            for state in states:
                if probe(state.parent, state.name) != state.change.expected:
                    raise Error(
                        "transaction.stale",
                        f"changed before commit: {state.change.path}; prior state preserved; "
                        "recreate plan",
                    )
            for state in states:
                change = state.change
                if change.expected != ABSENT:
                    try:
                        _replace(state, state.name, state.backup)
                    except BaseException:
                        destination = probe(state.parent, state.name)
                        backup = probe(state.parent, state.backup)
                        if not (destination == ABSENT and backup == change.expected):
                            raise
                if state.stage is not None:
                    try:
                        _replace(state, state.stage, state.name)
                    except BaseException:
                        destination = probe(state.parent, state.name)
                        staged = probe(state.parent, state.stage)
                        if not (destination == change.after and staged == ABSENT):
                            raise
                if probe(state.parent, state.name) != change.after:
                    raise Error(
                        "transaction.verify", f"installed object differs from plan: {change.path}"
                    )
            if verify is not None:
                verify()
        except BaseException as exc:
            residue = _rollback(states)
            restored = not residue and all(
                probe(state.parent, state.name) == state.change.expected for state in states
            )
            if restored:
                if isinstance(exc, KeyboardInterrupt):
                    raise _transaction_error(
                        "transaction.interrupted",
                        "mutation was interrupted and prior state was restored",
                        changed=False,
                        exit_code=130,
                    ) from None
                if isinstance(exc, Error):
                    raise
                raise Error(
                    "transaction.failed", f"mutation failed and prior state was restored: {exc}"
                ) from None
            raise _transaction_error(
                "transaction.residue",
                "mutation failed and exact residue was preserved",
                changed=True,
                residue=residue,
            ) from exc

        cleanup_residue: list[Residue] = []
        for state in states:
            if state.change.expected != ABSENT:
                item = _remove_expected(state, state.backup, state.change.expected)
                if item is not None:
                    cleanup_residue.append(item)
        cleanup_residue.extend(_stage_residue(states))
        if cleanup_residue:
            raise _transaction_error(
                "transaction.cleanup-residue",
                "mutation committed but cleanup residue remains",
                changed=True,
                residue=cleanup_residue,
            )
        return ApplyOutcome(True)
    finally:
        _close(states, boundaries)
