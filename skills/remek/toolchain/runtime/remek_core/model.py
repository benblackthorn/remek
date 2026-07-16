# ruff: noqa: D101, D102, D103
"""Models."""

import re
from dataclasses import asdict, dataclass, field
from typing import Literal, cast

Severity = Literal["info", "warning", "error"]
Status = Literal["ok", "planned", "issues", "refused", "failed"]
_SKILL_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


def valid_skill_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 64
        and _SKILL_NAME.fullmatch(value) is not None
    )


class RemekError(Exception):
    def __init__(
        self,
        code: str,
        message: str | None = None,
        *,
        changed: bool = False,
        exit_code: int | None = None,
    ) -> None:
        if message is None:
            message = code
            code = "operation.refused"
        super().__init__(message)
        self.code = code
        self.message = message
        self.changed = changed
        self.exit_code = exit_code if exit_code is not None else (3 if changed else 2)


Error = RemekError


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    severity: Severity
    message: str
    path: str | None = None
    repairable: bool = False

    def as_dict(self) -> dict[str, object]:
        return cast(dict[str, object], asdict(self))


@dataclass(frozen=True)
class PlannedChange:
    action: str
    path: str
    before: str
    after: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return cast(dict[str, str], asdict(self))


@dataclass(frozen=True)
class Result:
    command: str
    status: Status
    summary: str
    changed: bool = False
    findings: tuple[Finding, ...] = ()
    changes: tuple[PlannedChange, ...] = ()
    data: dict[str, object] = field(default_factory=dict)
    next_action: str | None = None
    exit_override: int | None = None

    @property
    def exit_code(self) -> int:
        if self.exit_override is not None:
            return self.exit_override
        if self.status == "refused":
            return 3 if self.changed else 2
        return {"failed": 70, "issues": 1}.get(
            self.status, int(any(item.severity == "error" for item in self.findings))
        )

    def as_dict(self) -> dict[str, object]:
        from .contract import SCHEMA  # noqa: PLC0415

        return {
            "schema": SCHEMA,
            "kind": "command-result",
            "command": self.command,
            "status": self.status,
            "changed": self.changed,
            "summary": self.summary,
            "findings": [item.as_dict() for item in self.findings],
            "changes": [item.as_dict() for item in self.changes],
            "data": self.data,
            "nextAction": self.next_action,
            "exitCode": self.exit_code,
        }


_BIDI = {0x061C, 0x200E, 0x200F, 0x2028, 0x2029, *range(0x202A, 0x202F), *range(0x2066, 0x2070)}


def safe_text(value: object) -> str:
    text = str(value)
    output: list[str] = []
    escapes = {"\b": r"\b", "\t": r"\t", "\n": r"\n", "\f": r"\f", "\r": r"\r"}
    for character in text:
        code = ord(character)
        if character == "\\":
            output.append(r"\\")
        elif character in escapes:
            output.append(escapes[character])
        elif code < 0x20 or 0x7F <= code <= 0x9F or code in _BIDI or 0xD800 <= code <= 0xDFFF:
            width = 4 if code <= 0xFFFF else 8
            output.append(f"\\u{code:0{width}x}")
        else:
            output.append(character)
    return "".join(output)
