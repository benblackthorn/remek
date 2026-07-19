# ruff: noqa: D101, D102, D103, I001
"""Repository state."""

import fnmatch
import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import TypeGuard, cast

from .contract import (
    SCHEMA,
    JSONObject,
    load_canonical_document,
    load_document,
    parse_canonical_document,
    render_document as render,
)
from .evaluation import (
    CaseSet,
    EvidencePlan,
    parse_case_set,
    parse_profile,
    profile_key,
    receipt_status,
    routing_catalog_digest,
    validate_evidence_intrinsic,
)
from .filesystem import (
    Tree,
    _directory_members,
    checked_path,
    checked_root as checked,
    directory_members,
    entry_exists as exists,
    git_tree,
    is_private_name,
    portable_path,
    read_regular as read,
    real_directory,
    snapshot_tree as snapshot,
    tree_digest,
)
from .frontmatter import FrontmatterError, parse_skill, render_skill
from .model import Error, Finding, Severity, valid_skill_name
from .transaction import Change, write_change

CONFIG_NAME = "remek.json"
DISCLOSURE_PATH = ".remek/disclosure-policy.json"
SKILLS_START, SKILLS_END = "<!-- remek-skills:start -->", "<!-- remek-skills:end -->"
INJECTED_METADATA_KEYS = frozenset(
    {
        "github-path",
        "github-pinned",
        "github-ref",
        "github-repo",
        "github-tree-sha",
        "local-path",
    }
)
MAX_RECORD_BYTES, MAX_RECORDS, MAX_SKILL_GOV, MAX_REPO_GOV = 65536, 128, 4194304, 16777216
MAX_FINDINGS = 4096
MAX_SKILLS, MAX_SKILL_FILES, MAX_SKILL_BYTES, MAX_SKILL_TOKENS = 128, 256, 8388608, 75000
_FIELDS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
_PROVENANCE_FIELDS = (
    "skill",
    "origin",
    "sourceDigest",
    "sourceLabel",
    "upstreamRepository",
    "upstreamRef",
    "upstreamCandidate",
    "rights",
    "rightsBasis",
    "license",
)
_GOVERNANCE_KINDS = {
    "approval",
    "behavior-cases",
    "disclosure-policy",
    "distribution",
    "eval-receipt",
    "operation-plan",
    "provenance",
    "release-identity",
    "release-manifest",
    "release-set",
    "repository",
    "routing-cases",
    "skill-policy",
    "workspace",
}
_LIFECYCLES, _EXPOSURES = (
    {"draft", "ready", "retired"},
    {
        "source-only",
        "private-only",
        "public-eligible",
    },
)
_SHIMS = {"gate": "assets/gate"}
_HEX = set("0123456789abcdef")
_PLACEHOLDERS = tuple(
    re.compile(value, re.IGNORECASE if "lorem" in value else 0)
    for value in (r"\{\{[A-Z][A-Z0-9_-]*\}\}", r"\[TODO\]", r"\bTODO:", r"\bTBD:", "lorem ipsum")
)
_CREDENTIALS = (
    ("credential.private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("credential.aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("credential.github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("credential.github-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("credential.aws-key", re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("credential.slack-token", re.compile(r"\bxox[a-z]-[A-Za-z0-9-]{20,}\b")),
    ("credential.provider-token", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
)


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and len(value) == 64 and not set(value) - _HEX


def _text(value: object, label: str, limit: int, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()):
        raise Error("record.shape", f"invalid {label}")
    return value


def _keys(document: JSONObject, expected: set[str], label: str) -> None:
    if set(document) != expected:
        raise Error("record.keys", f"invalid {label} fields")


def _f(
    code: str,
    message: str,
    path: str | None = None,
    severity: Severity = "error",
    repairable: bool = False,
) -> Finding:
    return Finding(code, severity, message, path, repairable)


class _Findings(list[Finding]):
    overflow = False

    def append(self, item: Finding) -> None:
        if len(self) < MAX_FINDINGS:
            super().append(item)
        else:
            self.overflow = True

    def extend(self, values: Iterable[Finding]) -> None:
        for item in values:
            self.append(item)
            if self.overflow:
                break

    def ordered(self) -> tuple[Finding, ...]:
        values = sorted(set(self))
        if self.overflow:
            values = [
                *values[: MAX_FINDINGS - 1],
                _f("repo.findings", "repository issues exceed the retained bound", "."),
            ]
        return tuple(values)


@dataclass(frozen=True)
class Config:
    repository_id: str
    skills_root: str
    governed_skills: tuple[str, ...]

    def render(self) -> bytes:
        return render(
            "repository",
            {
                "repositoryId": self.repository_id,
                "skillsRoot": self.skills_root,
                "governedSkills": list(self.governed_skills),
            },
        )


@dataclass(frozen=True)
class SkillPolicy:
    skill: str
    lifecycle: str
    exposure: str
    state_reason: str

    def render(self) -> bytes:
        return render(
            "skill-policy",
            {
                "skill": self.skill,
                "lifecycle": self.lifecycle,
                "exposure": self.exposure,
                "stateReason": self.state_reason,
            },
        )


@dataclass(frozen=True)
class Provenance:
    skill: str
    origin: str
    source_digest: str
    source_label: str
    upstream_repository: str
    upstream_ref: str
    upstream_candidate: str
    rights: str
    rights_basis: str
    license: str

    @property
    def digest(self) -> str:
        return _hash(self.render())

    def render(self) -> bytes:
        return render(
            "provenance", dict(zip(_PROVENANCE_FIELDS, self.__dict__.values(), strict=True))
        )


@dataclass(frozen=True)
class Distribution:
    distribution_id: str
    audience: str
    skills: tuple[str, ...]
    target: JSONObject
    delivery: tuple[str, ...]
    routing_profiles: tuple[JSONObject, ...]
    behavior_profiles: tuple[JSONObject, ...]
    private_disclosure: str

    def _fields(self, *, context: bool = False) -> JSONObject:
        result: JSONObject = {
            "id": self.distribution_id,
            "audience": self.audience,
            "target": self.target,
            "delivery": list(self.delivery),
            "evidencePolicy": {
                "routingProfiles": list(self.routing_profiles),
                "behaviorProfiles": list(self.behavior_profiles),
            },
            "privateDisclosure": self.private_disclosure,
        }
        if not context:
            result["skills"] = list(self.skills)
        return result

    @property
    def context_digest(self) -> str:
        fields = self._fields(context=True)
        fields["distribution"] = fields.pop("id")
        return _hash(render("distribution-context", fields))

    def render(self) -> bytes:
        return render("distribution", self._fields())


@dataclass(frozen=True)
class DisclosureEntry:
    entry_id: str
    entry_class: str
    match: str
    value: str
    retired: bool = False

    @property
    def digest(self) -> str:
        fields = self.as_dict()
        fields.pop("retired")
        return _hash(render("disclosure-entry", fields))

    def as_dict(self) -> JSONObject:
        return {
            "id": self.entry_id,
            "class": self.entry_class,
            "match": self.match,
            "value": self.value,
            "retired": self.retired,
        }


@dataclass(frozen=True)
class DisclosurePolicy:
    entries: tuple[DisclosureEntry, ...]

    def render(self) -> bytes:
        return render("disclosure-policy", {"entries": [item.as_dict() for item in self.entries]})

    def active(self) -> dict[str, DisclosureEntry]:
        return {item.entry_id: item for item in self.entries if not item.retired}


@dataclass(frozen=True)
class Skill:
    name: str
    path: Path
    fields: dict[str, object]
    body: str
    digest: str
    tree: Tree
    policy: SkillPolicy
    provenance: Provenance
    routing_cases: CaseSet
    behavior_cases: CaseSet
    evidence: tuple[JSONObject, ...]
    approvals: tuple[JSONObject, ...]

    @property
    def description(self) -> str:
        value = self.fields.get("description")
        return value if isinstance(value, str) else ""


@dataclass(frozen=True)
class RepositoryInspection:
    root: Path
    config: Config | None
    bundle: Path | None
    skills: tuple[Skill, ...]
    distributions: tuple[Distribution, ...]
    disclosure: DisclosurePolicy | None
    issues: tuple[Finding, ...]

    def skill(self, name: str) -> Skill:
        try:
            return next(item for item in self.skills if item.name == name)
        except StopIteration:
            raise Error("skill.missing", f"unknown governed skill: {name}") from None

    def distribution(self, name: str) -> Distribution:
        try:
            return next(item for item in self.distributions if item.distribution_id == name)
        except StopIteration:
            raise Error("distribution.missing", f"unknown distribution: {name}") from None


def new_config(
    repository_id: str | None = None,
    *,
    skills_root: str = "skills",
    governed_skills: tuple[str, ...] = (),
) -> Config:
    value = str(uuid.uuid4()) if repository_id is None else repository_id
    try:
        valid_uuid = isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        valid_uuid = False
    if (
        not valid_uuid
        or not isinstance(skills_root, str)
        or skills_root not in ("skills", ".agents/skills")
    ):
        raise Error("repo.config", "invalid repository identity or skills root")
    if (
        tuple(sorted(set(governed_skills))) != governed_skills
        or any(not valid_skill_name(name) for name in governed_skills)
        or len(governed_skills) > MAX_SKILLS
    ):
        raise Error("repo.config", "governed skills must be sorted and unique")
    return Config(value, skills_root, governed_skills)


def load_config(root: Path) -> Config:
    document = load_document(root / CONFIG_NAME, kind="repository")
    _keys(document, {"schema", "kind", "repositoryId", "skillsRoot", "governedSkills"}, "config")
    skills = document.get("governedSkills")
    if not isinstance(skills, list) or not all(isinstance(item, str) for item in skills):
        raise Error("repo.config", "invalid governed skill list")
    return new_config(
        cast(str, document.get("repositoryId")),
        skills_root=cast(str, document.get("skillsRoot")),
        governed_skills=tuple(cast(list[str], skills)),
    )


def parse_policy(document: JSONObject, skill: str) -> SkillPolicy:
    _keys(document, {"schema", "kind", "skill", "lifecycle", "exposure", "stateReason"}, "policy")
    lifecycle, exposure = document.get("lifecycle"), document.get("exposure")
    if (
        document.get("skill") != skill
        or not isinstance(lifecycle, str)
        or lifecycle not in _LIFECYCLES
        or not isinstance(exposure, str)
        or exposure not in _EXPOSURES
    ):
        raise Error("policy.state", "invalid skill policy")
    return SkillPolicy(
        skill,
        lifecycle,
        exposure,
        _text(document.get("stateReason"), "state reason", 500),
    )


def parse_provenance(document: JSONObject, skill: str) -> Provenance:
    _keys(document, {"schema", "kind", *_PROVENANCE_FIELDS}, "provenance")
    origin, digest = document.get("origin"), document.get("sourceDigest")
    label = _text(document.get("sourceLabel"), "source label", 128)
    if (
        document.get("skill") != skill
        or not isinstance(origin, str)
        or origin not in ("captured", "designed", "imported")
        or not _digest(digest)
    ):
        raise Error("provenance.identity", "invalid provenance identity")
    if "/" in label or "\\" in label:
        raise Error("provenance.source", "source label must be portable")
    try:
        portable_path(label, authored=True)
    except (Error, OSError, ValueError):
        raise Error("provenance.source", "source label must be portable") from None
    values = [
        skill,
        origin,
        digest,
        label,
        _text(document.get("upstreamRepository"), "upstream repository", 500, empty=True),
        _text(document.get("upstreamRef"), "upstream ref", 256, empty=True),
        _text(document.get("upstreamCandidate"), "upstream candidate", 64, empty=True),
        _text(document.get("rights"), "rights", 128, empty=True),
        _text(document.get("rightsBasis"), "rights basis", 1000, empty=True),
        _text(document.get("license"), "license", 128, empty=True),
    ]
    if values[6] and not _digest(values[6]):
        raise Error("provenance.upstream", "invalid upstream candidate")
    return Provenance(*values)


def _distribution_target(value: object, audience: str) -> JSONObject:
    target_keys = {
        "provider",
        "hostname",
        "nameWithOwner",
        "remote",
        "branch",
        "expectedVisibility",
    }
    if (
        not isinstance(value, dict)
        or set(value) != target_keys
        or value.get("provider") != "github"
    ):
        raise Error("distribution.target", "invalid GitHub target")
    target = cast(JSONObject, value)
    if not all(
        isinstance(target.get(key), str) and target.get(key) for key in target_keys - {"provider"}
    ):
        raise Error("distribution.target", "incomplete GitHub target")
    hostname = cast(str, target["hostname"])
    labels = hostname.split(".")
    repository = cast(str, target["nameWithOwner"])
    repository_parts = repository.split("/")
    remote = cast(str, target["remote"])
    if (
        hostname != hostname.lower()
        or len(hostname) > 253
        or any(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None for label in labels
        )
        or len(repository_parts) != 2
        or any(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?", part) is None
            for part in repository_parts
        )
        or repository_parts[-1].lower().endswith(".git")
        or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?", remote) is None
    ):
        raise Error("distribution.target", "noncanonical GitHub target")
    expected_visibility = "PUBLIC" if audience == "public" else "PRIVATE"
    if target["expectedVisibility"] != expected_visibility:
        raise Error("distribution.target", "target visibility differs from audience")
    branch = cast(str, target["branch"])
    components = branch.split("/")
    if (
        len(branch) > 255
        or re.fullmatch(r"[A-Za-z0-9._/-]+", branch) is None
        or branch == "@"
        or branch.startswith(("-", ".", "/"))
        or branch.endswith((".", "/"))
        or any(item in branch for item in ("..", "//", "@{"))
        or any(component.startswith(".") or component.endswith(".lock") for component in components)
        or any(ord(item) < 33 or ord(item) == 127 or item in "~^:?*[\\" for item in branch)
    ):
        raise Error("distribution.target", "invalid target branch")
    return target


def parse_distribution(document: JSONObject) -> Distribution:
    keys = {
        "schema",
        "kind",
        "id",
        "audience",
        "skills",
        "target",
        "delivery",
        "evidencePolicy",
        "privateDisclosure",
    }
    _keys(document, keys, "distribution")
    identifier, audience, skills = (
        document.get("id"),
        document.get("audience"),
        document.get("skills"),
    )
    if (
        identifier == "verify"
        or not valid_skill_name(identifier)
        or not isinstance(audience, str)
        or audience not in ("private", "public")
    ):
        raise Error("distribution.identity", "invalid distribution identity")
    if (
        not isinstance(skills, list)
        or len(skills) > MAX_SKILLS
        or not all(valid_skill_name(item) for item in skills)
        or skills != sorted(set(cast(list[str], skills)))
    ):
        raise Error("distribution.skills", "skills must be sorted and unique")
    skill_names = cast(list[str], skills)
    target = _distribution_target(document.get("target"), audience)
    delivery = document.get("delivery")
    if (
        not isinstance(delivery, list)
        or not delivery
        or any(not isinstance(item, str) or item not in ("gh", "npx") for item in delivery)
        or len(delivery) != len(set(cast(list[str], delivery)))
    ):
        raise Error("distribution.delivery", "invalid delivery policy")
    evidence = document.get("evidencePolicy")
    if not isinstance(evidence, dict) or set(evidence) != {"routingProfiles", "behaviorProfiles"}:
        raise Error("distribution.evidence", "invalid evidence policy")
    parsed: list[tuple[JSONObject, ...]] = []
    for key in ("routingProfiles", "behaviorProfiles"):
        values = evidence[key]
        if not isinstance(values, list) or not values or len(values) > 16:
            raise Error("distribution.evidence", "invalid required profiles")
        profiles = tuple(parse_profile(item) for item in values)
        if any(
            profile["claim"] == "smoke"
            or (profile["kind"] != "test-suite" and cast(int, profile["trialCount"]) < 3)
            for profile in profiles
        ):
            raise Error(
                "distribution.evidence",
                "release profiles require regression or comparative evidence "
                "and three nondeterministic trials",
            )
        if len({profile_key(item) for item in profiles}) != len(profiles):
            raise Error("distribution.evidence", "duplicate evaluator profile")
        parsed.append(tuple(sorted(profiles, key=profile_key)))
    private = document.get("privateDisclosure")
    if (
        not isinstance(private, str)
        or private not in ("allow", "block")
        or (audience == "public" and private != "block")
    ):
        raise Error("distribution.disclosure", "invalid private disclosure policy")
    return Distribution(
        cast(str, identifier),
        audience,
        tuple(skill_names),
        target,
        tuple(sorted(cast(list[str], delivery))),
        parsed[0],
        parsed[1],
        private,
    )


def _entry(value: object, canonical: bool) -> DisclosureEntry:
    keys = {"id", "class", "match", "value", *(["retired"] if canonical else [])}
    if not isinstance(value, dict) or set(value) != keys:
        raise Error("disclosure.entry", "invalid disclosure entry fields")
    identifier, entry_class, match = value.get("id"), value.get("class"), value.get("match")
    if (
        not valid_skill_name(identifier)
        or not isinstance(entry_class, str)
        or entry_class not in ("credential", "public-disclosure", "note")
        or not isinstance(match, str)
        or match not in ("literal", "glob")
    ):
        raise Error("disclosure.entry", "invalid disclosure entry")
    pattern = _text(value.get("value"), "disclosure value", 256)
    retired = value.get("retired", False)
    if not isinstance(retired, bool) or (
        match == "glob" and pattern.count("*") + pattern.count("?") > 8
    ):
        raise Error("disclosure.pattern", "invalid disclosure pattern")
    return DisclosureEntry(cast(str, identifier), entry_class, match, pattern, retired)


def parse_disclosure(document: JSONObject, *, canonical: bool = True) -> DisclosurePolicy:
    _keys(document, {"schema", "kind", "entries"}, "disclosure policy")
    values = document.get("entries")
    if not isinstance(values, list) or len(values) > 256:
        raise Error("disclosure.entries", "invalid disclosure entries")
    entries = tuple(_entry(item, canonical) for item in values)
    ids = tuple(item.entry_id for item in entries)
    if ids != tuple(sorted(set(ids))):
        raise Error("disclosure.order", "entry ids must be sorted and unique")
    return DisclosurePolicy(entries)


def merge_disclosure(previous: DisclosurePolicy, authored: DisclosurePolicy) -> DisclosurePolicy:
    old, new = {item.entry_id: item for item in previous.entries}, authored.active()
    merged: list[DisclosureEntry] = []
    for identifier in sorted(old.keys() | new.keys()):
        before, after = old.get(identifier), new.get(identifier)
        if before and after and before.digest != after.digest:
            raise Error("disclosure.immutable", f"entry {identifier} changed meaning")
        merged.append(replace(after or cast(DisclosureEntry, before), retired=after is None))
    return DisclosurePolicy(tuple(merged))


def _candidate(path: Path, tree: Tree | None = None) -> tuple[Tree, dict[str, object], str]:
    tree = tree or git_tree(snapshot(path, reject_bytecode=True))
    try:
        file = next(item for item in tree.files if item.path == "SKILL.md")
        fields, body = parse_skill(file.data.decode(errors="strict"))
    except (StopIteration, UnicodeError, FrontmatterError) as exc:
        raise Error("skill.frontmatter", str(exc)) from None
    return tree, fields, body


def load_candidate(path: Path) -> tuple[Tree, dict[str, object], str, str]:
    tree, fields, body = _candidate(path)
    return tree, fields, body, tree_digest(tree, domain=b"remek.candidate.v1\0")


def _records(  # noqa: PLR0912
    root: Path, base: Path
) -> tuple[tuple[JSONObject, ...], tuple[JSONObject, ...], list[Finding]]:
    result: list[tuple[JSONObject, ...]] = []
    findings: list[Finding] = []
    total, count = 0, 0
    for folder, kind in (("evidence", "eval-receipt"), ("approvals", "approval")):
        values: list[JSONObject] = []
        directory = base / folder
        record = "evidence" if folder == "evidence" else "approval"
        if real_directory(directory):
            failures: dict[str, Error] = {}
            try:
                raw_members = _directory_members(directory, failures)
            except Error as exc:
                code = (
                    "governance.bounds" if exc.code == "filesystem.limit" else f"{record}.malformed"
                )
                findings.append(_f(code, exc.message, str(directory.relative_to(root))))
                result.append(tuple(values))
                continue
            members = tuple(item for item in raw_members if not is_private_name(item.name))
            for member in raw_members:
                if is_private_name(member.name):
                    findings.append(
                        _f(
                            "transaction.residue",
                            "transaction residue",
                            str((directory / member.name).relative_to(root)),
                        )
                    )
            remaining = max(0, MAX_RECORDS - count)
            if len(members) > remaining:
                findings.append(
                    _f(
                        "governance.bounds",
                        "immutable record count exceeds bounds",
                        str(directory.relative_to(root)),
                    )
                )
                members = members[:remaining]
            count += len(members)
            for member in members:
                path = directory / member.name
                relative = str(path.relative_to(root))
                if member.name in failures:
                    findings.append(
                        _f(f"{record}.malformed", failures[member.name].message, relative)
                    )
                    continue
                try:
                    data = read(path, limit=MAX_RECORD_BYTES).data
                    total += len(data)
                    if not stat.S_ISREG(member.mode) or member.name != _hash(data) + ".json":
                        raise Error("governance.identity", "invalid content-addressed record")
                    value = parse_canonical_document(data, kind=kind)
                    if kind == "eval-receipt":
                        validate_evidence_intrinsic(value, stored=True)
                    else:
                        validate_approval_intrinsic(value, stored=True)
                    values.append(value)
                except Error as exc:
                    findings.append(_f(f"{record}.malformed", exc.message, relative))
        result.append(tuple(values))
    if total > MAX_SKILL_GOV:
        findings.append(
            _f(
                "governance.bounds",
                "immutable record bytes exceed bounds",
                str(base.relative_to(root)),
            )
        )
    return result[0], result[1], findings


def _governance(  # noqa: PLR0913
    root: Path, config: Config, name: str, candidate: Tree, fields: dict[str, object], body: str
) -> tuple[Skill, list[Finding]]:
    base = checked_path(root, root / ".remek" / "skills" / name)
    policy = parse_policy(load_canonical_document(base / "policy.json", kind="skill-policy"), name)
    provenance = parse_provenance(
        load_canonical_document(base / "provenance.json", kind="provenance"), name
    )
    routing = parse_case_set(
        load_canonical_document(base / "routing-cases.json", kind="routing-cases"), "routing"
    )
    behavior = parse_case_set(
        load_canonical_document(base / "behavior-cases.json", kind="behavior-cases"), "behavior"
    )
    if _hash(read(base / "sources" / provenance.source_label).data) != provenance.source_digest:
        raise Error("provenance.source", "retained source digest differs")
    evidence, approvals, findings = _records(root, base)
    return (
        Skill(
            name,
            root / config.skills_root / name,
            fields,
            body,
            tree_digest(candidate, domain=b"remek.candidate.v1\0"),
            candidate,
            policy,
            provenance,
            routing,
            behavior,
            evidence,
            approvals,
        ),
        findings,
    )


def credential_findings(text: str, path: str) -> list[Finding]:
    return [
        _f(code, "credential-shaped content must be redacted", path)
        for code, pattern in _CREDENTIALS
        if pattern.search(text)
    ]


def _disclosure_match(entry: DisclosureEntry, text: str) -> bool:
    value = text.casefold()
    pattern = entry.value.casefold()
    return pattern in value if entry.match == "literal" else fnmatch.fnmatchcase(value, pattern)


def disclosure_credential_findings(text: str, path: str, policy: DisclosurePolicy) -> list[Finding]:
    return [
        _f("disclosure.credential", f"credential entry {entry.entry_id} matched", path)
        for entry in policy.entries
        if not entry.retired
        and entry.entry_class == "credential"
        and _disclosure_match(entry, text)
    ]


def _governance_document(text: str) -> bool:
    try:
        value = json.loads(text)
    except (ValueError, OverflowError, RecursionError):
        return False
    return (
        isinstance(value, dict)
        and value.get("schema") == SCHEMA
        and isinstance(value.get("kind"), str)
        and value.get("kind") in _GOVERNANCE_KINDS
    )


def _payload_findings(  # noqa: PLR0912
    tree: Tree, fields: dict[str, object], body: str, name: str, base: str
) -> list[Finding]:
    def located(path: str) -> str:
        return path if base == "." else f"{base}/{path}"

    path = located("SKILL.md")
    result: list[Finding] = []
    paths = [item.path for item in tree.files] + [item.path for item in tree.directories]
    result.extend(
        _f("skill.empty-directory", "candidate contains an empty directory", located(item.path))
        for item in tree.directories
        if not any(path.startswith(item.path + "/") for path in paths)
    )
    size = sum(len(item.data) for item in tree.files)
    tokens = sum(
        len(re.findall(r"\w+|[^\w\s]", item.data.decode(errors="ignore"))) for item in tree.files
    )
    if len(tree.files) > MAX_SKILL_FILES or size > MAX_SKILL_BYTES or tokens > MAX_SKILL_TOKENS:
        result.append(_f("skill.budget", "candidate exceeds file, byte, or token budget", base))
    if fields.get("name") != name or not valid_skill_name(name):
        result.append(_f("skill.name", "name must match folder", path))
    description = fields.get("description")
    if (
        not isinstance(description, str)
        or not 1 <= len(description.strip()) <= 1024
        or SKILLS_START in description
        or SKILLS_END in description
    ):
        result.append(_f("skill.description", "invalid description", path))
    if not body.strip() or set(fields) - _FIELDS:
        result.append(_f("skill.frontmatter", "invalid fields or empty body", path))
    try:
        actual = next(item.data for item in tree.files if item.path == "SKILL.md")
        if render_skill(fields, body) != actual:
            result.append(_f("skill.frontmatter-canonical", "SKILL.md is not canonical", path))
    except (StopIteration, FrontmatterError) as exc:
        result.append(_f("skill.frontmatter", str(exc), path))
    metadata = fields.get("metadata", {})
    if not isinstance(metadata, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in metadata.items()
    ):
        result.append(_f("skill.metadata", "metadata must map strings", path))
    elif any(key.startswith("remek-") or key in INJECTED_METADATA_KEYS for key in metadata):
        result.append(_f("skill.metadata", "payload has governed metadata", path))
    for item in tree.files:
        item_path = located(item.path)
        parts = item.path.split("/")
        if ".DS_Store" in parts:
            result.append(
                _f(
                    "skill.residue",
                    "actual payload contains .DS_Store; expected skill files only; "
                    "repair: remove it",
                    item_path,
                )
            )
            continue
        governance = (
            ".remek" in parts
            or item.path in {"remek.json", "release-manifest.json"}
            or any(is_private_name(part) for part in parts)
        )
        try:
            text = item.data.decode(errors="strict")
        except UnicodeError:
            if governance:
                result.append(_f("skill.governance", "payload contains governance", item_path))
            result.append(_f("skill.encoding", "payload must be UTF-8", item_path))
            continue
        if governance or _governance_document(text):
            result.append(_f("skill.governance", "payload contains governance", item_path))
        result.extend(credential_findings(text, item_path))
        found = any(pattern.search(text) for pattern in _PLACEHOLDERS)
        if found and (item.path == "SKILL.md" or item.path.startswith("references/")):
            result.append(_f("skill.placeholder", "unresolved template marker", item_path))
        elif found and item.path.startswith("scripts/"):
            result.append(
                _f("skill.placeholder", "script has template marker", item_path, "warning")
            )
    return result


def _skill_findings(skill: Skill, root: Path) -> list[Finding]:
    result = _payload_findings(
        skill.tree,
        skill.fields,
        skill.body,
        skill.name,
        str(skill.path.relative_to(root)),
    )
    if skill.provenance.origin == "imported" and not all(
        (
            skill.provenance.upstream_repository,
            skill.provenance.upstream_ref,
            skill.provenance.upstream_candidate,
        )
    ):
        result.append(
            _f(
                "provenance.incomplete",
                "imported provenance is incomplete",
                f".remek/skills/{skill.name}/provenance.json",
            )
        )
    return result


def candidate_findings(skill: Skill, root: Path) -> tuple[Finding, ...]:
    return tuple(_skill_findings(skill, root))


def loaded_bootstrap() -> bytes:
    path = os.environ.get("REMEK_BOOTSTRAP")
    if not path:
        raise Error("toolchain.bootstrap", "loaded bootstrap identity is unavailable")
    return read(Path(path)).data


def _toolchain(root: Path) -> tuple[Path | None, list[Finding]]:
    present = [
        path
        for path in (root / ".remek/toolchain", root / "skills/remek/toolchain")
        if real_directory(path)
    ]
    if len(present) != 1:
        return None, [_f("repo.toolchain", "exactly one toolchain is required", ".remek/toolchain")]
    path, result = present[0], []
    try:
        tree = git_tree(snapshot(path, reject_bytecode=True))
        files_by_path = {item.path: item for item in tree.files}
        manifest = files_by_path.get("manifest.json")
        actual_files: JSONObject = {}
        for item in tree.files:
            if item.path != "manifest.json":
                actual_files[item.path] = [item.mode, _hash(item.data)]
        value: JSONObject = {
            "schema": SCHEMA,
            "kind": "toolchain-manifest",
            "rootMode": tree.root_mode,
            "directories": {item.path: item.mode for item in tree.directories},
            "files": actual_files,
        }
        expected = (
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        required = {"scripts/cli.py", "assets/gate"}
        if (
            manifest is None
            or manifest.mode != 0o644
            or len(manifest.data) > 256 << 10
            or manifest.data != expected
            or required - actual_files.keys()
        ):
            raise Error("toolchain.identity", "toolchain differs from manifest")
    except Error as exc:
        result.append(_f(exc.code, exc.message, str(path.relative_to(root))))
        return path, result
    for name, source in _SHIMS.items():
        try:
            matches = read(root / name).data == files_by_path[source].data and bool(
                (root / name).stat().st_mode & stat.S_IXUSR
            )
        except (OSError, Error, KeyError):
            matches = False
        if not matches:
            result.append(_f("repo.shim", f"root {name} differs", name, repairable=True))
    try:
        matches = read(root / "remek").data == loaded_bootstrap() and bool(
            (root / "remek").stat().st_mode & stat.S_IXUSR
        )
    except (OSError, Error):
        matches = False
    if not matches:
        result.append(_f("repo.shim", "root remek differs", "remek", repairable=True))
    return path, result


def _load_distributions(
    root: Path, disclosure: DisclosurePolicy | None
) -> tuple[tuple[Distribution, ...], list[Finding], int]:
    directory, values, issues, total = root / ".remek/distributions", [], [], 0
    if not real_directory(directory):
        return (), [], 0
    members = directory_members(directory)
    durable = [item for item in members if not is_private_name(item.name)]
    if len(durable) > MAX_RECORDS:
        return (
            (),
            [_f("governance.bounds", "distribution count exceeds bounds", ".remek/distributions")],
            0,
        )
    for member in members:
        if is_private_name(member.name):
            issues.append(
                _f(
                    "transaction.residue",
                    "transaction residue",
                    f".remek/distributions/{member.name}",
                )
            )
            continue
        try:
            data = read(directory / member.name, limit=MAX_RECORD_BYTES).data
            total += len(data)
            if total > MAX_SKILL_GOV:
                raise Error("governance.bounds", "distribution bytes exceed bounds")
            value = parse_distribution(parse_canonical_document(data, kind="distribution"))
            if not stat.S_ISREG(member.mode) or member.name != value.distribution_id + ".json":
                raise Error("distribution.file", "invalid distribution filename")
            values.append(value)
            text, path = data.decode(), f".remek/distributions/{member.name}"
            issues.extend(credential_findings(text, path))
            if disclosure:
                issues.extend(disclosure_credential_findings(text, path, disclosure))
        except Error as exc:
            issues.append(_f(exc.code, exc.message, f".remek/distributions/{member.name}"))
    return tuple(sorted(values, key=lambda item: item.distribution_id)), issues, total


def _owned_layout(root: Path, config: Config | None, issues: _Findings) -> None:
    def check(directory: Path, allowed: dict[str, bool] | None = None) -> None:
        if not real_directory(directory):
            return
        for member in directory_members(directory):
            path = str((directory / member.name).relative_to(root))
            if is_private_name(member.name):
                issues.append(_f("transaction.residue", "transaction residue", path))
                continue
            expected_directory = allowed.get(member.name) if allowed is not None else None
            if allowed is not None and (
                expected_directory is None or expected_directory != stat.S_ISDIR(member.mode)
            ):
                issues.append(_f("governance.layout", "unknown or invalid owned entry", path))

    check(
        root / ".remek",
        {
            "disclosure-policy.json": False,
            "distributions": True,
            "skills": True,
            "toolchain": True,
        },
    )
    governed = set(config.governed_skills) if config else set()
    check(root / ".remek/skills", {name: True for name in governed})
    allowed_skill = {
        "policy.json": False,
        "provenance.json": False,
        "routing-cases.json": False,
        "behavior-cases.json": False,
        "sources": True,
        "evidence": True,
        "approvals": True,
    }
    for name in governed:
        base = root / ".remek/skills" / name
        check(base, allowed_skill)
        directory = base / "sources"
        if real_directory(directory):
            check(directory, {item.name: False for item in directory_members(directory)})
    if config:
        allowed = {name: True for name in governed} if config.skills_root == "skills" else None
        check(root / config.skills_root, allowed)
    check(root)


def _tree_residue(tree: Tree, base: str) -> list[Finding]:
    paths = [item.path for item in tree.files] + [item.path for item in tree.directories]
    return [
        _f("transaction.residue", "transaction residue", f"{base}/{path}")
        for path in paths
        if any(is_private_name(part) for part in path.split("/"))
    ]


def inspect_repository(root: Path) -> RepositoryInspection:  # noqa: PLR0912, PLR0915
    root, issues = checked(root), _Findings()
    config: Config | None = None
    disclosure: DisclosurePolicy | None = None
    try:
        config = load_config(root)
        if read(root / CONFIG_NAME).data != config.render():
            issues.append(
                _f("repo.config-canonical", "config is not canonical", CONFIG_NAME, repairable=True)
            )
    except Error as exc:
        issues.append(_f(exc.code, exc.message, CONFIG_NAME))
    bundle, toolchain_findings = _toolchain(root)
    issues.extend(toolchain_findings)
    disclosure_size = 0
    try:
        disclosure_data = read(root / DISCLOSURE_PATH, limit=MAX_RECORD_BYTES).data
        disclosure_size = len(disclosure_data)
        disclosure = parse_disclosure(
            parse_canonical_document(disclosure_data, kind="disclosure-policy")
        )
        issues.extend(credential_findings(disclosure_data.decode(), DISCLOSURE_PATH))
    except (Error, UnicodeError) as exc:
        issues.append(_f("disclosure.invalid", str(exc), DISCLOSURE_PATH))
    distributions, distribution_findings, distribution_size = _load_distributions(root, disclosure)
    issues.extend(distribution_findings)
    skills: list[Skill] = []
    governance_total = disclosure_size + distribution_size
    if config:
        for name in config.governed_skills:
            path = root / config.skills_root / name
            try:
                tree, fields, body = _candidate(checked_path(root, path))
                issues.extend(_tree_residue(tree, str(path.relative_to(root))))
                skill, record_findings = _governance(root, config, name, tree, fields, body)
                skills.append(skill)
                issues.extend(record_findings)
                issues.extend(_skill_findings(skill, root))
                if disclosure:
                    for item in skill.tree.files:
                        with suppress(UnicodeError):
                            issues.extend(
                                disclosure_credential_findings(
                                    item.data.decode(),
                                    str(skill.path.relative_to(root) / item.path),
                                    disclosure,
                                )
                            )
                governance = snapshot(root / ".remek/skills" / name, reject_bytecode=True)
                issues.extend(_tree_residue(governance, f".remek/skills/{name}"))
                governance_size = sum(len(item.data) for item in governance.files)
                governance_total += governance_size
                if governance_size > MAX_SKILL_GOV:
                    issues.append(
                        _f(
                            "governance.bounds",
                            "skill governance exceeds bounds",
                            f".remek/skills/{name}",
                        )
                    )
                for item in governance.files:
                    with suppress(UnicodeError):
                        text = item.data.decode()
                        issues.extend(
                            credential_findings(text, f".remek/skills/{name}/{item.path}")
                        )
                        if disclosure:
                            issues.extend(
                                disclosure_credential_findings(
                                    text, f".remek/skills/{name}/{item.path}", disclosure
                                )
                            )
            except Error as exc:
                issues.append(_f(exc.code, exc.message, str(path.relative_to(root))))
    if governance_total > MAX_REPO_GOV:
        issues.append(_f("governance.bounds", "repository governance exceeds bounds", ".remek"))
    by_name = {item.name: item for item in skills}
    for distribution in distributions:
        for name in distribution.skills:
            skill_member = by_name.get(name)
            if skill_member is None:
                issues.append(
                    _f(
                        "distribution.skill",
                        f"missing skill {name}",
                        f".remek/distributions/{distribution.distribution_id}.json",
                    )
                )
            elif skill_member.policy.exposure == "source-only" or (
                distribution.audience == "public"
                and skill_member.policy.exposure != "public-eligible"
            ):
                issues.append(
                    _f(
                        "distribution.exposure",
                        f"audience exceeds {name} exposure",
                        f".remek/distributions/{distribution.distribution_id}.json",
                    )
                )
    if (
        bundle == root / "skills/remek/toolchain"
        and config
        and (config.skills_root, config.governed_skills) != ("skills", ("remek",))
    ):
        issues.append(_f("repo.producer", "producer must govern only remek", CONFIG_NAME))
    if config and len(skills) == len(config.governed_skills):
        try:
            if readme_change(root, tuple(skills)):
                issues.append(
                    _f("repo.readme", "README inventory is stale", "README.md", repairable=True)
                )
        except Error as exc:
            issues.append(_f("repo.readme", exc.message, "README.md"))
    _owned_layout(root, config, issues)
    return RepositoryInspection(
        root,
        config,
        bundle,
        tuple(skills),
        distributions,
        disclosure,
        issues.ordered(),
    )


def _plans(inspection: RepositoryInspection, skill: Skill, kind: str) -> list[EvidencePlan]:
    if kind == "behavior":
        return [evaluation_plan(inspection, skill.name, kind, None)]
    distributions: list[str | None] = [
        item.distribution_id for item in inspection.distributions if skill.name in item.skills
    ]
    return [
        evaluation_plan(inspection, skill.name, kind, distribution)
        for distribution in distributions or [None]
    ]


def _record_path(skill: Skill, folder: str, document: JSONObject) -> str:
    kind = cast(str, document["kind"])
    data = render(
        kind,
        {key: value for key, value in document.items() if key not in {"schema", "kind"}},
    )
    return f".remek/skills/{skill.name}/{folder}/{_hash(data)}.json"


def repository_findings(inspection: RepositoryInspection) -> tuple[Finding, ...]:
    issues = list(inspection.issues)
    for skill in inspection.skills:
        for kind in ("routing", "behavior"):
            passing = False
            for receipt in (item for item in skill.evidence if item.get("evidenceKind") == kind):
                errors: list[Error] = []
                for plan in _plans(inspection, skill, kind):
                    try:
                        current, passed, _ = receipt_status(receipt, plan)
                        passing |= current and passed
                    except Error as exc:
                        errors.append(exc)
                malformed = next(
                    (error for error in errors if error.code != "evidence.stale"), None
                )
                if malformed:
                    issues.append(
                        _f(
                            "evidence.malformed",
                            malformed.message,
                            _record_path(skill, "evidence", receipt),
                        )
                    )
            if not passing:
                context = (
                    "; expected while draft/source-only, required by release policy before release"
                    if skill.policy.lifecycle == "draft" and skill.policy.exposure == "source-only"
                    else "; required by release policy before release"
                )
                issues.append(
                    _f(
                        f"evidence.{kind}",
                        f"current passing {kind} evidence is missing{context}",
                        f".remek/skills/{skill.name}/evidence",
                        "warning",
                    )
                )
    return tuple(sorted(set(issues)))


def disclosure_matches(
    skill: Skill, policy: DisclosurePolicy, distribution: Distribution
) -> tuple[tuple[DisclosureEntry, str], ...]:
    result: list[tuple[DisclosureEntry, str]] = []
    seen: set[tuple[str, str]] = set()
    surfaces = [(skill.name, skill.name)]
    surfaces.extend((item.path, item.path) for item in skill.tree.directories)
    for file in skill.tree.files:
        try:
            text = file.data.decode().casefold()
        except UnicodeError:
            text = ""
        surfaces.extend(((file.path, file.path), (file.path, text)))
    for path, text in surfaces:
        for entry in policy.entries:
            matched = _disclosure_match(entry, text)
            blocks = (
                entry.entry_class == "credential"
                or distribution.audience == "public"
                or distribution.private_disclosure == "block"
            )
            key = (entry.entry_id, path)
            if (
                not entry.retired
                and entry.entry_class != "note"
                and matched
                and blocks
                and key not in seen
            ):
                result.append((entry, path))
                seen.add(key)
    return tuple(result)


def evaluation_plan(
    inspection: RepositoryInspection,
    skill_name: str,
    evidence_kind: str,
    dist: str | None,
) -> EvidencePlan:
    skill = inspection.skill(skill_name)
    if evidence_kind == "behavior":
        if dist is not None:
            raise Error("evidence.distribution", "behavior evidence is not distribution-bound")
        return EvidencePlan(skill.name, skill.digest, skill.behavior_cases, None)
    if evidence_kind != "routing":
        raise Error("evidence.kind", "kind must be routing or behavior")
    members = inspection.skills
    if dist:
        distribution = inspection.distribution(dist)
        if skill_name not in distribution.skills:
            raise Error("evidence.distribution", "skill is outside the distribution")
        by_name = {item.name: item for item in inspection.skills}
        members = tuple(by_name[name] for name in distribution.skills if name in by_name)
    catalog = tuple((item.name, item.description) for item in members)
    return EvidencePlan(
        skill.name,
        skill.digest,
        skill.routing_cases,
        routing_catalog_digest(catalog),
        dist,
    )


def approval_template(inspection: RepositoryInspection, dist: str, skill_name: str) -> JSONObject:
    distribution, skill = inspection.distribution(dist), inspection.skill(skill_name)
    if skill.name not in distribution.skills:
        raise Error("approval.skill", "skill not selected; nothing prepared; correct distribution")
    return {
        "schema": SCHEMA,
        "kind": "approval",
        "skill": skill.name,
        "candidate": skill.digest,
        "provenanceDigest": skill.provenance.digest,
        "distribution": distribution.distribution_id,
        "distributionContextDigest": distribution.context_digest,
        "audience": distribution.audience,
        "target": distribution.target,
        "delivery": list(distribution.delivery),
        "rightsReviewed": False,
        "proprietaryContentReviewed": False,
        "publicIrreversibilityAcknowledged": False,
        "exceptions": [],
        "reviewer": "",
        "reviewedOn": "",
    }


def validate_approval_intrinsic(document: JSONObject, *, stored: bool = False) -> JSONObject:
    keys = {
        "schema",
        "kind",
        "skill",
        "candidate",
        "provenanceDigest",
        "distribution",
        "distributionContextDigest",
        "audience",
        "target",
        "delivery",
        "rightsReviewed",
        "proprietaryContentReviewed",
        "publicIrreversibilityAcknowledged",
        "exceptions",
        "reviewer",
        "reviewedOn",
    }
    skill, distribution, audience = (
        document.get("skill"),
        document.get("distribution"),
        document.get("audience"),
    )
    if (
        document.get("schema") != SCHEMA
        or document.get("kind") != "approval"
        or set(document) != keys
        or not valid_skill_name(skill)
        or distribution == "verify"
        or not valid_skill_name(distribution)
        or not isinstance(audience, str)
        or audience not in ("private", "public")
        or not all(
            _digest(document.get(key))
            for key in ("candidate", "provenanceDigest", "distributionContextDigest")
        )
    ):
        raise Error("approval.shape", "approval fields are intrinsically invalid")
    _distribution_target(document.get("target"), audience)
    delivery = document.get("delivery")
    if (
        not isinstance(delivery, list)
        or not delivery
        or any(not isinstance(item, str) or item not in ("gh", "npx") for item in delivery)
        or delivery != sorted(set(cast(list[str], delivery)))
    ):
        raise Error("approval.shape", "approval delivery is invalid")
    booleans = (
        document.get("rightsReviewed"),
        document.get("proprietaryContentReviewed"),
        document.get("publicIrreversibilityAcknowledged"),
    )
    if any(type(value) is not bool for value in booleans):
        raise Error("approval.shape", "approval review fields must be booleans")
    if stored and (booleans[0] is not True or booleans[1] is not True):
        raise Error("approval.incomplete", "stored approval is internally incomplete")
    if audience == "public" and booleans[2] is not True:
        raise Error("approval.incomplete", "public approval lacks irreversibility acknowledgement")
    reviewer = _text(document.get("reviewer"), "reviewer", 128)
    reviewed_on = _text(document.get("reviewedOn"), "review date", 10)
    try:
        parsed_date = date.fromisoformat(reviewed_on)
    except ValueError:
        parsed_date = None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", reviewed_on) is None or parsed_date is None:
        raise Error("approval.date", "reviewedOn invalid; nothing recorded; use YYYY-MM-DD")
    exceptions = document.get("exceptions")
    if not isinstance(exceptions, list) or len(exceptions) > 64:
        raise Error("approval.exceptions", "exception list is invalid")
    identifiers: list[str] = []
    for value in exceptions:
        allowed = {"id", "digest"} if stored else {"id"}
        if (
            not isinstance(value, dict)
            or set(value) not in ({"id", "digest"}, allowed)
            or not valid_skill_name(value.get("id"))
            or ("digest" in value and not _digest(value.get("digest")))
        ):
            raise Error("approval.exceptions", "exception entry is intrinsically invalid")
        identifiers.append(cast(str, value["id"]))
    if len(identifiers) != len(set(identifiers)) or (stored and identifiers != sorted(identifiers)):
        raise Error("approval.exceptions", "exception ids must be unique and normalized")
    return {**document, "reviewer": reviewer, "reviewedOn": reviewed_on}


def validate_approval(
    document: JSONObject, inspection: RepositoryInspection, dist: str, skill_name: str
) -> JSONObject:
    document = validate_approval_intrinsic(document)
    template = approval_template(inspection, dist, skill_name)
    if set(document) != set(template):
        raise Error(
            "approval.keys", "approval fields invalid; nothing recorded; use fresh template"
        )
    bound = {
        "schema",
        "kind",
        "skill",
        "candidate",
        "provenanceDigest",
        "distribution",
        "distributionContextDigest",
        "audience",
        "target",
        "delivery",
    }
    if any(document.get(key) != template.get(key) for key in bound):
        raise Error("approval.stale", "approval stale; nothing recorded; prepare anew")
    distribution = inspection.distribution(dist)
    if (
        document.get("rightsReviewed") is not True
        or document.get("proprietaryContentReviewed") is not True
        or (
            distribution.audience == "public"
            and document.get("publicIrreversibilityAcknowledged") is not True
        )
    ):
        raise Error("approval.incomplete", "review incomplete; nothing recorded; complete it")
    reviewer, reviewed_on = cast(str, document["reviewer"]), cast(str, document["reviewedOn"])
    exceptions, active, normalized, seen = (
        document.get("exceptions"),
        inspection.disclosure.active() if inspection.disclosure else {},
        [],
        set(),
    )
    if not isinstance(exceptions, list) or len(exceptions) > 64:
        raise Error("approval.exceptions", "exception list invalid; nothing recorded; correct it")
    for value in exceptions:
        if not isinstance(value, dict) or set(value) not in ({"id"}, {"id", "digest"}):
            raise Error("approval.exceptions", "exception invalid; nothing recorded; correct it")
        identifier = value.get("id")
        if not isinstance(identifier, str) or identifier in seen or identifier not in active:
            raise Error(
                "approval.exceptions", "exception unknown/repeated; nothing recorded; correct it"
            )
        entry = active[identifier]
        if entry.entry_class == "credential":
            raise Error(
                "approval.exceptions", "credential cannot be excepted; nothing recorded; remove it"
            )
        digest = entry.digest
        if value.get("digest", digest) != digest:
            raise Error("approval.exceptions", "exception stale; nothing recorded; refresh digest")
        normalized.append({"id": identifier, "digest": digest})
        seen.add(identifier)
    return cast(
        JSONObject,
        {
            **document,
            "exceptions": sorted(normalized, key=lambda item: cast(str, item["id"])),
            "reviewer": reviewer,
            "reviewedOn": reviewed_on,
        },
    )


def _approval(
    skill: Skill,
    inspection: RepositoryInspection,
    distribution: Distribution,
    required_exceptions: set[str],
) -> JSONObject | None:
    for value in skill.approvals:
        try:
            current = validate_approval(value, inspection, distribution.distribution_id, skill.name)
            exceptions = {
                cast(str, item["id"]) for item in cast(list[JSONObject], current["exceptions"])
            }
            if required_exceptions <= exceptions:
                return current
        except Error:
            pass
    return None


def release_findings(  # noqa: PLR0912
    inspection: RepositoryInspection, dist: str
) -> tuple[Finding, ...]:
    checked_findings = repository_findings(inspection)
    malformed = tuple(
        item
        for item in checked_findings
        if item.severity == "error" and item.code in {"evidence.malformed", "approval.malformed"}
    )
    if malformed:
        return tuple(sorted(set(malformed)))
    issues = [item for item in checked_findings if item.severity == "error"]
    distribution = inspection.distribution(dist)
    by_name = {item.name: item for item in inspection.skills}
    members = tuple(by_name[name] for name in distribution.skills if name in by_name)
    if inspection.disclosure is None:
        return (
            *issues,
            _f("release.disclosure", "missing; source unchanged; restore policy", DISCLOSURE_PATH),
        )
    for skill in members:
        base = f".remek/skills/{skill.name}"
        policy = f"{base}/policy.json"
        if skill.policy.lifecycle != "ready":
            issues.append(
                _f("release.lifecycle", "not ready; source unchanged; accept ready", policy)
            )
        if skill.policy.exposure == "source-only" or (
            distribution.audience == "public" and skill.policy.exposure != "public-eligible"
        ):
            issues.append(
                _f("release.exposure", "blocked; source unchanged; accept eligible", policy)
            )
        if not all(
            (skill.provenance.rights, skill.provenance.rights_basis, skill.provenance.license)
        ):
            issues.append(
                _f("release.rights", "rights or license is incomplete", f"{base}/provenance.json")
            )
        candidate_license = skill.fields.get("license")
        if distribution.audience == "public" and (
            not isinstance(candidate_license, str)
            or not candidate_license.strip()
            or candidate_license != skill.provenance.license
        ):
            actual_license = (
                repr(candidate_license)
                if isinstance(candidate_license, str) and len(candidate_license) <= 128
                else "missing or invalid"
            )
            issues.append(
                _f(
                    "release.license",
                    f"actual candidate license is {actual_license}; expected "
                    f"{skill.provenance.license!r} from reviewed provenance; repair: set "
                    "SKILL.md frontmatter license to that reviewed value, or revise provenance "
                    "through accept if it is wrong",
                    str(skill.path.relative_to(inspection.root) / "SKILL.md"),
                )
            )
        matches = disclosure_matches(skill, inspection.disclosure, distribution)
        required_exceptions = {
            entry.entry_id for entry, _ in matches if entry.entry_class != "credential"
        }
        approval = _approval(skill, inspection, distribution, required_exceptions)
        if approval is None:
            issues.append(
                _f(
                    "release.approval",
                    "missing; source unchanged; plan/record",
                    base + "/approvals",
                )
            )
            exception_ids: set[str] = set()
        else:
            exception_ids = {
                cast(str, item["id"]) for item in cast(list[JSONObject], approval["exceptions"])
            }
        for entry, path in matches:
            if entry.entry_class == "credential" or entry.entry_id not in exception_ids:
                resolution = "redact" if entry.entry_class == "credential" else "approve exception"
                issues.append(
                    _f(
                        "release.disclosure",
                        f"entry {entry.entry_id} blocked; source unchanged; {resolution}",
                        f"{skill.path.relative_to(inspection.root)}/{path}",
                    )
                )
        for kind, required in (
            ("routing", distribution.routing_profiles),
            ("behavior", distribution.behavior_profiles),
        ):
            passing: set[str] = set()
            plan = evaluation_plan(
                inspection, skill.name, kind, dist if kind == "routing" else None
            )
            for receipt in (item for item in skill.evidence if item.get("evidenceKind") == kind):
                try:
                    current, passed, identity = receipt_status(receipt, plan)
                    if current and passed:
                        passing.add(identity)
                except Error:
                    pass
            if any(profile_key(profile) not in passing for profile in required):
                issues.append(
                    _f(
                        f"release.evidence.{kind}",
                        f"{kind} evidence missing; source unchanged; record fresh proof",
                        f"{base}/evidence",
                    )
                )
    return tuple(sorted(set(issues)))


def readme_change(root: Path, skills: tuple[Skill, ...]) -> Change | None:
    rows = [SKILLS_START, "| Skill | Description |", "| --- | --- |"]
    for item in skills:
        description = item.description.replace("|", "\\|").replace("\n", " ").strip()
        rows.append(f"| `{item.name}` | {description} |")
    rows.append(SKILLS_END)
    path = root / "README.md"
    current = read(path).data if exists(path) else None
    try:
        text = current.decode() if current is not None else f"# {root.name}\n"
    except UnicodeDecodeError:
        raise Error("repo.readme", "README is not UTF-8") from None
    start, end = text.count(SKILLS_START), text.count(SKILLS_END)
    start_index, end_index = text.find(SKILLS_START), text.find(SKILLS_END)
    if (start, end) == (0, 0):
        updated = text.rstrip() + "\n\n## Skills\n\n" + "\n".join(rows) + "\n"
    elif start == end == 1 and start_index < end_index:
        updated = text[:start_index] + "\n".join(rows) + text[end_index + len(SKILLS_END) :]
    else:
        raise Error("repo.readme", "malformed README markers")
    data = updated.encode()
    if current == data:
        return None
    return write_change(root, path, data, "regenerate governed skill inventory")


def repair_changes(inspection: RepositoryInspection) -> tuple[Change, ...]:
    changes: list[Change] = []
    if inspection.config:
        changes.append(
            write_change(
                inspection.root,
                inspection.root / CONFIG_NAME,
                inspection.config.render(),
                "canonicalize config",
            )
        )
    if inspection.bundle:
        files = {item.path: item for item in snapshot(inspection.bundle).files}
        for name, source in _SHIMS.items():
            if source in files:
                changes.append(
                    write_change(
                        inspection.root,
                        inspection.root / name,
                        files[source].data,
                        f"restore {name} shim",
                        mode=0o755,
                    )
                )
        changes.append(
            write_change(
                inspection.root,
                inspection.root / "remek",
                loaded_bootstrap(),
                "restore remek shim",
                mode=0o755,
            )
        )
    try:
        readme = readme_change(inspection.root, inspection.skills)
        if readme:
            changes.append(readme)
    except Error:
        pass
    return tuple(item for item in changes if item.expected != item.after)


def audit_repository(root: Path) -> tuple[Finding, ...]:
    root, candidates = checked(root), []
    if exists(root / "SKILL.md"):
        candidates.append(root)
    for relative in ("skills", ".agents/skills"):
        directory = root / relative
        if real_directory(directory):
            candidates.extend(
                directory / item.name
                for item in directory_members(directory)
                if stat.S_ISDIR(item.mode) and exists(directory / item.name / "SKILL.md")
            )
    candidates = sorted(set(candidates))
    if not candidates:
        return (_f("audit.empty", "no ordinary Agent Skill payload was found", "."),)
    issues = _Findings()
    if len(candidates) > MAX_SKILLS:
        issues.append(_f("audit.limit", f"audit found more than {MAX_SKILLS} skills", "."))
    for path in candidates[:MAX_SKILLS]:
        label = str(path.relative_to(root)) or "."
        boundary = "tree"
        try:
            tree = git_tree(snapshot(path, reject_bytecode=True))
            issues.extend(
                finding
                for item in tree.files
                for finding in credential_findings(
                    item.data.decode(errors="ignore"), str(Path(label) / item.path)
                )
            )
            boundary = "frontmatter"
            tree, fields, body = _candidate(path, tree)
        except Error:
            issues.append(
                _f(
                    "audit.profile-unsupported",
                    f"unsupported deterministic {boundary}",
                    label,
                )
            )
            continue
        name, message = fields.get("name"), ""
        if name != path.name or not valid_skill_name(name):
            repair = (
                "run accept on the parent scaffold workspace"
                if path.name == "candidate" and exists(path.parent / "workspace.json")
                else "rename the folder to match the frontmatter name or correct that name"
            )
            message = (
                f"frontmatter name must match folder and be lowercase hyphenated; repair: {repair}"
            )
        elif not isinstance(fields.get("description"), str):
            message = (
                "actual description is missing or not text; expected non-empty text; repair: "
                "set description in canonical SKILL.md frontmatter"
            )
        elif not body.strip():
            message = (
                "actual SKILL.md body is empty; expected reviewed instructions; repair: add them"
            )
        if message:
            issues.append(_f("audit.open-invalid", message, label))
            continue
        metadata = fields.get("metadata", {})
        injected = (
            sorted(key for key in metadata if key in INJECTED_METADATA_KEYS)
            if isinstance(metadata, dict)
            else []
        )
        if injected:
            issues.append(
                _f(
                    "audit.metadata",
                    "installer metadata normalized by imported scaffold: " + ", ".join(injected),
                    f"{label}/SKILL.md",
                    "info",
                )
            )
        profile_findings = _payload_findings(tree, fields, body, path.name, label)
        issues.extend(profile_findings)
        incompatible = any(item.severity == "error" for item in profile_findings)
        issues.append(
            _f(
                "audit.remek-incompatible" if incompatible else "audit.compatible",
                "structurally valid open format is outside remek profile"
                if incompatible
                else "structurally valid under open and remek profiles",
                label,
                "warning" if incompatible else "info",
            )
        )
    return issues.ordered()
