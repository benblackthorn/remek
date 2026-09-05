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
from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard, cast

from .contract import (
    SCHEMA,
    JSONObject,
    load_document,
    parse_canonical_document,
    parse_document,
    render_document as render,
)
from .evaluation import (
    CaseSet,
    EvaluationPlan,
    parse_case_set,
    parse_profile,
    profile_key,
    evaluation_status,
    routing_catalog_digest,
    validate_evaluation_intrinsic,
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
from .frontmatter import FrontmatterError, parse_skill
from .model import Error, Finding, Severity, valid_skill_name

CONFIG_NAME = "remek.json"
DISCLOSURE_PATH = ".remek/disclosure-policy.json"
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
MAX_EVALUATION_BYTES = 512 << 10
MAX_FINDINGS = 4096
MAX_SKILLS, MAX_SKILL_FILES, MAX_SKILL_BYTES, MAX_SKILL_TOKENS = 128, 256, 8388608, 75000
_FIELDS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
_GOVERNANCE_KINDS = {
    "approval",
    "behavior-cases",
    "disclosure-policy",
    "distribution",
    "eval-receipt",
    "eval-evidence",
    "skill-record",
    "evaluation",
    "release-review",
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
_EXPOSURES = {"source-only", "private-only", "public-eligible"}
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
class Provenance:
    origin: str
    source: JSONObject | None
    source_note: str
    upstream_repository: str
    upstream_ref: str
    rights: str
    rights_basis: str
    license: str

    def as_dict(self) -> JSONObject:
        return {
            "origin": self.origin,
            "source": self.source,
            "sourceNote": self.source_note,
            "upstreamRepository": self.upstream_repository,
            "upstreamRef": self.upstream_ref,
            "rights": self.rights,
            "rightsBasis": self.rights_basis,
            "license": self.license,
        }


@dataclass(frozen=True)
class SkillRecord:
    skill: str
    exposure: str
    provenance: Provenance
    routing_cases: CaseSet
    behavior_cases: CaseSet

    @property
    def digest(self) -> str:
        return _hash(self.render())

    def render(self) -> bytes:
        return render(
            "skill-record",
            {
                "skill": self.skill,
                "exposure": self.exposure,
                "provenance": self.provenance.as_dict(),
                "cases": {
                    "routing": json.loads(self.routing_cases.render())["cases"],
                    "behavior": json.loads(self.behavior_cases.render())["cases"],
                },
            },
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
    active_review: str | None = None

    def subject_fields(self) -> JSONObject:
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
        result["skills"] = list(self.skills)
        return result

    def render(self) -> bytes:
        return render("distribution", {**self.subject_fields(), "activeReview": self.active_review})


@dataclass(frozen=True)
class DisclosureEntry:
    entry_id: str
    entry_class: str
    match: str
    value: str

    @property
    def digest(self) -> str:
        return _hash(render("disclosure-entry", self.as_dict()))

    def as_dict(self) -> JSONObject:
        return {
            "id": self.entry_id,
            "class": self.entry_class,
            "match": self.match,
            "value": self.value,
        }


@dataclass(frozen=True)
class DisclosurePolicy:
    entries: tuple[DisclosureEntry, ...]

    def render(self) -> bytes:
        return render("disclosure-policy", {"entries": [item.as_dict() for item in self.entries]})

    def active(self) -> dict[str, DisclosureEntry]:
        return {item.entry_id: item for item in self.entries}


@dataclass(frozen=True)
class Skill:
    name: str
    path: Path
    fields: dict[str, object]
    body: str
    digest: str
    tree: Tree
    record: SkillRecord
    evidence: tuple[JSONObject, ...]

    @property
    def provenance(self) -> Provenance:
        return self.record.provenance

    @property
    def routing_cases(self) -> CaseSet:
        return self.record.routing_cases

    @property
    def behavior_cases(self) -> CaseSet:
        return self.record.behavior_cases

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
    reviews: tuple[JSONObject, ...] = ()

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


def parse_skill_record(document: JSONObject, skill: str) -> SkillRecord:
    _keys(document, {"schema", "kind", "skill", "exposure", "provenance", "cases"}, "skill record")
    exposure = document.get("exposure")
    if (
        document.get("schema") != SCHEMA
        or document.get("kind") != "skill-record"
        or document.get("skill") != skill
        or not valid_skill_name(skill)
        or not isinstance(exposure, str)
        or exposure not in _EXPOSURES
    ):
        raise Error("record.identity", "invalid skill record identity or exposure")
    value = document.get("provenance")
    keys = {
        "origin",
        "source",
        "sourceNote",
        "upstreamRepository",
        "upstreamRef",
        "rights",
        "rightsBasis",
        "license",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise Error("provenance.shape", "invalid provenance fields")
    origin, source = value.get("origin"), value.get("source")
    if not isinstance(origin, str) or origin not in {"captured", "designed", "imported"}:
        raise Error("provenance.identity", "invalid provenance origin")
    if source is not None:
        if (
            not isinstance(source, dict)
            or set(source) != {"path", "type", "digest"}
            or not isinstance(source.get("type"), str)
            or source["type"] not in {"file", "tree"}
            or not _digest(source.get("digest"))
            or not isinstance(source.get("path"), str)
        ):
            raise Error("provenance.source", "invalid retained source descriptor")
        path = portable_path(cast(str, source["path"]), authored=True)
        if not str(path).startswith("sources/"):
            raise Error("provenance.source", "retained source must be strictly inside sources/")
    provenance = Provenance(
        origin,
        source,
        _text(value.get("sourceNote"), "source note", 1000),
        _text(value.get("upstreamRepository"), "upstream repository", 500, empty=True),
        _text(value.get("upstreamRef"), "upstream ref", 256, empty=True),
        _text(value.get("rights"), "rights", 128, empty=True),
        _text(value.get("rightsBasis"), "rights basis", 1000, empty=True),
        _text(value.get("license"), "license", 128, empty=True),
    )
    cases = document.get("cases")
    if not isinstance(cases, dict) or set(cases) != {"routing", "behavior"}:
        raise Error("cases.shape", "skill record needs routing and behavior case arrays")
    parsed = [
        parse_case_set({"schema": SCHEMA, "kind": f"{kind}-cases", "cases": cases[kind]}, kind)
        for kind in ("routing", "behavior")
    ]
    return SkillRecord(skill, exposure, provenance, parsed[0], parsed[1])


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
        "activeReview",
    }
    _keys(document, keys, "distribution")
    if document.get("schema") != SCHEMA or document.get("kind") != "distribution":
        raise Error("distribution.shape", "invalid distribution schema or kind")
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
    active_review = document.get("activeReview")
    if active_review is not None and not _digest(active_review):
        raise Error("distribution.review", "activeReview must be null or one SHA-256")
    return Distribution(
        cast(str, identifier),
        audience,
        tuple(skill_names),
        target,
        tuple(sorted(cast(list[str], delivery))),
        parsed[0],
        parsed[1],
        private,
        active_review,
    )


def _entry(value: object) -> DisclosureEntry:
    keys = {"id", "class", "match", "value"}
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
    if match == "glob" and pattern.count("*") + pattern.count("?") > 8:
        raise Error("disclosure.pattern", "invalid disclosure pattern")
    return DisclosureEntry(cast(str, identifier), entry_class, match, pattern)


def parse_disclosure(document: JSONObject) -> DisclosurePolicy:
    _keys(document, {"schema", "kind", "entries"}, "disclosure policy")
    if document.get("schema") != SCHEMA or document.get("kind") != "disclosure-policy":
        raise Error("disclosure.shape", "invalid disclosure policy schema or kind")
    values = document.get("entries")
    if not isinstance(values, list) or len(values) > 256:
        raise Error("disclosure.entries", "invalid disclosure entries")
    entries = tuple(_entry(item) for item in values)
    ids = tuple(item.entry_id for item in entries)
    if ids != tuple(sorted(set(ids))):
        raise Error("disclosure.order", "entry ids must be sorted and unique")
    return DisclosurePolicy(entries)


def _candidate(path: Path, tree: Tree | None = None) -> tuple[Tree, dict[str, object], str]:
    tree = tree or git_tree(snapshot(path, reject_bytecode=True))
    try:
        file = next(item for item in tree.files if item.path == "SKILL.md")
        fields, body = parse_skill(file.data.decode(errors="strict"))
    except (StopIteration, UnicodeError, FrontmatterError) as exc:
        raise Error("skill.frontmatter", str(exc)) from None
    return tree, fields, body


def _records(  # noqa: PLR0912
    root: Path, directory: Path, kind: str, disclosure: DisclosurePolicy | None = None
) -> tuple[tuple[JSONObject, ...], list[Finding], int]:
    values: list[JSONObject] = []
    findings: list[Finding] = []
    total = 0
    record = "evidence" if kind == "evaluation" else "review"
    if not real_directory(directory):
        return (), [], 0
    failures: dict[str, Error] = {}
    try:
        members = _directory_members(directory, failures)
    except Error as exc:
        code = "governance.bounds" if exc.code == "filesystem.limit" else f"{record}.malformed"
        return (), [_f(code, exc.message, str(directory.relative_to(root)))], 0
    durable = [item for item in members if not is_private_name(item.name)]
    if kind == "evaluation" and len(durable) > MAX_RECORDS:
        findings.append(
            _f(
                "governance.bounds",
                "per-skill evidence record count exceeds bounds",
                str(directory.relative_to(root)),
            )
        )
    for member in members:
        path = directory / member.name
        relative = str(path.relative_to(root))
        if is_private_name(member.name):
            findings.append(_f("transaction.residue", "transaction residue", relative))
            continue
        if member.name in failures:
            findings.append(_f(f"{record}.malformed", failures[member.name].message, relative))
            continue
        try:
            data = read(path, limit=MAX_EVALUATION_BYTES).data
            total += len(data)
            if total > (MAX_SKILL_GOV if kind == "evaluation" else MAX_REPO_GOV):
                raise Error("governance.bounds", f"{record} history bytes exceed scope bounds")
            text = data.decode(errors="ignore")
            findings.extend(credential_findings(text, relative))
            if disclosure:
                findings.extend(disclosure_credential_findings(text, relative, disclosure))
            if not stat.S_ISREG(member.mode) or member.name != _hash(data) + ".json":
                raise Error("governance.identity", "invalid content-addressed record")
            value = parse_canonical_document(data, kind=kind)
            if kind == "evaluation":
                validate_evaluation_intrinsic(value)
            else:
                from .review import validate_review_intrinsic  # noqa: PLC0415

                validate_review_intrinsic(value)
            values.append(value)
        except Error as exc:
            code = "governance.bounds" if exc.code == "governance.bounds" else f"{record}.malformed"
            findings.append(_f(code, exc.message, relative))
            if exc.code == "governance.bounds":
                break
    return tuple(values), findings, total


def _governance(  # noqa: PLR0913
    root: Path, config: Config, name: str, candidate: Tree, fields: dict[str, object], body: str
) -> tuple[Skill, list[Finding]]:
    base = checked_path(root, root / ".remek" / "skills" / name)
    record = parse_skill_record(load_document(base / "skill.json", kind="skill-record"), name)
    source = record.provenance.source
    if source is not None:
        path = checked_path(base / "sources", base / cast(str, source["path"]))
        actual = (
            _hash(read(path).data)
            if source["type"] == "file"
            else tree_digest(
                git_tree(snapshot(path, reject_bytecode=True)), domain=b"remek.candidate.v1\0"
            )
        )
        if actual != source["digest"]:
            raise Error("provenance.source", "retained source digest differs")
    evidence, findings, _ = _records(root, base / "evidence", "evaluation")
    return Skill(
        name,
        root / config.skills_root / name,
        fields,
        body,
        tree_digest(candidate, domain=b"remek.candidate.v1\0"),
        candidate,
        record,
        evidence,
    ), findings


def credential_findings(text: str, path: str) -> list[Finding]:
    return [
        _f(code, "credential-shaped content must be redacted", redact_credential_text(path, None))
        for code, pattern in _CREDENTIALS
        if pattern.search(text)
    ]


def _disclosure_match(entry: DisclosureEntry, text: str) -> bool:
    value = text.casefold()
    pattern = entry.value.casefold()
    return pattern in value if entry.match == "literal" else fnmatch.fnmatchcase(value, pattern)


def redact_credential_text(text: str, policy: DisclosurePolicy | None) -> str:
    marker = "[credential-redacted]"
    if policy and any(
        entry.entry_class == "credential" and _disclosure_match(entry, text)
        for entry in policy.entries
    ):
        return marker
    for _, pattern in _CREDENTIALS:
        text = pattern.sub(marker, text)
    return text


def disclosure_credential_findings(text: str, path: str, policy: DisclosurePolicy) -> list[Finding]:
    return [
        _f("disclosure.credential", f"credential entry {entry.entry_id} matched", path)
        for entry in policy.entries
        if entry.entry_class == "credential" and _disclosure_match(entry, text)
    ]


def _governance_document(text: str) -> bool:
    try:
        value = json.loads(text)
    except (ValueError, OverflowError, RecursionError):
        return False
    return (
        isinstance(value, dict)
        and value.get("schema") in ("remek.1", "remek.2")
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
    for candidate_path in paths:
        result.extend(credential_findings(candidate_path, located(candidate_path)))
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
    if not isinstance(description, str) or not 1 <= len(description.strip()) <= 1024:
        result.append(_f("skill.description", "invalid description", path))
    if not body.strip() or set(fields) - _FIELDS:
        result.append(_f("skill.frontmatter", "invalid fields or empty body", path))
    compatibility = fields.get("compatibility")
    if compatibility is not None and (
        not isinstance(compatibility, str) or not 1 <= len(compatibility) <= 500
    ):
        result.append(
            _f(
                "skill.compatibility",
                "compatibility must be text of 1 through 500 characters",
                path,
            )
        )
    if "allowed-tools" in fields and not isinstance(fields["allowed-tools"], str):
        result.append(_f("skill.allowed-tools", "allowed-tools must be scalar text", path))
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
    provenance = skill.provenance
    path = f".remek/skills/{skill.name}/skill.json"
    if provenance.source is None:
        result.append(
            _f(
                "provenance.unretained",
                "no independently verifiable retained origin; review the skill record's sourceNote",
                path,
                "warning",
            )
        )
    if provenance.origin == "imported" and not all(
        (provenance.upstream_repository, provenance.upstream_ref)
    ):
        result.append(
            _f(
                "provenance.incomplete",
                "imported upstream declarations are incomplete",
                path,
                "warning",
            )
        )
    if not all(
        (provenance.rights.strip(), provenance.rights_basis.strip(), provenance.license.strip())
    ):
        result.append(
            _f(
                "provenance.rights",
                "rights, rights basis, or license is undeclared; required before release",
                path,
                "warning",
            )
        )
    return result


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
            value = parse_distribution(parse_document(data, kind="distribution"))
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
            "reviews": True,
            "skills": True,
            "toolchain": True,
        },
    )
    governed = set(config.governed_skills) if config else set()
    check(root / ".remek/skills", {name: True for name in governed})
    allowed_skill = {
        "skill.json": False,
        "sources": True,
        "evidence": True,
    }
    for name in governed:
        base = root / ".remek/skills" / name
        check(base, allowed_skill)
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
    except Error as exc:
        issues.append(_f(exc.code, exc.message, CONFIG_NAME))
    bundle, toolchain_findings = _toolchain(root)
    issues.extend(toolchain_findings)
    disclosure_size = 0
    try:
        disclosure_data = read(root / DISCLOSURE_PATH, limit=MAX_RECORD_BYTES).data
        disclosure_size = len(disclosure_data)
        disclosure = parse_disclosure(parse_document(disclosure_data, kind="disclosure-policy"))
        issues.extend(credential_findings(disclosure_data.decode(), DISCLOSURE_PATH))
    except (Error, UnicodeError) as exc:
        issues.append(_f("disclosure.invalid", str(exc), DISCLOSURE_PATH))
    distributions, distribution_findings, distribution_size = _load_distributions(root, disclosure)
    issues.extend(distribution_findings)
    reviews, review_findings, review_size = _records(
        root, root / ".remek/reviews", "release-review", disclosure
    )
    issues.extend(review_findings)
    skills: list[Skill] = []
    governance_total = disclosure_size + distribution_size + review_size
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
    review_ids = {
        _hash(
            render(
                "release-review",
                {key: value for key, value in item.items() if key not in {"schema", "kind"}},
            )
        )
        for item in reviews
    }
    for distribution in distributions:
        if distribution.active_review is not None and distribution.active_review not in review_ids:
            issues.append(
                _f(
                    "review.missing",
                    "activeReview names a missing or malformed review",
                    f".remek/distributions/{distribution.distribution_id}.json",
                )
            )
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
            elif skill_member.record.exposure == "source-only" or (
                distribution.audience == "public"
                and skill_member.record.exposure != "public-eligible"
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
    _owned_layout(root, config, issues)
    return RepositoryInspection(
        root,
        config,
        bundle,
        tuple(skills),
        distributions,
        disclosure,
        issues.ordered(),
        reviews,
    )


def _record_path(skill: Skill, folder: str, document: JSONObject) -> str:
    data = render(
        cast(str, document["kind"]),
        {key: value for key, value in document.items() if key not in {"schema", "kind"}},
    )
    return f".remek/skills/{skill.name}/{folder}/{_hash(data)}.json"


def repository_findings(inspection: RepositoryInspection) -> tuple[Finding, ...]:
    issues = list(inspection.issues)
    for skill in inspection.skills:
        passing: set[str] = set()
        for report in skill.evidence:
            kind = cast(str, report["evidenceKind"])
            try:
                plan = evaluation_plan(
                    inspection, skill.name, kind, cast(str | None, report["distribution"])
                )
                _, passed, _ = evaluation_status(report, plan)
                if passed:
                    passing.add(kind)
                else:
                    issues.append(
                        _f(
                            "evidence.failed",
                            "current evaluation reports failed or error observations",
                            _record_path(skill, "evidence", report),
                            "warning",
                        )
                    )
            except Error:
                issues.append(
                    _f(
                        "evidence.stale",
                        "historical evaluation does not match current inputs; retained unchanged",
                        _record_path(skill, "evidence", report),
                        "warning",
                    )
                )
            if report.get("artifacts"):
                issues.append(
                    _f(
                        "evidence.external",
                        "external artifact bytes and availability were not checked",
                        _record_path(skill, "evidence", report),
                        "warning",
                    )
                )
        for kind in ("routing", "behavior"):
            if kind not in passing:
                issues.append(
                    _f(
                        f"evidence.{kind}",
                        f"current reported-passing {kind} evidence is missing; "
                        "required only by release policy",
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
            if entry.entry_class != "note" and matched and blocks and key not in seen:
                result.append((entry, path))
                seen.add(key)
    return tuple(result)


def evaluation_plan(
    inspection: RepositoryInspection,
    skill_name: str,
    evidence_kind: str,
    dist: str | None,
) -> EvaluationPlan:
    skill = inspection.skill(skill_name)
    cases = skill.behavior_cases if evidence_kind == "behavior" else skill.routing_cases
    if not cases.cases:
        raise Error(
            "evidence.cases", "requested case set is empty; author actual cases before evaluation"
        )
    if evidence_kind == "behavior":
        if dist is not None:
            raise Error("evidence.distribution", "behavior evidence is not distribution-bound")
        return EvaluationPlan(skill.name, skill.digest, skill.behavior_cases, None)
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
    return EvaluationPlan(
        skill.name,
        skill.digest,
        skill.routing_cases,
        routing_catalog_digest(catalog),
        dist,
    )


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
            repair = "rename the folder to match the frontmatter name or correct that name"
            message = (
                f"frontmatter name must match folder and be lowercase hyphenated; repair: {repair}"
            )
        elif not isinstance(fields.get("description"), str):
            message = (
                "actual description is missing or not text; expected non-empty text; repair: "
                "set description in supported SKILL.md frontmatter"
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
                    "installer metadata needs explicit reviewed removal: " + ", ".join(injected),
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
                "parsed supported frontmatter is outside the remek payload profile"
                if incompatible
                else "structurally valid under the supported remek profile",
                label,
                "warning" if incompatible else "info",
            )
        )
    return issues.ordered()
