# ruff: noqa: D103, I001
"""Workflows."""

import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import tempfile
import time
from dataclasses import replace
from contextlib import suppress
from pathlib import Path
from typing import NoReturn, cast
from urllib.parse import urlparse

from .contract import (
    SCHEMA,
    MAX_ITEMS,
    JSONObject,
    JSONValue,
    document_limit,
    load_document,
    parse_document,
    parse_canonical_document,
    render_document as render,
    value_count,
)
from .evaluation import evaluation_document, validate_evaluation
from .review import relevant_evidence, release_findings, validate_review
from .filesystem import (
    Tree,
    TreeDirectory as Directory,
    TreeFile as File,
    checked_root as checked,
    directory_members,
    entry_exists as exists,
    fingerprint,
    git_mode,
    git_tree,
    inventory_digest,
    paths_related,
    portable_path,
    read_regular as read,
    real_directory,
    snapshot_tree as snapshot,
    tree_from_entries as assemble,
)
from .model import Error, valid_skill_name
from .plans import Plan, SourceBinding
from .repository import (
    DISCLOSURE_PATH,
    MAX_RECORDS,
    MAX_REPO_GOV,
    MAX_SKILL_GOV,
    MAX_SKILLS,
    Config,
    DisclosurePolicy,
    Distribution,
    RepositoryInspection as Inspection,
    Skill,
    credential_findings,
    disclosure_credential_findings,
    evaluation_plan,
    loaded_bootstrap,
    new_config,
    parse_distribution,
    inspect_repository as inspect,
    repository_findings as check,
)
from .transaction import Change, delete_change, tree_change, write_change as write

_PROCESS_OUTPUT_LIMIT = 4 * 1024 * 1024
_PROCESS_TIMEOUT_SECONDS = 30  # Fixed subprocess contract; see docs/contracts.md.
_TARGET_OUTPUT_LIMIT = 64 * 1024
_RELEASE_HISTORY_LIMIT = 256
_RELEASE_FILE = "release-manifest.json"
_RELEASE_KEYS = {
    "schema",
    "kind",
    "audience",
    "sourceRepositoryIdentity",
    "sourceCommit",
    "sourceBranchDigest",
    "distributionIdentity",
    "releaseId",
    "releaseSetDigest",
    "reviewDigest",
    "payloadDigest",
    "candidates",
    "directories",
    "files",
    "targetVerificationDigest",
    "preReleaseHead",
    "remoteBinding",
    "expectedCommitPaths",
}
_SHIMS = {"gate": "assets/gate"}


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _text_digest(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise Error("release.identity", "private release identity is invalid")
    return _hash(value.encode())


def _target_lineage_digest(target: JSONObject, observation: JSONObject) -> str:
    values = (
        observation.get("provider"),
        target.get("hostname"),
        target.get("nameWithOwner"),
        target.get("expectedVisibility"),
        observation.get("visibility"),
        target.get("branch"),
    )
    if (
        any(not isinstance(value, str) or not value for value in values)
        or observation.get("provider") != target.get("provider")
        or observation.get("hostname") != target.get("hostname")
        or observation.get("nameWithOwner") != target.get("nameWithOwner")
    ):
        raise Error("release.target", "target verification is invalid")
    digest = hashlib.sha256(b"remek.release-target-lineage.v2\0")
    for value in values:
        data = cast(str, value).encode()
        digest.update(len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


def _hex(value: object, lengths: tuple[int, ...] = (64,)) -> bool:
    return (
        isinstance(value, str)
        and len(value) in lengths
        and re.fullmatch(r"[0-9a-f]+", value) is not None
    )


def _release_path(value: str) -> str:
    if credential_findings(value, "release path"):
        raise Error("release.credential", "release path contains credential-shaped content")
    portable = portable_path(value, authored=True)
    if "\\" in value or ".remek" in portable.split("/") or portable.endswith("/.gitattributes"):
        raise Error("release.payload-path", "release payload path is unsupported")
    return portable


def _manifest(  # noqa: PLR0912, PLR0915
    document: JSONObject, code: str
) -> JSONObject:
    def invalid() -> NoReturn:
        raise Error(code, "release manifest shape is invalid")

    def objects(key: str, keys: set[str]) -> list[JSONObject]:
        value = document.get(key)
        if not isinstance(value, list) or any(
            not isinstance(item, dict) or set(item) != keys for item in value
        ):
            invalid()
        return [item for item in value if isinstance(item, dict)]

    if (
        set(document) != _RELEASE_KEYS
        or not isinstance(document.get("audience"), str)
        or document.get("audience") not in ("private", "public")
        or not _hex(document.get("sourceCommit"), (40, 64))
        or not all(
            _hex(document.get(key))
            for key in (
                "sourceRepositoryIdentity",
                "distributionIdentity",
                "releaseId",
                "releaseSetDigest",
                "reviewDigest",
                "payloadDigest",
            )
        )
        or (
            document.get("sourceBranchDigest") is not None
            and not _hex(document.get("sourceBranchDigest"))
        )
    ):
        invalid()
    directories: list[tuple[str, int]] = []
    for item in objects("directories", {"path", "mode"}):
        path, mode = item.get("path"), item.get("mode")
        if not isinstance(path, str) or mode != 0o755:
            invalid()
        directories.append((path, mode))
    files: list[tuple[str, int, bytes]] = []
    for item in objects("files", {"path", "mode", "sha256"}):
        path, mode, digest = item.get("path"), item.get("mode"), item.get("sha256")
        if not isinstance(path, str) or mode not in (0o644, 0o755) or not _hex(digest):
            invalid()
        files.append((path, mode, bytes.fromhex(cast(str, digest))))
    directory_paths = [path for path, _ in directories]
    file_paths = [path for path, _, _ in files]
    try:
        portable = [_release_path(path) for path in (*directory_paths, *file_paths)]
    except Error:
        invalid()
    directory_set = set(directory_paths)
    if (
        directory_paths != sorted(set(directory_paths))
        or file_paths != sorted(set(file_paths))
        or len(portable) != len(set(portable))
        or bool(directory_paths) != bool(file_paths)
        or (
            directory_paths
            and (
                directory_paths[0] != "skills"
                or any(not path.startswith("skills/") for path in file_paths)
                or any(
                    path.rpartition("/")[0] not in directory_set
                    for path in (*directory_paths[1:], *file_paths)
                )
                or any(
                    not any(path.startswith(f"{directory}/") for path in file_paths)
                    for directory in directory_paths
                )
            )
        )
    ):
        invalid()
    payload_files = [(path[7:], mode, digest) for path, mode, digest in files]
    payload_digest = inventory_digest(
        0o755, [(path[7:], mode) for path, mode in directories[1:]], payload_files
    )
    roots = [path for path in directory_paths if path.count("/") == 1]
    if any(path.count("/") < 2 for path in file_paths):
        invalid()
    candidates: list[JSONValue] = []
    for root in roots:
        prefix = f"{root}/"
        name = root[7:]
        if not valid_skill_name(name):
            invalid()
        root_files = [item for item in payload_files if item[0].startswith(root[7:] + "/")]
        root_files = [
            (path.removeprefix(root[7:] + "/"), mode, digest) for path, mode, digest in root_files
        ]
        if not any(path == "SKILL.md" for path, _, _ in root_files):
            invalid()
        candidates.append(
            {
                "name": name,
                "candidate": inventory_digest(
                    0o755,
                    [
                        (path.removeprefix(prefix), mode)
                        for path, mode in directories
                        if path.startswith(prefix)
                    ],
                    root_files,
                    domain=b"remek.candidate.v1\0",
                ),
            }
        )
    if (
        len(candidates) > MAX_SKILLS
        or document.get("payloadDigest") != payload_digest
        or document.get("candidates") != candidates
    ):
        invalid()
    remote = document.get("remoteBinding")
    match remote:
        case None:
            pass
        case {
            "nameDigest": name_digest,
            "fetchUrlDigests": list(fetch),
            "pushUrlDigests": list(push),
        } if (
            len(cast(JSONObject, remote)) == 3
            and _hex(name_digest)
            and fetch
            and push
            and all(_hex(item) for item in (*fetch, *push))
        ):
            pass
        case _:
            invalid()
    paths = document.get("expectedCommitPaths")
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
        invalid()
    path_values = cast(list[str], paths)
    ledger = path_values[:-1]
    if any(credential_findings(path, "release path") for path in ledger):
        invalid()
    if ledger != sorted(set(ledger)) or any(not path.startswith("skills/") for path in ledger):
        invalid()
    try:
        for path in ledger:
            portable_path(path)
    except Error:
        invalid()
    target, pre = document.get("targetVerificationDigest"), document.get("preReleaseHead")
    match target, pre, remote, path_values:
        case "not-performed", None, None, []:
            pass
        case str(target), str(pre), dict(), [*_, "release-manifest.json"] if _hex(target) and _hex(
            pre, (40, 64)
        ):
            pass
        case _:
            invalid()
    return document


def _preflight(inspection: Inspection, command: str) -> None:
    for finding in check(inspection):
        if finding.severity == "error":
            raise Error(
                f"{command}.preflight",
                f"{command} preflight failed: {finding.code}: {finding.message}",
            )


def _screen(
    inspection: Inspection,
    data: bytes,
    path: str,
) -> None:
    text = data.decode()
    issues = credential_findings(text, path)
    if path != DISCLOSURE_PATH and inspection.disclosure is not None:
        issues.extend(disclosure_credential_findings(text, path, inspection.disclosure))
    if issues:
        first = issues[0]
        raise Error("credential.content", f"{first.code}: {first.message} ({path})")


def _size(path: Path) -> int:
    if not exists(path):
        return 0
    if real_directory(path):
        return sum(len(item.data) for item in snapshot(path).files)
    return len(read(path).data)


def _bound(
    path: Path,
    size: int,
    *,
    skill: Path | None = None,
    record_kind: str,
) -> None:
    old = _size(path)
    if size > document_limit(record_kind) or (
        skill is not None and _size(skill) - old + size > MAX_SKILL_GOV
    ):
        raise Error("governance.bounds", "planned governance exceeds bounds")


def _bound_changes(root: Path, changes: list[Change]) -> None:
    size = sum(
        _size(root / path)
        for path in (
            ".remek/disclosure-policy.json",
            ".remek/distributions",
            ".remek/skills",
            ".remek/reviews",
        )
    )
    for change in changes:
        after = (
            sum(len(item.data) for item in change.tree.files)
            if change.tree is not None
            else len(change.data or b"")
        )
        size += after - _size(change.path)
    if size > MAX_REPO_GOV:
        raise Error("governance.bounds", "planned governance exceeds source bounds")


def _one(change: Change) -> tuple[Change, ...]:
    return () if change.expected == change.after else (change,)


def _owned_write(root: Path, destination: Path, data: bytes, reason: str) -> tuple[Change, ...]:
    if exists(destination):
        if read(destination, limit=len(data)).data != data:
            raise Error("governance.identity", "existing immutable record bytes differ")
        return ()
    parent = destination.parent
    if real_directory(parent):
        return (write(root, destination, data, reason),)
    if exists(parent):
        raise Error("governance.layout", "governance record directory must be real")
    return (tree_change(root, parent, assemble([File(destination.name, data, 0o644)]), reason),)


def _review_pointer(root: Path, dist: Distribution, value: str | None, reason: str) -> Change:
    path = root / ".remek/distributions" / f"{dist.distribution_id}.json"
    before = fingerprint(path)
    source = read(path, limit=document_limit("distribution"))
    if parse_distribution(parse_document(source.data, kind="distribution")) != dist:
        raise Error("distribution.drift", "distribution changed since inspection; re-plan")
    text = source.data.decode()
    decoder = json.JSONDecoder()
    position = text.index("{") + 1
    # Walk only top-level key/value tokens in the bounded, strictly validated document.
    while True:
        while text[position] in " \t\r\n,":
            position += 1
        key, position = decoder.raw_decode(text, position)
        position = text.index(":", position) + 1
        while text[position] in " \t\r\n":
            position += 1
        start = position
        _, position = decoder.raw_decode(text, position)
        if key == "activeReview":
            break
    output = (text[:start] + json.dumps(value) + text[position:]).encode()
    if len(output) > document_limit("distribution"):
        raise Error("governance.bounds", "updated distribution exceeds its byte bound")
    change = write(root, path, output, reason, mode=source.identity.mode)
    if change.expected != before:
        raise Error("distribution.drift", "distribution changed while planning; re-plan")
    return change


def _record(
    root: Path,
    inspection: Inspection,
    skill_name: str,
    folder: str,
    data: bytes,
) -> tuple[str, tuple[Change, ...]]:
    noun = folder.rstrip("s")
    _screen(inspection, data, f"{noun} record")
    digest = _hash(data)
    destination = root / ".remek" / "skills" / skill_name / folder / f"{digest}.json"
    skill = inspection.skill(skill_name)
    if not exists(destination) and len(skill.evidence) >= MAX_RECORDS:
        raise Error("governance.bounds", "skill record count exceeds bounds")
    _bound(destination, len(data), skill=destination.parent.parent, record_kind="evaluation")
    return digest, _owned_write(root, destination, data, f"record immutable reviewed {noun}")


def _prefix(source: Tree, prefix: str) -> tuple[list[File], list[Directory]]:
    parts = prefix.split("/")
    directories = [Directory("/".join(parts[:index])) for index in range(1, len(parts))]
    directories.append(Directory(prefix, source.root_mode))
    directories.extend(Directory(f"{prefix}/{item.path}", item.mode) for item in source.directories)
    files = [File(f"{prefix}/{item.path}", item.data, item.mode) for item in source.files]
    return files, directories


def _external(root: Path, path: Path, label: str) -> SourceBinding:
    selected = path.expanduser().absolute()
    canonical = checked(selected.parent) / selected.name
    binding = SourceBinding(canonical, fingerprint(canonical))
    if paths_related(root, binding.path):
        raise Error(f"{label}.related", f"{label} must be outside the governed source")
    return binding


def _init_state(toolchain: Tree, config: Config) -> Tree:
    files, directories = _prefix(toolchain, ".remek/toolchain")
    directories.extend(
        [
            Directory(".remek/distributions"),
            Directory(".remek/skills"),
            Directory(".remek/reviews"),
        ]
    )
    files.extend(
        [
            File("remek.json", config.render(), 0o644),
            File(
                DISCLOSURE_PATH,
                DisclosurePolicy(()).render(),
                0o644,
            ),
            File(".gitignore", b".DS_Store\n__pycache__/\n.venv/\n/.tmp/\n", 0o644),
        ]
    )
    source_files = {item.path: item for item in toolchain.files}
    files.append(File("remek", loaded_bootstrap(), 0o755))
    for shim, source in _SHIMS.items():
        files.append(File(shim, source_files[source].data, 0o755))
    return assemble(files, directories)


def init_plan(
    target: Path,
    bundle: Path,
    repository_id: str | None = None,
    *,
    project: bool = False,
) -> Plan:
    selected = target.expanduser().absolute()
    parent = checked(selected.parent)
    canonical = parent / selected.name
    config = new_config(
        repository_id,
        skills_root=".agents/skills" if project else "skills",
    )
    toolchain = snapshot(checked(bundle), reject_bytecode=True)
    state = _init_state(toolchain, config)
    inputs: JSONObject = {"target": str(canonical), "project": project}
    generated: JSONObject = {"repositoryId": config.repository_id}
    if not exists(canonical):
        change = tree_change(parent, canonical, state, "create the governed source atomically")
        return Plan("init", canonical, (change,), inputs, generated)
    root = checked(canonical)
    conflicts = [root / name for name in ("remek.json", ".remek", "remek", "gate")]
    if any(exists(path) for path in conflicts):
        raise Error("init.conflict", "existing repository contains a reserved remek path")
    skills = root / "skills"
    if not project and exists(skills):
        if not real_directory(skills):
            raise Error(
                "init.skills",
                "existing skills/ is not an empty real directory; repair: follow the documented "
                "first-time in-place migration, or use --project only to govern .agents/skills "
                "intentionally",
            )
        members = directory_members(skills)
        if members:
            names = ", ".join(sorted(item.name for item in members)[:5])
            raise Error(
                "init.skills",
                f"existing skills/ contains foreign entries ({names}); repair: follow the "
                "documented first-time in-place migration; --project intentionally governs "
                ".agents/skills instead",
            )
    files = {item.path: item for item in state.files}
    toolchain_files = [item for item in state.files if item.path.startswith(".remek/")]
    toolchain_dirs = [item for item in state.directories if item.path.startswith(".remek")]
    remek_tree = assemble(
        [File(item.path.removeprefix(".remek/"), item.data, item.mode) for item in toolchain_files],
        [
            Directory(item.path.removeprefix(".remek/"), item.mode)
            for item in toolchain_dirs
            if item.path != ".remek"
        ],
    )
    changes: list[Change] = [
        tree_change(root, root / ".remek", remek_tree, "install the manifest-owned toolchain"),
        write(root, root / "remek.json", config.render(), "record repository identity"),
    ]
    for name in ("remek", "gate"):
        changes.append(
            write(root, root / name, files[name].data, f"install root {name} shim", mode=0o755)
        )
    if not exists(root / ".gitignore"):
        changes.append(
            write(root, root / ".gitignore", files[".gitignore"].data, "ignore local residue")
        )
    return Plan("init", root, tuple(changes), inputs, generated)


def _git_checkout_containing(path: Path, forbidden_roots: tuple[Path, ...]) -> Path | None:
    try:
        completed = _run(
            _git_arguments(path, "rev-parse", "--show-toplevel"),
            cwd=path,
            environment=_git_environment(),
            forbidden_roots=forbidden_roots,
        )
    except Error as exc:
        if exc.code == "external.unavailable" and exc.message.startswith("cannot run git"):
            raise Error(
                "git.required",
                "Git is required for staging checkout-boundary checks; " + exc.message,
            ) from None
        raise
    if completed.returncode != 0:
        return None
    return Path(completed.stdout.strip()).resolve()


def _source_bindings(inspection: Inspection) -> JSONObject:
    if inspection.config is None:
        raise Error("governance.config", "repository configuration is unavailable")
    root = inspection.root
    paths = [root / "remek.json", root / ".remek"]
    paths.extend(skill.path for skill in inspection.skills)
    return {str(path): fingerprint(path) for path in paths}


def eval_record_plan(root: Path, skill_name: str, evidence: Path) -> Plan:
    root = checked(root)
    inspection = inspect(root)
    _preflight(inspection, "eval record")
    binding = _external(root, evidence, "evidence artifact")
    document = load_document(binding.path, kind="evaluation")
    kind, distribution = document.get("evidenceKind"), document.get("distribution")
    if not isinstance(kind, str) or (
        distribution is not None and not isinstance(distribution, str)
    ):
        raise Error("evidence.shape", "evidence kind or distribution is invalid")
    evaluation = evaluation_plan(inspection, skill_name, kind, distribution)
    output = evaluation_document(document, evaluation)
    normalized, passed = validate_evaluation(document, evaluation)
    digest, records = _record(root, inspection, skill_name, "evidence", output)
    changes = list(records)
    revoked: list[str] = []
    if records:
        skill = inspection.skill(skill_name)
        updated_skill = replace(skill, evidence=(*skill.evidence, normalized))
        updated = replace(
            inspection,
            skills=tuple(
                updated_skill if item.name == skill_name else item for item in inspection.skills
            ),
        )
        for dist in inspection.distributions:
            if (
                skill_name in dist.skills
                and dist.active_review is not None
                and any(
                    report_id == digest
                    for report_id, *_ in relevant_evidence(
                        updated, dist.distribution_id, skill_name
                    )
                )
            ):
                changes.append(
                    _review_pointer(
                        root,
                        dist,
                        None,
                        "revoke active review after new relevant evidence",
                    )
                )
                revoked.append(dist.distribution_id)
    _bound_changes(root, changes)
    return Plan(
        "eval-record",
        root,
        tuple(changes),
        {"skill": skill_name, "evidence": str(binding.path)},
        bindings={"reportId": digest, "source": _source_bindings(inspection)},
        sources=(binding,),
        data={"reportId": digest, "reportedPassing": passed, "revokedDistributions": revoked},
    )


def review_record_plan(root: Path, distribution: str, artifact: Path) -> Plan:
    root = checked(root)
    inspection = inspect(root)
    _preflight(inspection, "review record")
    binding = _external(root, artifact, "review artifact")
    document = load_document(binding.path, kind="release-review")
    normalized = validate_review(document, inspection, distribution)
    fields = {key: value for key, value in normalized.items() if key not in {"schema", "kind"}}
    output = render("release-review", fields)
    _screen(inspection, output, "release review")
    digest = _hash(output)
    destination = root / ".remek/reviews" / f"{digest}.json"
    _bound(destination, len(output), record_kind="release-review")
    changes = list(_owned_write(root, destination, output, "record immutable release review"))
    dist = inspection.distribution(distribution)
    if dist.active_review != digest:
        changes.append(
            _review_pointer(
                root,
                dist,
                digest,
                "activate exact distribution review",
            )
        )
    _bound_changes(root, changes)
    return Plan(
        "review-record",
        root,
        tuple(changes),
        {"distribution": distribution, "review": str(binding.path)},
        bindings={"reviewId": digest, "source": _source_bindings(inspection)},
        sources=(binding,),
        data={
            "reviewId": digest,
            "contextDigest": normalized["contextDigest"],
            "distribution": distribution,
            "priorActiveReview": dist.active_review,
        },
    )


def update_plan(root: Path, bundle: Path) -> Plan:
    root = checked(root)
    source = snapshot(checked(bundle), reject_bytecode=True)
    inspection = inspect(root)
    allowed = {"repo.toolchain", "repo.shim"}
    destination = root / ".remek" / "toolchain"
    if not real_directory(destination):
        raise Error("update.layout", "update requires .remek/toolchain")
    if any(item.code == "toolchain.identity" for item in inspection.issues):
        current = snapshot(destination, reject_bytecode=True)
        if {item.path for item in current.files} - {item.path for item in source.files} or {
            item.path for item in current.directories
        } - {item.path for item in source.directories}:
            raise Error("update.ownership", "damaged toolchain contains unknown paths; preserved")
        allowed.add("toolchain.identity")
    for finding in check(inspection):
        if finding.severity == "error" and finding.code not in allowed:
            raise Error("update.preflight", f"update preflight failed: {finding.code}")
    changes = list(
        _one(tree_change(root, destination, source, "replace the embedded toolchain atomically"))
    )
    files = {item.path: item for item in source.files}
    remek = write(root, root / "remek", loaded_bootstrap(), "refresh root remek shim", mode=0o755)
    changes.extend(_one(remek))
    for name, source_path in _SHIMS.items():
        shim = write(
            root,
            root / name,
            files[source_path].data,
            f"refresh root {name} shim",
            mode=0o755,
        )
        changes.extend(_one(shim))
    return Plan(
        "update",
        root,
        tuple(changes),
        bindings={"sourceToolchain": f"tree:{source.digest}"},
        data={
            "oldBundleIdentity": fingerprint(destination),
            "newBundleIdentity": f"tree:{source.digest}",
        },
    )


def _capture_process(
    process: subprocess.Popen[bytes], arguments: list[str], output_limit: int
) -> tuple[int, dict[str, bytearray]]:
    assert process.stdout is not None and process.stderr is not None
    selector: selectors.BaseSelector | None = None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        selector = selectors.DefaultSelector()
        for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        deadline = time.monotonic() + _PROCESS_TIMEOUT_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(arguments, _PROCESS_TIMEOUT_SECONDS)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(arguments, _PROCESS_TIMEOUT_SECONDS)
            for key, _ in events:
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[cast(str, key.data)].extend(chunk)
                if sum(len(value) for value in buffers.values()) > output_limit:
                    raise Error("external.output", f"{arguments[0]} output exceeds its bound")
        returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
    except BaseException as exc:
        with suppress(OSError):
            process.kill()
        with suppress(OSError, subprocess.SubprocessError):
            process.wait(timeout=_PROCESS_TIMEOUT_SECONDS)
        if isinstance(exc, (OSError, subprocess.SubprocessError)):
            raise Error("external.unavailable", f"{arguments[0]} query failed") from None
        raise
    finally:
        for resource in (selector, process.stdout, process.stderr):
            if resource is not None:
                with suppress(OSError):
                    resource.close()
    return returncode, buffers


def _within_forbidden(path: Path, roots: tuple[Path, ...]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _external_command(  # noqa: PLR0912, PLR0915
    arguments: list[str],
    environment: dict[str, str],
    forbidden_roots: tuple[Path, ...],
) -> tuple[list[str], dict[str, str]]:
    tool = arguments[0]
    value = environment.get("PATH")
    if value is None:
        raise Error("external.unavailable", f"cannot run {tool}")
    roots = tuple(root.resolve(strict=False) for root in forbidden_roots)
    directories: list[Path] = []
    executable: Path | None = None
    filtered: set[str] = set()
    for entry in value.split(os.pathsep):
        path = Path(entry)
        if not entry or not path.is_absolute():
            raise Error(
                "external.path",
                f"{tool} PATH entries must be nonempty absolute directories; correct PATH",
            )
        try:
            canonical = path.resolve(strict=True)
            info = canonical.stat()
        except OSError:
            continue
        if not stat.S_ISDIR(info.st_mode):
            continue
        if _within_forbidden(canonical, roots):
            filtered.add("directory is inside a selected root")
            continue
        tool_targets: dict[str, Path] = {}
        unsafe = False
        for name in ("git", "gh"):
            try:
                target = (canonical / name).resolve(strict=True)
                target_info = target.stat()
            except OSError:
                continue
            reason = (
                f"{name} target is not a regular file"
                if not stat.S_ISREG(target_info.st_mode)
                else f"{name} target has multiple hard links"
                if target_info.st_nlink != 1
                else f"{name} target is inside a selected root"
                if _within_forbidden(target, roots)
                else ""
            )
            if reason:
                filtered.add(reason)
                unsafe = True
                break
            tool_targets[name] = target
        if unsafe:
            continue
        directories.append(canonical)
        if executable is not None:
            continue
        candidate = tool_targets.get(tool)
        if candidate is None:
            continue
        if os.access(candidate, os.X_OK):
            executable = candidate
        else:
            filtered.add(f"{tool} target is not executable")
    if executable is None:
        detail = (
            ": PATH directories were filtered ("
            + "; ".join(sorted(filtered))
            + "); select executable, single-linked regular git and gh outside selected roots"
            if filtered
            else ""
        )
        raise Error("external.unavailable", f"cannot run {tool}{detail}")
    child = dict(environment)
    child["PATH"] = os.pathsep.join(str(path) for path in directories)
    return [str(executable), *arguments[1:]], child


def _run(  # noqa: PLR0913
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
    forbidden_roots: tuple[Path, ...] = (),
    input_text: str = "",
    output_limit: int = _PROCESS_OUTPUT_LIMIT,
) -> subprocess.CompletedProcess[str]:
    logical_arguments = arguments
    child_arguments = arguments
    child_environment = environment
    if arguments[0] in {"git", "gh"}:
        if not forbidden_roots:
            raise Error("external.boundary", f"{arguments[0]} selected roots are unavailable")
        child_arguments, child_environment = _external_command(
            arguments,
            environment if environment is not None else dict(os.environ),
            forbidden_roots,
        )
    input_data = input_text.encode()
    if len(input_data) > output_limit:
        raise Error("external.input", f"{logical_arguments[0]} input exceeds its bound")
    with tempfile.TemporaryFile() as input_file:
        input_file.write(input_data)
        input_file.seek(0)
        try:
            process = subprocess.Popen(
                child_arguments,
                cwd=cwd,
                env=child_environment,
                stdin=input_file,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError:
            raise Error("external.unavailable", f"cannot run {logical_arguments[0]}") from None
        returncode, buffers = _capture_process(process, logical_arguments, output_limit)
    try:
        stdout = bytes(buffers["stdout"]).decode()
        stderr = bytes(buffers["stderr"]).decode()
    except UnicodeDecodeError:
        raise Error("external.output", f"{logical_arguments[0]} output is not UTF-8") from None
    return subprocess.CompletedProcess(logical_arguments, returncode, stdout, stderr)


def _git_arguments(root: Path, *arguments: str) -> list[str]:
    return [
        "git",
        "-C",
        str(root),
        "--no-pager",
        "--no-optional-locks",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "diff.external=",
        "-c",
        "core.multiPackIndex=false",
        "-c",
        "log.showSignature=false",
        *arguments,
    ]


def _git_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _git(
    root: Path,
    *arguments: str,
    forbidden_roots: tuple[Path, ...] | None = None,
    allowed: tuple[int, ...] = (0,),
    input_text: str = "",
) -> str:
    roots = forbidden_roots if forbidden_roots is not None else (root,)
    completed = _run(
        _git_arguments(root, *arguments),
        cwd=root,
        environment=_git_environment(),
        forbidden_roots=roots,
        input_text=input_text,
    )
    if completed.returncode not in allowed:
        raise Error("git.query", "Git query failed")
    return completed.stdout.removesuffix("\n")


def _nul_records(value: str) -> list[str]:
    if not value:
        return []
    if not value.endswith("\0"):
        raise Error("git.output", "Git returned malformed path records")
    return value[:-1].split("\0")


def _guard_git_attributes(root: Path, paths: str, forbidden_roots: tuple[Path, ...]) -> None:
    if not paths:
        return
    attributes = _nul_records(
        _git(
            root,
            "check-attr",
            "--all",
            "-z",
            "--stdin",
            forbidden_roots=forbidden_roots,
            input_text=paths,
        )
    )
    if len(attributes) % 3:
        raise Error("git.output", "Git returned malformed attribute records")
    for index in range(0, len(attributes), 3):
        _, attribute, value = attributes[index : index + 3]
        if attribute == "filter" and value not in {"unset", "unspecified"}:
            raise Error("git.attributes", "release Git roots may not select content filters")


def _guard_git_worktree(root: Path, forbidden_roots: tuple[Path, ...]) -> None:
    graft_path = Path(
        _git(root, "rev-parse", "--git-path", "info/grafts", forbidden_roots=forbidden_roots)
    )
    graft_path = graft_path if graft_path.is_absolute() else root / graft_path
    if exists(graft_path):
        try:
            grafts = read(graft_path)
        except Error:
            raise Error("git.grafts", "Git graft state is unsupported") from None
        if grafts.data.strip():
            raise Error("git.grafts", "Git graft state is unsupported")
    tracked = _git(
        root, "ls-files", "--cached", "--full-name", "-z", forbidden_roots=forbidden_roots
    )
    tagged = _nul_records(
        _git(
            root,
            "ls-files",
            "--cached",
            "--full-name",
            "-v",
            "-z",
            forbidden_roots=forbidden_roots,
        )
    )
    if any(len(record) < 3 or record[:2] != "H " for record in tagged):
        raise Error("git.index-flags", "Git index flags can hide state")
    for record in _nul_records(
        _git(
            root,
            "ls-files",
            "--cached",
            "--full-name",
            "--stage",
            "-z",
            forbidden_roots=forbidden_roots,
        )
    ):
        try:
            metadata, _ = record.split("\t", 1)
            mode, _, stage = metadata.split(" ")
        except ValueError:
            raise Error("git.output", "Git returned malformed index records") from None
        if stage != "0":
            raise Error("git.index", "Git index contains unresolved entries")
        if mode == "160000":
            raise Error("git.submodule", "release Git roots may not contain submodules")
    _guard_git_attributes(root, tracked, forbidden_roots)


def _git_state(root: Path, forbidden_roots: tuple[Path, ...] | None = None) -> JSONObject:
    roots = forbidden_roots if forbidden_roots is not None else (root,)
    top = Path(_git(root, "rev-parse", "--show-toplevel", forbidden_roots=roots)).resolve()
    if top != root:
        raise Error("git.root", "selected path is not the Git worktree root")
    shallow = _git(root, "rev-parse", "--is-shallow-repository", forbidden_roots=roots)
    if shallow not in {"false", "true"}:
        raise Error("git.output", "Git returned invalid shallow state")
    if shallow == "true":
        raise Error("git.shallow", "release Git roots require complete history")
    if _git(
        root,
        "config",
        "--local",
        "--includes",
        "--name-only",
        "--get-regexp",
        r"^fsck\.",
        forbidden_roots=roots,
        allowed=(0, 1),
    ):
        raise Error("git.integrity", "repository-local fsck configuration is unsupported")
    try:
        integrity = _run(
            _git_arguments(
                root, "fsck", "--full", "--no-dangling", "--no-reflogs", "--no-progress", "HEAD"
            ),
            cwd=root,
            environment=_git_environment(),
            forbidden_roots=roots,
        )
    except Error as exc:
        if exc.code == "external.unavailable" and exc.message.startswith("cannot run git"):
            raise Error(
                "git.required",
                "Git is required for release integrity checks; " + exc.message,
            ) from None
        raise Error(
            "git.integrity",
            f"Git object integrity check failed or exceeded its {_PROCESS_TIMEOUT_SECONDS}-second "
            "command bound",
        ) from None
    if integrity.returncode != 0:
        raise Error(
            "git.integrity",
            f"Git object integrity check failed or exceeded its {_PROCESS_TIMEOUT_SECONDS}-second "
            "command bound",
        )
    _guard_git_worktree(root, roots)
    status = _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "-z",
        forbidden_roots=roots,
    )
    if status:
        raise Error("git.dirty", "Git dirty; repository unchanged; commit or clean")
    head = _git(root, "rev-parse", "HEAD", forbidden_roots=roots)
    branch = (
        _git(
            root,
            "symbolic-ref",
            "--quiet",
            "--short",
            "HEAD",
            forbidden_roots=roots,
            allowed=(0, 1),
        )
        or None
    )
    return {"root": str(root), "head": head, "branch": branch}


def _require_ancestor(
    root: Path, ancestor: str, descendant: str, forbidden_roots: tuple[Path, ...]
) -> None:
    completed = _run(
        _git_arguments(root, "merge-base", "--is-ancestor", ancestor, descendant),
        cwd=root,
        environment=_git_environment(),
        forbidden_roots=forbidden_roots,
    )
    if completed.returncode == 1:
        raise Error("release.ancestry", "prior source commit is not an ancestor")
    if completed.returncode != 0:
        raise Error("git.query", "cannot verify source commit ancestry")


def _release_history(root: Path, forbidden_roots: tuple[Path, ...]) -> tuple[JSONObject, ...]:
    commits = _git(
        root,
        "log",
        "--full-history",
        "--format=%H",
        "--diff-filter=AM",
        "--no-renames",
        "-n",
        str(_RELEASE_HISTORY_LIMIT + 1),
        "HEAD",
        "--",
        _RELEASE_FILE,
        forbidden_roots=forbidden_roots,
    ).splitlines()
    if len(commits) > _RELEASE_HISTORY_LIMIT:
        raise Error("release.lineage", "release manifest history exceeds its bound")
    manifests: list[JSONObject] = []
    for commit in commits:
        completed = _run(
            _git_arguments(root, "show", "--no-textconv", f"{commit}:{_RELEASE_FILE}"),
            cwd=root,
            environment=_git_environment(),
            forbidden_roots=forbidden_roots,
        )
        if completed.returncode != 0:
            raise Error("release.lineage", "release manifest history is unreadable")
        try:
            manifest = parse_canonical_document(completed.stdout.encode(), kind="release-manifest")
        except Error:
            raise Error("release.lineage", "release manifest history is invalid") from None
        manifests.append(_manifest(manifest, "release.lineage"))
    return tuple(manifests)


def _require_release_lineage(  # noqa: PLR0913
    history: tuple[JSONObject, ...],
    source_root: Path,
    source_head: str,
    source_identity: str,
    distribution_identity: str,
    audience: str,
    forbidden_roots: tuple[Path, ...],
) -> None:
    for manifest in history:
        if manifest.get("sourceRepositoryIdentity") != source_identity:
            raise Error("release.owner", "release manifest history belongs to another source")
        if manifest.get("distributionIdentity") != distribution_identity:
            raise Error("release.owner", "release manifest history names another distribution")
        if manifest.get("audience") != audience:
            raise Error(
                "release.audience",
                "audience changed; use a separate mirror and history",
            )
        previous = cast(str, manifest["sourceCommit"])
        if len(previous) != len(source_head):
            raise Error("release.lineage", "release manifest history is invalid")
        try:
            _require_ancestor(source_root, previous, source_head, forbidden_roots)
        except Error as error:
            if error.code == "release.ancestry":
                raise
            raise Error("release.lineage", "release source history is unavailable") from None


def _require_target_lineage(history: tuple[JSONObject, ...], digest: str) -> None:
    for manifest in history:
        prior = manifest.get("targetVerificationDigest")
        if prior != digest:
            raise Error(
                "release.target-lineage",
                f"history target digest is {prior}; expected {digest}; repair: use a fresh mirror "
                "and history",
            )


def _target_text(target: JSONObject, key: str) -> str:
    value = target.get(key)
    if not isinstance(value, str) or not value:
        raise Error("target.shape", f"target {key} is invalid")
    return value


def verify_github_target(target: JSONObject, forbidden_roots: tuple[Path, ...]) -> JSONObject:
    host = _target_text(target, "hostname")
    repository = _target_text(target, "nameWithOwner")
    expected = _target_text(target, "expectedVisibility")
    environment = {
        key: value for key, value in os.environ.items() if key not in {"GH_FORCE_TTY", "GH_REPO"}
    }
    environment.update({"GH_HOST": host, "GH_PROMPT_DISABLED": "1"})
    completed = _run(
        ["gh", "repo", "view", "--json", "nameWithOwner,visibility", "--", repository],
        cwd=Path("/"),
        environment=environment,
        forbidden_roots=forbidden_roots,
        output_limit=_TARGET_OUTPUT_LIMIT,
    )
    if completed.returncode != 0:
        raise Error("target.unverified", "target query failed; repo unchanged; fix auth/target")
    try:
        value = json.loads(completed.stdout)
    except (ValueError, OverflowError, RecursionError):
        raise Error("target.output", "invalid JSON; repo unchanged; fix GitHub CLI") from None
    if not isinstance(value, dict) or set(value) != {"nameWithOwner", "visibility"}:
        raise Error("target.output", "target fields invalid; repo unchanged; fix GitHub CLI")
    if value.get("nameWithOwner") != repository or value.get("visibility") != expected:
        raise Error(
            "target.mismatch",
            f"observed target differs: "
            f"{value.get('nameWithOwner')}/{value.get('visibility')}; expected "
            f"{repository}/{expected}; repository unchanged; repair: correct target or access",
        )
    return {"provider": "github", "hostname": host, **cast(JSONObject, value)}


def _remote_identity(url: str) -> tuple[str, str]:
    scp = re.fullmatch(r"([^/@:]+)@([^/:]+):(.+)", url)
    if scp is not None:
        user, host, path = scp.groups()
        if user != "git" or any(value in path for value in ("?", "#")):
            raise Error(
                "remote.url", "unsupported credentials/endpoint; repo unchanged; correct remote URL"
            )
    else:
        try:
            parsed = urlparse(url)
            host, port = parsed.hostname or "", parsed.port
        except ValueError:
            raise Error(
                "remote.url", "unsupported credentials/endpoint; repo unchanged; correct remote URL"
            ) from None
        if (
            parsed.scheme not in {"https", "ssh"}
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or port is not None
            or (parsed.scheme == "ssh" and parsed.username != "git")
            or (parsed.scheme != "ssh" and parsed.username is not None)
        ):
            raise Error(
                "remote.url", "unsupported credentials/endpoint; repo unchanged; correct remote URL"
            )
        path = parsed.path
    repository = path.strip("/")
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not host or repository.count("/") != 1:
        raise Error("remote.url", "remote URL malformed; repo unchanged; set host/repository")
    return host.casefold(), repository


def _remote_binding(
    root: Path, target: JSONObject, forbidden_roots: tuple[Path, ...]
) -> JSONObject:
    remote = _target_text(target, "remote")
    override_patterns = [
        rf"remote\.{re.escape(remote)}\.(vcs|receivepack|mirror)",
        r"url\..+\.(insteadof|pushinsteadof)",
        r"core\.(sshcommand|askpass)",
        r"credential(\..+)?\.helper",
        r"push\.pushoption",
    ]

    def refuse_overrides(patterns: list[str]) -> None:
        values = _git(
            root,
            "config",
            "--local",
            "--includes",
            "--name-only",
            "--get-regexp",
            f"^({'|'.join(patterns)})$",
            forbidden_roots=forbidden_roots,
            allowed=(0, 1),
        )
        if values:
            raise Error(
                "remote.config",
                "local Git configuration overrides push; repo unchanged; remove it",
            )

    refuse_overrides(override_patterns)

    def urls(key: str) -> tuple[str, ...]:
        return tuple(
            _nul_records(
                _git(
                    root,
                    "config",
                    "--local",
                    "--includes",
                    "--null",
                    "--get-all",
                    key,
                    forbidden_roots=forbidden_roots,
                    allowed=(0, 1),
                )
            )
        )

    fetch = urls(f"remote.{remote}.url")
    push = urls(f"remote.{remote}.pushurl") or fetch
    if not fetch or not push:
        raise Error("remote.missing", "remote incomplete; repo unchanged; set fetch/push URL")
    if any(
        ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
        for value in (*fetch, *push)
        for character in value
    ):
        raise Error("remote.url", "remote URL has controls; repo unchanged; correct URL")
    if any(value.startswith("https://") for value in (*fetch, *push)):
        refuse_overrides([r"http\..+"])
    expected = (
        _target_text(target, "hostname").casefold(),
        _target_text(target, "nameWithOwner"),
    )
    identities = {_remote_identity(value) for value in (*fetch, *push)}
    if identities != {expected}:
        raise Error(
            "remote.mismatch", "remote URLs differ; repository unchanged; correct remote/target"
        )
    return {
        "nameDigest": _hash(remote.encode()),
        "fetchUrlDigests": [_hash(value.encode()) for value in fetch],
        "pushUrlDigests": [_hash(value.encode()) for value in push],
    }


def _skills_payload(members: tuple[Skill, ...]) -> Tree:
    files: list[File] = []
    directories: list[Directory] = []
    for skill in members:
        nested_files, nested_dirs = _prefix(skill.tree, skill.name)
        files.extend(nested_files)
        directories.extend(nested_dirs)
    payload = assemble(files, directories)
    for path in [item.path for item in payload.directories] + [item.path for item in payload.files]:
        _release_path(path)
    return payload


def _git_blob_oid(data: bytes, algorithm: str) -> str:
    if algorithm not in {"sha1", "sha256"}:
        raise Error("git.object-format", "Git object format is unsupported")
    return hashlib.new(algorithm, f"blob {len(data)}\0".encode() + data).hexdigest()


def _git_file_mode(mode: int) -> str:
    return f"100{git_mode(mode):o}"


def _require_head_files(  # noqa: PLR0913
    root: Path,
    head: str,
    scopes: list[str],
    files: list[File],
    refusal: tuple[str, str],
    forbidden_roots: tuple[Path, ...],
) -> None:
    code, message = refusal
    algorithm = _git(root, "rev-parse", "--show-object-format", forbidden_roots=forbidden_roots)
    expected: dict[str, tuple[str, str]] = {}
    for item in files:
        if item.path in expected:
            raise Error("git.projection", "release-owned projection contains duplicates")
        expected[item.path] = (_git_file_mode(item.mode), _git_blob_oid(item.data, algorithm))
    actual: dict[str, tuple[str, str]] = {}
    for record in _nul_records(
        _git(
            root,
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            head,
            "--",
            *scopes,
            forbidden_roots=forbidden_roots,
        )
    ):
        try:
            metadata, path = record.split("\t", 1)
            mode, kind, object_id = metadata.split(" ")
        except ValueError:
            raise Error("git.output", "Git returned malformed tree records") from None
        if path in actual or kind != "blob":
            raise Error(code, message)
        actual[path] = (mode, object_id)
    if actual != expected:
        raise Error(code, message)


def _source_head(inspection: Inspection, head: str, forbidden_roots: tuple[Path, ...]) -> None:
    if inspection.config is None:
        raise Error("release.config", "repository configuration is unavailable")
    root = inspection.root
    files: list[File] = []
    scopes = ["remek.json", "remek", "gate", ".remek"]
    for name in ("remek.json", "remek", "gate"):
        item = read(root / name)
        files.append(File(name, item.data, item.identity.mode))
    governance_files, _ = _prefix(snapshot(root / ".remek"), ".remek")
    files.extend(governance_files)
    for skill in inspection.skills:
        prefix = f"{inspection.config.skills_root}/{skill.name}"
        candidate_files, _ = _prefix(skill.tree, prefix)
        files.extend(candidate_files)
        scopes.append(prefix)
    _require_head_files(
        root,
        head,
        scopes,
        files,
        ("release.source-head", "source files differ from raw HEAD"),
        forbidden_roots,
    )


def _mirror_head(root: Path, head: str, forbidden_roots: tuple[Path, ...]) -> None:
    payload_files: list[File] = []
    if exists(root / "skills"):
        payload_files, _ = _prefix(snapshot(root / "skills"), "skills")
    manifest = read(root / _RELEASE_FILE)
    payload_files.append(File(_RELEASE_FILE, manifest.data, manifest.identity.mode))
    _require_head_files(
        root,
        head,
        ["skills", _RELEASE_FILE],
        payload_files,
        ("release.mirror-head", "managed mirror files differ from raw HEAD"),
        forbidden_roots,
    )


def _inventory(tree: Tree) -> tuple[list[JSONValue], list[JSONValue]]:
    if not tree.files and not tree.directories:
        return [], []
    directories: list[JSONValue] = [{"path": "skills", "mode": tree.root_mode}]
    directories.extend(
        {"path": f"skills/{item.path}", "mode": item.mode} for item in tree.directories
    )
    files: list[JSONValue] = [
        {
            "path": f"skills/{item.path}",
            "mode": item.mode,
            "sha256": _hash(item.data),
        }
        for item in tree.files
    ]
    return directories, files


def _tree_file_index(tree: Tree) -> dict[str, tuple[int, str]]:
    return {item.path: (git_mode(item.mode), _hash(item.data)) for item in tree.files}


def _commit_paths(destination: Path, payload: Tree) -> list[str]:
    current = snapshot(destination) if exists(destination) else assemble([])
    before, after = _tree_file_index(current), _tree_file_index(payload)
    paths = [
        f"skills/{path}"
        for path in sorted(set(before) | set(after))
        if before.get(path) != after.get(path)
    ]
    return [*paths, _RELEASE_FILE]


def _release(  # noqa: PLR0913
    inspection: Inspection,
    dist: str,
    members: tuple[Skill, ...],
    payload: Tree,
    source: JSONObject,
    *,
    target_lineage_digest: str,
    pre_release_head: str | None,
    remote_binding: JSONValue,
    expected_paths: list[str],
) -> tuple[bytes, JSONObject]:
    if inspection.config is None:
        raise Error("release.config", "repository configuration is unavailable")
    distribution = inspection.distribution(dist)
    candidates: list[JSONValue] = [
        {"name": item.name, "candidate": item.digest} for item in members
    ]
    distribution_digest = _hash(distribution.render())
    release_set = _hash(
        render(
            "release-set",
            {
                "distribution": distribution.distribution_id,
                "distributionDigest": distribution_digest,
                "candidates": candidates,
                "payloadDigest": payload.digest,
                "reviewDigest": distribution.active_review,
            },
        )
    )
    source_commit = cast(str, source["head"])
    release_id = _hash(
        render(
            "release-identity",
            {
                "sourceRepositoryId": inspection.config.repository_id,
                "sourceCommit": source_commit,
                "distribution": distribution.distribution_id,
                "releaseSetDigest": release_set,
                "payloadDigest": payload.digest,
                "reviewDigest": distribution.active_review,
            },
        )
    )
    directories, files = _inventory(payload)
    fields: JSONObject = {
        "audience": distribution.audience,
        "sourceRepositoryIdentity": _hash(inspection.config.repository_id.encode()),
        "sourceCommit": source_commit,
        "sourceBranchDigest": _text_digest(source["branch"]),
        "distributionIdentity": _hash(distribution.distribution_id.encode()),
        "releaseId": release_id,
        "releaseSetDigest": release_set,
        "payloadDigest": payload.digest,
        "reviewDigest": distribution.active_review,
        "candidates": candidates,
        "directories": directories,
        "files": files,
        "targetVerificationDigest": target_lineage_digest,
        "preReleaseHead": pre_release_head,
        "remoteBinding": remote_binding,
        "expectedCommitPaths": cast(list[JSONValue], expected_paths),
    }
    document: JSONObject = {"schema": SCHEMA, "kind": "release-manifest", **fields}
    nodes = value_count(document)
    if nodes > MAX_ITEMS:
        raise Error(
            "release.bounds",
            f"release has {len(members)} skills, {len(files)} files, and {nodes} JSON values; "
            f"limit is {MAX_ITEMS}",
        )
    _manifest(document, "release.manifest")
    try:
        output = render("release-manifest", fields)
    except Error as exc:
        if exc.code == "operation.refused" and exc.message.startswith("JSON exceeds"):
            raise Error(
                "release.bounds",
                f"release manifest exceeds canonical JSON bounds: {exc.message}",
            ) from None
        raise
    return output, fields


def _load_release_manifest(path: Path) -> JSONObject:
    file = read(path)
    if git_mode(file.identity.mode) != 0o644:
        raise Error("release.manifest", "release manifest mode is not Git-portable")
    document = parse_canonical_document(file.data, kind="release-manifest")
    return _manifest(document, "release.manifest")


def _verify_payload(root: Path, manifest: JSONObject) -> None:
    declared_empty = manifest.get("directories") == [] and manifest.get("files") == []
    if declared_empty:
        if exists(root / "skills"):
            raise Error("release.payload", "empty release must not materialize skills")
        tree = assemble([])
    else:
        tree = git_tree(snapshot(root / "skills", reject_bytecode=True))
    directories, files = _inventory(tree)
    if manifest.get("directories") != directories or manifest.get("files") != files:
        raise Error("release.payload", "managed payload inventory differs from manifest")


def verify_materialized_release(root: Path) -> JSONObject:
    selected = checked(root)
    manifest = _load_release_manifest(selected / _RELEASE_FILE)
    _verify_payload(selected, manifest)
    return manifest


def _release_source(
    root: Path,
    dist: str,
    forbidden_roots: tuple[Path, ...],
    destination: str,
) -> tuple[Inspection, Distribution, tuple[Skill, ...], Tree, JSONObject]:
    inspection = inspect(root)
    blocking = next(
        (item for item in release_findings(inspection, dist) if item.severity == "error"), None
    )
    if blocking:
        message = blocking.message.replace(
            "; source unchanged;", f"; source and {destination} unchanged;", 1
        )
        if message == blocking.message:
            message += f"; source and {destination} unchanged"
        path = f" {blocking.path}" if blocking.path else ""
        raise Error("release.readiness", f"{blocking.code}{path}: {message}")
    distribution = inspection.distribution(dist)
    skills = {item.name: item for item in inspection.skills}
    members = tuple(skills[name] for name in distribution.skills)
    payload = _skills_payload(members)
    source = _git_state(root, forbidden_roots)
    _source_head(inspection, cast(str, source["head"]), forbidden_roots)
    return inspection, distribution, members, payload, source


def _mirror_context(  # noqa: PLR0913
    root: Path,
    selected: Path,
    inspection: Inspection,
    distribution: Distribution,
    source: JSONObject,
    forbidden_roots: tuple[Path, ...],
) -> tuple[JSONObject, tuple[JSONObject, ...]]:
    state = _git_state(selected, forbidden_roots)
    expected_branch = distribution.target.get("branch")
    if state.get("branch") != expected_branch:
        raise Error(
            "release.branch",
            f"mirror branch is {state.get('branch')}; expected {expected_branch}; repository "
            f"unchanged; repair: switch the mirror to {expected_branch} or review a new target",
        )
    history = _release_history(selected, forbidden_roots)
    config = cast(Config, inspection.config)
    _require_release_lineage(
        history,
        root,
        cast(str, source["head"]),
        _hash(config.repository_id.encode()),
        _hash(distribution.distribution_id.encode()),
        distribution.audience,
        forbidden_roots,
    )
    return state, history


def release_plan(  # noqa: PLR0915
    root: Path,
    dist: str,
    *,
    mirror: Path | None = None,
    staging: Path | None = None,
    adopt: bool = False,
) -> Plan:
    root = checked(root)
    if (mirror is None) == (staging is None):
        raise Error("release.destination", "choose exactly one of --mirror or --staging")
    destination: Path | None = None
    if staging is not None:
        selected_staging = staging.expanduser().absolute()
        parent = checked(selected_staging.parent)
        destination = parent / selected_staging.name
        forbidden_roots = (root, destination)
    else:
        selected_mirror = checked(cast(Path, mirror))
        forbidden_roots = (root, selected_mirror)
    inspection, distribution, members, payload, source = _release_source(
        root,
        dist,
        forbidden_roots,
        "staging" if staging is not None else "mirror",
    )
    inputs: JSONObject = {
        "distribution": dist,
        "mirror": None,
        "staging": None,
        "adopt": adopt,
    }
    if staging is not None:
        assert destination is not None
        parent = destination.parent
        if (
            exists(destination)
            or paths_related(root, destination)
            or _git_checkout_containing(parent, forbidden_roots) is not None
        ):
            raise Error("release.staging", "staging conflict; none created; choose external path")
        manifest_data, manifest = _release(
            inspection,
            dist,
            members,
            payload,
            source,
            target_lineage_digest="not-performed",
            pre_release_head=None,
            remote_binding=None,
            expected_paths=[],
        )
        files: list[File] = []
        directories: list[Directory] = []
        if payload.files or payload.directories:
            files, directories = _prefix(payload, "skills")
        files.append(File(_RELEASE_FILE, manifest_data, 0o644))
        tree = assemble(files, directories)
        change = tree_change(parent, destination, tree, "materialize unverified staging payload")
        inputs["staging"] = str(destination)
        return Plan(
            "release",
            root,
            (change,),
            inputs,
            bindings={"sourceGit": source, "releaseId": manifest["releaseId"]},
            data={
                "releaseId": manifest["releaseId"],
                "reviewDigest": manifest["reviewDigest"],
                "mode": "staging",
                "targetVerified": False,
                "publicationPerformed": False,
            },
        )
    selected = selected_mirror
    if paths_related(root, selected):
        raise Error("release.mirror", "mirror overlaps source; both unchanged; choose another")
    mirror_state, history = _mirror_context(
        root, selected, inspection, distribution, source, forbidden_roots
    )
    future_paths = "".join(f"skills/{item.path}\0" for item in payload.files) + _RELEASE_FILE + "\0"
    _guard_git_attributes(selected, future_paths, forbidden_roots)
    old_path = selected / _RELEASE_FILE
    old: JSONObject | None = None
    if exists(old_path):
        old = _load_release_manifest(old_path)
        _verify_payload(selected, old)
        _mirror_head(selected, cast(str, mirror_state["head"]), forbidden_roots)
    elif exists(selected / "skills") and not adopt:
        raise Error(
            "release.adoption",
            "unmanifested skills; mirror unchanged; use --adopt-existing or fresh mirror",
        )
    remote = _remote_binding(selected, distribution.target, forbidden_roots)
    target = verify_github_target(distribution.target, forbidden_roots)
    target_lineage = _target_lineage_digest(distribution.target, target)
    _require_target_lineage(history, target_lineage)
    expected_paths = _commit_paths(selected / "skills", payload)
    manifest_data, manifest = _release(
        inspection,
        dist,
        members,
        payload,
        source,
        target_lineage_digest=target_lineage,
        pre_release_head=cast(str, mirror_state["head"]),
        remote_binding=remote,
        expected_paths=expected_paths,
    )
    if old is not None and old.get("releaseId") == manifest.get("releaseId"):
        changing = {"schema", "kind", "preReleaseHead", "expectedCommitPaths"}
        if {key: value for key, value in old.items() if key not in changing} != {
            key: value for key, value in manifest.items() if key not in changing
        }:
            raise Error("release.identity", "release id context differs")
        _release_commit(selected, old, forbidden_roots)
        return Plan(
            "release",
            root,
            (),
            {**inputs, "mirror": str(selected)},
            bindings={
                "sourceGit": source,
                "mirrorGit": mirror_state,
                "remote": remote,
                "target": target,
            },
            data={
                "releaseId": manifest["releaseId"],
                "reviewDigest": manifest["reviewDigest"],
                "mode": "managed",
                "targetVerified": True,
                "publicationPerformed": False,
            },
        )
    skills_path = selected / "skills"
    payload_change = (
        tree_change(
            selected,
            skills_path,
            payload,
            "materialize exact distribution payload",
        )
        if payload.files or payload.directories
        else delete_change(
            selected,
            skills_path,
            "clear the exact distribution payload",
        )
    )
    changes = list(_one(payload_change))
    changes.extend(
        _one(write(selected, old_path, manifest_data, "record deterministic release manifest"))
    )
    inputs["mirror"] = str(selected)
    return Plan(
        "release",
        root,
        tuple(changes),
        inputs,
        bindings={
            "sourceGit": source,
            "mirrorGit": mirror_state,
            "remote": remote,
            "target": target,
            "releaseId": manifest["releaseId"],
            "adoptedIdentity": payload_change.expected if old is None and adopt else None,
        },
        data={
            "releaseId": manifest["releaseId"],
            "reviewDigest": manifest["reviewDigest"],
            "mirror": str(selected),
            "mode": "managed",
            "targetVerified": True,
            "publicationPerformed": False,
        },
    )


def _release_commit(
    root: Path, manifest: JSONObject, forbidden_roots: tuple[Path, ...]
) -> tuple[str, str, tuple[str, ...]]:
    parents = _git(
        root,
        "rev-list",
        "--parents",
        "-n",
        "1",
        "HEAD",
        forbidden_roots=forbidden_roots,
    ).split()
    if len(parents) != 2 or parents[1] != manifest.get("preReleaseHead"):
        raise Error("release.commit", "mirror HEAD is not one commit over its bound parent")
    changed = sorted(
        _nul_records(
            _git(
                root,
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--name-only",
                "-z",
                parents[1],
                parents[0],
                forbidden_roots=forbidden_roots,
            )
        )
    )
    expected = manifest.get("expectedCommitPaths")
    if (
        not isinstance(expected, list)
        or not all(isinstance(item, str) for item in expected)
        or changed != sorted(cast(list[str], expected))
        or _RELEASE_FILE not in changed
        or any(path != _RELEASE_FILE and not path.startswith("skills/") for path in changed)
    ):
        raise Error("release.commit", "release commit changed unexpected paths")
    return parents[0], parents[1], tuple(changed)


def release_verify(root: Path, dist: str, mirror: Path) -> dict[str, object]:
    root = checked(root)
    selected = checked(mirror)
    forbidden_roots = (root, selected)
    inspection, distribution, members, payload, source = _release_source(
        root, dist, forbidden_roots, "mirror"
    )
    manifest = _load_release_manifest(selected / _RELEASE_FILE)
    if manifest.get("targetVerificationDigest") == "not-performed":
        raise Error("release.staging", "staging output lacks managed target verification")
    if manifest.get("distributionIdentity") != _hash(dist.encode()):
        raise Error("release.distribution", "manifest distribution differs")
    if manifest.get("audience") != distribution.audience:
        raise Error(
            "release.audience",
            "audience changed; use a separate mirror and history",
        )
    if manifest.get("sourceCommit") != source.get("head"):
        raise Error(
            "release.source",
            f"actual source commit is {source.get('head')}; expected manifest-bound "
            f"{manifest.get('sourceCommit')}; source and mirror unchanged; repair: restore the "
            "bound source commit, or prepare and verify a fresh release from the current source",
        )
    branch_digest = _text_digest(source.get("branch"))
    if manifest.get("sourceBranchDigest") != branch_digest:
        raise Error(
            "release.source",
            f"actual source branch digest is {branch_digest}; expected manifest-bound "
            f"{manifest.get('sourceBranchDigest')}; source and mirror unchanged; repair: switch "
            "to the bound source branch, or prepare and verify a fresh release",
        )
    mirror_state, history = _mirror_context(
        root, selected, inspection, distribution, source, forbidden_roots
    )
    _verify_payload(selected, manifest)
    _mirror_head(selected, cast(str, mirror_state["head"]), forbidden_roots)
    _, parent, changed = _release_commit(selected, manifest, forbidden_roots)
    remote = _remote_binding(selected, distribution.target, forbidden_roots)
    if remote != manifest.get("remoteBinding"):
        actual_remote = _hash(json.dumps(remote, sort_keys=True, separators=(",", ":")).encode())
        expected_remote = _hash(
            json.dumps(
                manifest.get("remoteBinding"), sort_keys=True, separators=(",", ":")
            ).encode()
        )
        raise Error(
            "release.remote",
            f"actual remote-binding digest is {actual_remote}; expected {expected_remote}; "
            "mirror unchanged; repair: restore the manifest-bound remote alias and URLs, or "
            "prepare a fresh release after any distribution change and required reapproval",
        )
    target = verify_github_target(distribution.target, forbidden_roots)
    target_lineage = _target_lineage_digest(distribution.target, target)
    if target_lineage != manifest.get("targetVerificationDigest"):
        raise Error(
            "release.target",
            f"actual target-lineage digest is {target_lineage}; expected "
            f"{manifest.get('targetVerificationDigest')}; mirror unchanged; repair: restore the "
            "approved GitHub target and visibility, or use a fresh approved distribution and "
            "fresh mirror history for a semantic target change",
        )
    _require_target_lineage(history, target_lineage)
    manifest_data, _ = _release(
        inspection,
        dist,
        members,
        payload,
        source,
        target_lineage_digest=target_lineage,
        pre_release_head=parent,
        remote_binding=remote,
        expected_paths=[
            *(path for path in changed if path.startswith("skills/")),
            _RELEASE_FILE,
        ],
    )
    if read(selected / _RELEASE_FILE).data != manifest_data:
        raise Error("release.manifest", "release manifest differs from bound identities")
    return {
        "artifactVerified": True,
        "sourceReadinessVerified": True,
        "targetVerified": True,
        "commitLineageVerified": True,
        "publicationPerformed": False,
        "reviewDigest": manifest.get("reviewDigest"),
        "releaseId": manifest.get("releaseId"),
        "sourceCommit": manifest.get("sourceCommit"),
        "mirrorCommit": mirror_state.get("head"),
        "target": target,
    }
