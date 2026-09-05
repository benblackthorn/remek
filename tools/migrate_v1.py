#!/usr/bin/env python3
# ruff: noqa: D100, D101, D103, E402

import argparse
import hashlib
import json
import os
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from tempfile import mkdtemp
from typing import TextIO, cast

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "skills/remek/toolchain"
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
os.environ["REMEK_BOOTSTRAP"] = str(ROOT / "skills/remek/scripts/cli.py")

from skills.remek.toolchain.runtime.remek_core.contract import (
    JSONObject,
    JSONValue,
    _constant,
    _float,
    _pairs,
    parse_document,
    render_document,
    value_count,
)
from skills.remek.toolchain.runtime.remek_core.filesystem import (
    OpenedBoundary,
    Tree,
    TreeDirectory,
    TreeFile,
    checked_path,
    checked_root,
    directory_members,
    entry_exists,
    fingerprint,
    git_mode,
    git_tree,
    is_private_name,
    paths_related,
    portable_path,
    read_artifact,
    read_regular,
    remove_at,
    snapshot_tree,
    tree_from_entries,
    write_artifact,
    write_tree_at,
)
from skills.remek.toolchain.runtime.remek_core.model import RemekError, safe_text
from skills.remek.toolchain.runtime.remek_core.plans import (
    LoadedPlan,
    Plan,
    SourceBinding,
    load_operation_plan,
    operation_document,
    plan_diff,
    validate_output_path,
    verify_operation_plan,
)
from skills.remek.toolchain.runtime.remek_core.repository import (
    Config,
    inspect_repository,
    new_config,
    parse_disclosure,
    parse_distribution,
    parse_skill_record,
    repository_findings,
)
from skills.remek.toolchain.runtime.remek_core.transaction import (
    ApplyOutcome,
    Change,
    apply_changes,
    tree_change,
    write_change,
)
from skills.remek.toolchain.runtime.remek_core.workflows import (
    _git,
    _git_blob_oid,
    _guard_git_worktree,
)


@dataclass(frozen=True)
class Inventory:
    root: Path
    config: Config
    tree: Tree
    report: JSONObject


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: JSONObject) -> bytes:
    if value_count(value) > 32768:
        raise RemekError("migration.limit", "private migration inventory exceeds 32768 values")
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    if len(data) > 1024 * 1024:
        raise RemekError("migration.limit", "private migration inventory exceeds 1 MiB")
    return data


def _legacy(data: bytes, kind: str, path: str) -> JSONObject:
    try:
        if len(data) > 64 * 1024:
            raise RemekError("migration.limit", "legacy declaration exceeds 64 KiB")
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_float=_float,
        )
        if not isinstance(value, dict) or value_count(value) > 4096:
            raise RemekError("migration.json", "legacy JSON exceeds its object/value limits")
        if value.get("schema") != "remek.1" or value.get("kind") != kind:
            raise RemekError("migration.schema", f"expected remek.1 {kind}; mixed schema refused")
        return cast(JSONObject, value)
    except (ValueError, UnicodeError, RecursionError, RemekError) as exc:
        raise RemekError("migration.declaration", f"{path}: {exc}") from None


def _keys(document: JSONObject, names: set[str], path: str) -> None:
    if set(document) != {"schema", "kind", *names}:
        missing = sorted(names - document.keys())
        raise RemekError(
            "migration.fields", f"{path}: missing or unknown declaration fields; missing={missing}"
        )


def _text(document: JSONObject, name: str, path: str, limit: int, *, empty: bool = False) -> str:
    value = document.get(name)
    if not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()):
        raise RemekError("migration.fields", f"{path}: invalid or missing {name}")
    return value


def _append_tree(
    files: list[TreeFile], directories: list[TreeDirectory], prefix: str, tree: Tree
) -> None:
    directories.append(TreeDirectory(prefix, tree.root_mode))
    directories.extend(
        TreeDirectory(f"{prefix}/{item.path}", item.mode) for item in tree.directories
    )
    files.extend(TreeFile(f"{prefix}/{item.path}", item.data, item.mode) for item in tree.files)


def _owned_tree(root: Path, config: Config) -> Tree:
    files: list[TreeFile] = []
    directories: list[TreeDirectory] = []
    for relative in ("remek.json", "remek", "gate", "README.md", ".gitignore"):
        path = checked_path(root, root / relative)
        if entry_exists(path):
            item = read_regular(path)
            files.append(TreeFile(relative, item.data, item.identity.mode))
    _append_tree(files, directories, ".remek", snapshot_tree(root / ".remek", reject_bytecode=True))
    skills_root = config.skills_root
    parts = skills_root.split("/")
    for index in range(1, len(parts) + 1):
        relative = "/".join(parts[:index])
        path = checked_path(root, root / relative)
        if not entry_exists(path) and not config.governed_skills:
            continue
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise RemekError("migration.layout", f"{relative}: expected a real directory")
        directories.append(TreeDirectory(relative, stat.S_IMODE(path.lstat().st_mode)))
    for name in config.governed_skills:
        relative = f"{skills_root}/{name}"
        path = checked_path(root, root / relative)
        _append_tree(files, directories, relative, snapshot_tree(path, reject_bytecode=True))
    return tree_from_entries(files, directories)


def _foreign(root: Path, tree: Tree, config: Config) -> list[JSONValue]:
    owned = {item.path for item in tree.files} | {item.path for item in tree.directories}
    result: list[JSONValue] = []
    for relative in ("", config.skills_root):
        if not entry_exists(root / relative):
            continue
        for member in directory_members(root / relative):
            path = f"{relative}/{member.name}".lstrip("/")
            if is_private_name(member.name):
                raise RemekError(
                    "migration.residue", f"{path}: transaction residue requires diagnosis"
                )
            if path in owned:
                continue
            mode = member.mode
            classification = (
                "directory"
                if stat.S_ISDIR(mode)
                else "link"
                if stat.S_ISLNK(mode)
                else "file"
                if stat.S_ISREG(mode)
                else "special"
            )
            result.append(
                {
                    "path": path,
                    "classification": classification,
                    "disposition": ("foreign; owner must verify backup and history coverage"),
                }
            )
    return result


def _git_inventory(root: Path, tree: Tree, forbidden: tuple[Path, ...]) -> JSONObject:
    if not entry_exists(root / ".git"):
        return {"present": False, "historyBackup": "owner must inventory any separate history"}
    _guard_git_worktree(root, forbidden)
    head = _git(root, "rev-parse", "--verify", "HEAD", forbidden_roots=forbidden, allowed=(0, 128))
    branch = _git(
        root, "symbolic-ref", "--quiet", "HEAD", forbidden_roots=forbidden, allowed=(0, 1)
    )
    status = _git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
        forbidden_roots=forbidden,
    )
    refs = _git(
        root, "for-each-ref", "--format=%(refname) %(objectname)", forbidden_roots=forbidden
    )
    changed: list[JSONValue] = []
    if head:
        algorithm = _git(root, "rev-parse", "--show-object-format", forbidden_roots=forbidden)
        entries = _git(root, "ls-tree", "-rz", "HEAD", forbidden_roots=forbidden)
        index = {}
        for entry in entries.split("\0"):
            if entry:
                metadata, path = entry.split("\t", 1)
                mode, _, oid = metadata.split(" ")
                index[path] = (mode, oid)
        for item in tree.files:
            mode = "100755" if git_mode(item.mode) == 0o755 else "100644"
            if index.get(item.path) != (mode, _git_blob_oid(item.data, algorithm)):
                changed.append(item.path)
    return {
        "workingOwnedPathsDifferentFromRawHead": changed,
        "present": True,
        "head": head,
        "branch": branch,
        "workingState": status,
        "refs": refs,
        "historyBackup": (
            "separate owner-verified Git bundle required; archive does not preserve history"
        ),
    }


def _inventory_v1(source: Path, forbidden: tuple[Path, ...] = ()) -> Inventory:
    root = checked_root(source)
    config = _legacy(read_regular(root / "remek.json").data, "repository", "remek.json")
    _keys(config, {"repositoryId", "skillsRoot", "governedSkills"}, "remek.json")
    names = config.get("governedSkills")
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise RemekError("migration.fields", "remek.json: invalid governedSkills")
    normalized = new_config(
        cast(str, config.get("repositoryId")),
        skills_root=cast(str, config.get("skillsRoot")),
        governed_skills=tuple(cast(list[str], names)),
    )
    tree = _owned_tree(root, normalized)
    _known_governance(tree, cast(list[str], names))
    report: JSONObject = {
        "source": str(root),
        "repository": config,
        "ownedFiles": [
            {
                "path": item.path,
                "bytes": len(item.data),
                "sha256": _hash(item.data),
                "mode": f"{git_mode(item.mode):o}",
            }
            for item in tree.files
        ],
        "ownedDirectories": [
            {"path": item.path, "mode": f"{item.mode:o}"} for item in tree.directories
        ],
        "foreignNeighbors": _foreign(root, tree, normalized),
        "git": _git_inventory(root, tree, forbidden or (root, ROOT)),
        "externalArtifacts": (
            "Owner must inventory raw reports, incomplete workspaces, installations and mirror "
            "histories separately; availability is unknown"
        ),
    }
    _json(report)
    return Inventory(root, normalized, tree, report)


def _known_governance(tree: Tree, names: list[str]) -> None:
    declarations = {"policy.json", "provenance.json", "routing-cases.json", "behavior-cases.json"}
    for item in tree.files:
        if not item.path.startswith(".remek/"):
            continue
        parts = item.path.split("/")
        known = item.path == ".remek/disclosure-policy.json" or parts[1] == "toolchain"
        known |= parts[1] == "distributions" and len(parts) == 3
        if parts[1] == "skills" and len(parts) >= 4 and parts[2] in names:
            known |= (len(parts) == 4 and parts[3] in declarations) or (
                len(parts) > 4 and parts[3] in {"sources", "evidence", "approvals"}
            )
        if not known:
            raise RemekError(
                "migration.foreign",
                f"{item.path}: unknown governance file; "
                "preserve and resolve ownership before conversion",
            )
    roots = {".remek", ".remek/skills", ".remek/distributions", ".remek/toolchain"}
    roots.update(f".remek/skills/{name}" for name in names)
    folders = [".remek/toolchain/"] + [
        f".remek/skills/{name}/{folder}/"
        for name in names
        for folder in ("sources", "evidence", "approvals")
    ]
    for directory in tree.directories:
        path = directory.path
        if (
            path.startswith(".remek/")
            and path not in roots
            and not any(path == prefix[:-1] or path.startswith(prefix) for prefix in folders)
        ):
            raise RemekError(
                "migration.foreign",
                f"{path}: unknown governance directory; preserve and resolve ownership",
            )


def _verify_archive(inventory: Inventory, archive: Path) -> Tree:
    root = checked_root(archive)
    archived = _owned_tree(root, inventory.config)
    if git_tree(archived).digest != git_tree(inventory.tree).digest:
        raise RemekError(
            "migration.archive",
            "archive owned paths, bytes or executable modes differ from source inventory",
        )
    return archived


def _skill_record(files: dict[str, TreeFile], name: str) -> tuple[bytes, JSONObject]:
    base = f".remek/skills/{name}"

    def read(filename: str, kind: str) -> JSONObject:
        path = f"{base}/{filename}"
        if path not in files:
            raise RemekError("migration.fields", f"{path}: required declaration missing")
        return _legacy(files[path].data, kind, path)

    policy = read("policy.json", "skill-policy")
    _keys(policy, {"skill", "lifecycle", "exposure", "stateReason"}, base + "/policy.json")
    lifecycle = policy.get("lifecycle")
    if (
        policy.get("skill") != name
        or lifecycle not in ("draft", "ready", "retired")
        or policy.get("exposure") not in ("source-only", "private-only", "public-eligible")
    ):
        raise RemekError("migration.fields", f"{base}/policy.json: invalid skill or lifecycle")
    _text(policy, "stateReason", base, 500)
    provenance = read("provenance.json", "provenance")
    old_fields = {
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
    }
    _keys(provenance, old_fields, base + "/provenance.json")
    if provenance.get("skill") != name:
        raise RemekError("migration.fields", f"{base}/provenance.json: wrong skill")
    label = _text(provenance, "sourceLabel", base, 128)
    portable_path(label, authored=True)
    if "/" in label or "\\" in label:
        raise RemekError("migration.source", f"{base}: legacy sourceLabel must be one filename")
    digest = _text(provenance, "sourceDigest", base, 64)
    upstream = _text(provenance, "upstreamCandidate", base, 64, empty=True)
    if any(
        len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
        for value in (digest, *([upstream] if upstream else []))
    ):
        raise RemekError("migration.source", f"{base}: invalid legacy source digest")
    retained = files.get(f"{base}/sources/{label}")
    descriptor: JSONValue = None
    note = (
        "No verifiable retained origin is present; legacy declarations remain in "
        "the verified archive."
    )
    if retained is not None:
        if _hash(retained.data) != digest:
            raise RemekError(
                "migration.source", f"{base}/sources/{label}: retained source digest differs"
            )
        descriptor = {"path": f"sources/{label}", "type": "file", "digest": digest}
        note = (
            "Exact legacy retained source file preserved; the descriptor checks those bytes only."
        )
        if provenance["origin"] == "imported":
            note = (
                "Exact legacy import manifest retained; it is not the original imported "
                "source tree. Legacy upstreamCandidate remains only in the private "
                "migration map and archive."
            )
    cases: JSONObject = {}
    for kind in ("routing", "behavior"):
        document = read(f"{kind}-cases.json", f"{kind}-cases")
        _keys(document, {"cases"}, f"{base}/{kind}-cases.json")
        cases[kind] = document["cases"]
    fields: JSONObject = {
        "skill": name,
        "exposure": "source-only" if lifecycle == "retired" else policy["exposure"],
        "provenance": {
            "origin": provenance["origin"],
            "source": descriptor,
            "sourceNote": note,
            **{
                key: provenance[key]
                for key in ("upstreamRepository", "upstreamRef", "rights", "rightsBasis", "license")
            },
        },
        "cases": cases,
    }
    data = render_document("skill-record", fields)
    parse_skill_record({"schema": "remek.2", "kind": "skill-record", **fields}, name)
    return data, {
        "skill": name,
        "oldLifecycle": lifecycle,
        "oldStateReason": policy["stateReason"],
        "oldProvenance": provenance,
        "sourceNote": note,
        "missingFacts": [
            key for key in ("rights", "rightsBasis", "license") if not provenance[key]
        ],
    }


def _convert(  # noqa: PLR0912, PLR0915
    inventory: Inventory, bundle: Path
) -> tuple[Tree, JSONObject]:
    files = {item.path: item for item in inventory.tree.files}
    result = {path: item for path, item in files.items() if not path.startswith(".remek/")}
    transformations: list[JSONValue] = []
    retired: set[str] = set()
    for name in inventory.config.governed_skills:
        data, facts = _skill_record(files, name)
        result[f".remek/skills/{name}/skill.json"] = TreeFile(
            f".remek/skills/{name}/skill.json", data, 0o644
        )
        transformations.append(facts)
        if facts["oldLifecycle"] == "retired":
            retired.add(name)
        for path, item in files.items():
            if path.startswith(f".remek/skills/{name}/sources/"):
                result[path] = item
    profiles: list[JSONValue] = []
    for path, item in files.items():
        if path.startswith(".remek/distributions/"):
            document = _legacy(item.data, "distribution", path)
            _keys(
                document,
                {
                    "id",
                    "audience",
                    "skills",
                    "target",
                    "delivery",
                    "evidencePolicy",
                    "privateDisclosure",
                },
                path,
            )
            document.update({"schema": "remek.2", "activeReview": None})
            distribution = parse_distribution(document)
            members = distribution.skills
            if not set(members) <= set(inventory.config.governed_skills):
                raise RemekError("migration.fields", f"{path}: selected skill is not governed")
            distribution = replace(
                distribution, skills=tuple(name for name in members if name not in retired)
            )
            if Path(path).name != f"{document['id']}.json":
                raise RemekError(
                    "migration.fields", f"{path}: distribution filename differs from id"
                )
            result[path] = TreeFile(path, distribution.render(), 0o644)
            profiles.append(
                {
                    "distribution": document["id"],
                    "profiles": document["evidencePolicy"],
                    "retiredSelectionsRemoved": [name for name in members if name in retired],
                    "status": (
                        "Recover configuration or owner-revise profiles; require fresh v2 "
                        "mirror lineage and new evidence/review"
                    ),
                }
            )
    path = ".remek/disclosure-policy.json"
    if path not in files:
        raise RemekError("migration.fields", f"{path}: required declaration missing")
    disclosure = _legacy(files[path].data, "disclosure-policy", path)
    _keys(disclosure, {"entries"}, path)
    entries = disclosure.get("entries")
    if not isinstance(entries, list) or len(entries) > 256:
        raise RemekError("migration.fields", f"{path}: invalid entries")
    stripped: list[JSONValue] = []
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"id", "class", "match", "value", "retired"}
            or not isinstance(entry.get("retired"), bool)
        ):
            raise RemekError("migration.fields", f"{path}: malformed disclosure entry")
        stripped.append({key: value for key, value in entry.items() if key != "retired"})
    parse_disclosure({"schema": "remek.2", "kind": "disclosure-policy", "entries": stripped})
    active = [
        value
        for entry, value in zip(entries, stripped, strict=True)
        if not cast(JSONObject, entry)["retired"]
    ]
    result[path] = TreeFile(path, render_document("disclosure-policy", {"entries": active}), 0o644)
    result["remek.json"] = TreeFile("remek.json", inventory.config.render(), 0o644)
    toolchain = snapshot_tree(bundle, reject_bytecode=True)
    prefix = _toolchain_prefix(inventory.tree)
    result = {path: item for path, item in result.items() if not path.startswith(prefix + "/")}
    for item in toolchain.files:
        path = f"{prefix}/{item.path}"
        result[path] = TreeFile(path, item.data, item.mode)
    for path, source in (
        ("remek", ROOT / "skills/remek/scripts/cli.py"),
        ("gate", bundle / "assets/gate"),
    ):
        result[path] = TreeFile(path, read_regular(source).data, 0o755)
    if prefix == "skills/remek/toolchain":
        path = "skills/remek/scripts/cli.py"
        result[path] = TreeFile(path, read_regular(ROOT / path).data, 0o755)
    retained_roots = [f".remek/skills/{name}/sources" for name in inventory.config.governed_skills]
    directories = {
        item.path: item
        for item in inventory.tree.directories
        if (
            not item.path.startswith(".remek/")
            or any(item.path == root or item.path.startswith(root + "/") for root in retained_roots)
        )
        and not item.path.startswith(prefix + "/")
    }
    for relative in (
        ".remek",
        ".remek/skills",
        ".remek/distributions",
        ".remek/reviews",
        prefix,
    ):
        directories.setdefault(relative, TreeDirectory(relative))
    for directory in toolchain.directories:
        relative = f"{prefix}/{directory.path}"
        directories[relative] = TreeDirectory(relative, directory.mode)
    for name in inventory.config.governed_skills:
        relative = f".remek/skills/{name}/evidence"
        directories[relative] = TreeDirectory(relative)
    for path in (*result, *list(directories)):
        for index in range(1, len(Path(path).parts)):
            relative = "/".join(Path(path).parts[:index])
            directories.setdefault(relative, TreeDirectory(relative))
    mapping: list[JSONValue] = []
    for path, item in files.items():
        destination: JSONValue = path if path in result else None
        disposition = (
            "preserved"
            if path in result and result[path] == item
            else "transformed"
            if path in result
            else "historical-only"
        )
        parts = Path(path).parts
        if (
            len(parts) == 4
            and parts[:2] == (".remek", "skills")
            and parts[3]
            in (
                "policy.json",
                "provenance.json",
                "routing-cases.json",
                "behavior-cases.json",
            )
        ):
            destination = str(Path(path).parent / "skill.json")
            disposition = "merged declaration; original archived"
        if (
            len(parts) > 4
            and parts[:2] == (".remek", "skills")
            and parts[3] in {"evidence", "approvals"}
        ):
            kind = "eval-receipt" if parts[3] == "evidence" else "approval"
            try:
                document = _legacy(item.data, kind, path)
                if Path(path).stem != _hash(item.data) or _json(document) != item.data:
                    raise RemekError("noncanonical record or content-address mismatch")
                disposition = (
                    "historical-only; legacy JSON parsed; semantic claims not revalidated and"
                    " never qualify as v2 evidence/review"
                )
            except RemekError:
                disposition = (
                    "historical-only; malformed legacy record; never qualifies as v2 "
                    "evidence/review"
                )
        mapping.append(
            {
                "oldPath": path,
                "archiveSha256": _hash(item.data),
                "mode": f"{git_mode(item.mode):o}",
                "activeDestination": destination,
                "disposition": disposition,
            }
        )
    return tree_from_entries(list(result.values()), list(directories.values())), {
        "inventory": inventory.report,
        "mapping": mapping,
        "managedToolchain": prefix,
        "addedFiles": [
            {"path": path, "sha256": _hash(item.data), "mode": f"{git_mode(item.mode):o}"}
            for path, item in result.items()
            if path not in files
        ],
        "skillTransformations": transformations,
        "distributionGates": profiles,
        "guarantees": (
            "Only structurally converted source data; no v1 evidence or approval "
            "qualifies; old source, backup, installed hosts and old mirrors remain "
            "untouched. Owner must verify external work/history backup before real "
            "cutover."
        ),
    }


def _toolchain_prefix(tree: Tree) -> str:
    paths = {item.path for item in tree.directories}
    present = [path for path in (".remek/toolchain", "skills/remek/toolchain") if path in paths]
    if len(present) != 1:
        raise RemekError("migration.layout", "exactly one legacy managed toolchain layout required")
    return present[0]


def _subtree(tree: Tree, prefix: str) -> Tree:
    return tree_from_entries(
        [
            TreeFile(item.path[len(prefix) + 1 :], item.data, item.mode)
            for item in tree.files
            if item.path.startswith(prefix + "/")
        ],
        [
            TreeDirectory(item.path[len(prefix) + 1 :], item.mode)
            for item in tree.directories
            if item.path.startswith(prefix + "/")
        ],
        root_mode=next(item.mode for item in tree.directories if item.path == prefix),
    )


def _conversion_plan(source: Path, target: Path, archive: Path, bundle: Path = BUNDLE) -> Plan:
    source, archive, bundle = checked_root(source), checked_root(archive), checked_root(bundle)
    target = checked_root(target.parent) / target.name
    roots = (source, target, archive, ROOT)
    if any(
        paths_related(first, second)
        for index, first in enumerate(roots)
        for second in roots[index + 1 :]
    ):
        raise RemekError(
            "migration.overlap",
            "source, target, archive and trusted producer must be disjoint non-ancestor roots",
        )
    if archive.stat().st_mode & 0o077:
        raise RemekError("migration.privacy", "verified backup root must be owner-only (0700)")
    inventory = _inventory_v1(source, roots)
    archived = _verify_archive(inventory, archive)
    expected, mapping = _convert(inventory, bundle)
    changes: list[Change] = []
    if not entry_exists(target):
        changes.append(
            tree_change(
                target.parent,
                target,
                tree_from_entries(
                    list(expected.files), list(expected.directories), root_mode=0o700
                ),
                "materialize reviewed v2 owned paths into absent private rehearsal",
            )
        )
    else:
        if not stat.S_ISDIR(target.lstat().st_mode):
            raise RemekError("migration.target", "rehearsal target must be one real directory")
        if target.stat().st_mode & 0o077:
            raise RemekError(
                "migration.privacy", "existing rehearsal root must be owner-only (0700)"
            )
        current = _owned_tree(target, inventory.config)
        _foreign(target, current, inventory.config)
        if current.digest != expected.digest:
            if current.digest != inventory.tree.digest:
                raise RemekError(
                    "migration.target",
                    (
                        "target is neither an exact inventoried v1 rehearsal nor the completed v2"
                        " conversion"
                    ),
                )
            managed: tuple[str, ...] = (".remek",)
            if _toolchain_prefix(inventory.tree) == "skills/remek/toolchain":
                managed += ("skills/remek/toolchain",)
            for prefix in managed:
                changes.append(
                    tree_change(
                        target,
                        target / prefix,
                        _subtree(expected, prefix),
                        "replace inventoried v1 governance/runtime; archive preserved",
                    )
                )
            old = {item.path: item for item in current.files}
            for item in expected.files:
                if (
                    not any(item.path.startswith(prefix + "/") for prefix in managed)
                    and old.get(item.path) != item
                ):
                    changes.append(
                        write_change(
                            target,
                            target / item.path,
                            item.data,
                            "apply enumerated v2 declaration or managed shim",
                            mode=item.mode,
                        )
                    )
    mapping.update(
        {"archive": str(archive), "target": str(target), "expectedOwnedTreeDigest": expected.digest}
    )
    inputs: JSONObject = {"source": str(source), "archive": str(archive)}
    return Plan(
        "migrate-v1",
        target,
        tuple(changes),
        inputs,
        bindings={
            "mappingDigest": _hash(_json(mapping)),
        },
        sources=(
            SourceBinding(source, f"tree:{inventory.tree.digest}"),
            SourceBinding(archive, f"tree:{archived.digest}"),
            SourceBinding(
                ROOT / "skills/remek/scripts/cli.py",
                fingerprint(ROOT / "skills/remek/scripts/cli.py"),
            ),
        ),
        data={"mapping": mapping, "expected": expected},
    )


def _reconstruct(loaded: LoadedPlan, bundle: Path = BUNDLE) -> Plan:
    if (
        loaded.command != "migrate-v1"
        or set(loaded.inputs) != {"source", "archive"}
        or loaded.generated
    ):
        raise RemekError("migration.plan", "expected a source-only migrate-v1 operation plan")
    if not all(
        isinstance(value, str) and Path(value).is_absolute() for value in loaded.inputs.values()
    ):
        raise RemekError("migration.plan", "migration inputs require absolute paths")
    plan = _conversion_plan(
        Path(cast(str, loaded.inputs["source"])),
        loaded.root,
        Path(cast(str, loaded.inputs["archive"])),
        bundle,
    )
    if not plan.changes:
        current = parse_document(operation_document(plan, bundle)[0], kind="operation-plan")
        fields = set(current) - {"changes", "planDigest"}
        if all(current[key] == loaded.document[key] for key in fields):
            return plan
    verify_operation_plan(loaded, plan, bundle)
    return plan


def _flush(stream: TextIO) -> None:
    try:
        stream.flush()
    except (Exception, KeyboardInterrupt):
        with suppress(Exception, KeyboardInterrupt):
            stream.close()
        raise


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Offline, source-only v1 to v2 rehearsal converter; validate the trusted "
            "producer checkout with its gate first."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("plan")
    for name in ("source", "target", "archive", "output"):
        create.add_argument(f"--{name}", type=Path, required=True)
    for name in ("show", "apply"):
        commands.add_parser(name).add_argument("plan", type=Path)
    outcome = ApplyOutcome(False)
    try:
        args = parser.parse_args(arguments)
        if args.command == "plan":
            plan = _conversion_plan(args.source, args.target, args.archive)
            if not plan.changes:
                print(
                    "No-op: rehearsal already matches the complete conversion; no artifact created."
                )
                _flush(sys.stdout)
                return 0
            output = validate_output_path(args.output, plan, BUNDLE)
            mapping_path = validate_output_path(Path(str(output) + ".mapping.json"), plan, BUNDLE)
            if entry_exists(output) or entry_exists(mapping_path):
                raise RemekError(
                    "migration.output", "plan or private mapping output already exists"
                )
            data, _ = operation_document(plan, BUNDLE)
            write_artifact(mapping_path, _json(cast(JSONObject, plan.data["mapping"])))
            write_artifact(output, data)
            print(
                f"Saved private plan {safe_text(output)} and mapping {safe_text(mapping_path)}. "
                "Review all transformations and owner gates before apply."
            )
        else:
            loaded = load_operation_plan(args.plan)
            plan = _reconstruct(loaded)
            mapping = _json(cast(JSONObject, plan.data["mapping"]))
            if (
                read_artifact(Path(str(args.plan.expanduser().absolute()) + ".mapping.json")).data
                != mapping
            ):
                raise RemekError(
                    "migration.mapping", "private mapping report is missing or changed"
                )
            if args.command == "show":
                diff = plan_diff(plan)
                if len(mapping) + len(diff.encode()) > 1024 * 1024:
                    raise RemekError(
                        "migration.limit", "complete mapping and diff exceed 1 MiB; nothing output"
                    )
                print(mapping.decode(), end="")
                print(diff, end="")
            else:
                _prevalidate(plan)
                outcome = apply_changes(plan.changes, verify=lambda: _verify_installed(plan))
                _verify_result(plan)
                print("Applied conversion to rehearsal only." if outcome.changed else "No changes.")
        _flush(sys.stdout)
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        changed = outcome.changed or (isinstance(exc, RemekError) and exc.changed)
        changed_paths = (
            exc.changed_paths or outcome.changed_paths
            if isinstance(exc, RemekError)
            else outcome.changed_paths
        )
        code = (
            exc.exit_code
            if isinstance(exc, RemekError)
            else (
                130
                if isinstance(exc, KeyboardInterrupt)
                else 2
                if isinstance(exc, (OSError, UnicodeError, ValueError))
                else 70
            )
        )
        with suppress(Exception, KeyboardInterrupt):
            print(
                f"{safe_text(exc)}; changed={str(changed).lower()}; "
                f"changedPaths={safe_text(changed_paths)}",
                file=sys.stderr,
            )
        with suppress(Exception, KeyboardInterrupt):
            _flush(sys.stdout)
        with suppress(Exception, KeyboardInterrupt):
            _flush(sys.stderr)
        return 3 if changed else code


def _prevalidate(plan: Plan) -> None:
    tree = cast(Tree, plan.data["expected"])
    temporary = checked_root(Path(mkdtemp(prefix="remek-validation-")))
    try:
        if any(
            paths_related(temporary, root)
            for root in (plan.root, ROOT, *(source.path for source in plan.sources))
        ):
            raise RemekError("migration.overlap", "validation directory overlaps protected roots")
        with OpenedBoundary(temporary) as boundary:
            write_tree_at(boundary.descriptor, "source", tree)
        _verify_result(replace(plan, root=temporary / "source"))
    finally:
        try:
            with OpenedBoundary(temporary) as boundary:
                if entry_exists(temporary / "source"):
                    remove_at(boundary.descriptor, "source", f"tree:{tree.digest}")
            temporary.rmdir()
        except (Exception, KeyboardInterrupt) as exc:
            raise RemekError(
                "migration.validation-residue",
                f"rehearsal unchanged; private validation residue at {temporary}: {exc}",
                outcome="residue",
                residue=(
                    {
                        "path": str(temporary),
                        "identity": "unknown",
                        "reason": "private validation cleanup failed",
                    },
                ),
            ) from exc


def _verify_installed(plan: Plan) -> None:
    for change in plan.changes:
        if fingerprint(change.path) != change.after:
            raise RemekError("migration.installed", f"installed postimage differs: {change.path}")


def _verify_result(plan: Plan) -> None:
    inspection = inspect_repository(plan.root)
    errors = [finding for finding in repository_findings(inspection) if finding.severity == "error"]
    if errors:
        raise RemekError(
            "migration.validation",
            f"converted source has structural errors: {errors[0].code}; "
            f"{errors[0].path}; {errors[0].message}",
        )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
