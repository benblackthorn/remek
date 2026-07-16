#!/usr/bin/env python3
# ruff: noqa: D100, D103, E402

import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))

from skills.remek.toolchain.runtime.remek_core.contract import JSONObject, render_document
from skills.remek.toolchain.runtime.remek_core.filesystem import tree_from_entries
from skills.remek.toolchain.runtime.remek_core.model import RemekError
from skills.remek.toolchain.runtime.remek_core.workflows import verify_materialized_release


def _self_test() -> None:
    zero = "0" * 64
    fields: JSONObject = {
        "audience": "private",
        "sourceRepositoryIdentity": zero,
        "sourceCommit": zero[:40],
        "sourceBranchDigest": None,
        "distributionIdentity": zero,
        "releaseId": zero,
        "releaseSetDigest": zero,
        "payloadDigest": tree_from_entries([]).digest,
        "candidates": [],
        "directories": [],
        "files": [],
        "targetVerificationDigest": "not-performed",
        "preReleaseHead": None,
        "remoteBinding": None,
        "expectedCommitPaths": [],
    }
    with TemporaryDirectory() as directory:
        root = Path(directory)
        manifest = root / "release-manifest.json"
        manifest.write_bytes(render_document("release-manifest", fields))
        verify_materialized_release(root)
        manifest.write_bytes(manifest.read_bytes() + b" ")
        try:
            verify_materialized_release(root)
        except RemekError:
            return
        raise RemekError("self-test accepted a malformed manifest")


def main(arguments: list[str]) -> int:
    try:
        if len(arguments) != 1:
            raise RemekError("expected one mirror path or --self-test")
        _self_test() if arguments[0] == "--self-test" else verify_materialized_release(
            Path(arguments[0]).absolute()
        )
    except (OSError, RemekError, UnicodeError, ValueError):
        sys.stderr.write("invalid release mirror\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
