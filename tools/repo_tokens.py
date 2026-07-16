#!/usr/bin/env python3
# ruff: noqa: D100, D103, E501, PLR0912, SIM905

import re
import subprocess
import sys
from pathlib import Path

LIMITS = {"shipped": 70_000, "tests": 30_000, "documentation": 15_000, "vendor": 0, "other": 5_000}
MODES = {
    **dict.fromkeys(
        "gate remek tools/repo_tokens.py tools/verify_release_manifest.py".split(), "100755"
    ),
    **dict.fromkeys(
        "skills/remek/scripts/cli.py skills/remek/toolchain/scripts/cli.py skills/remek/toolchain/assets/gate".split(),
        "100644",
    ),
}
BRAND = re.compile(r"\bremek\b", re.I)


def main():
    root = Path.cwd()
    violations = []
    try:
        index = {
            path.decode(): metadata[:6].decode()
            for value in subprocess.check_output(["git", "ls-files", "--stage", "-z"]).split(b"\0")
            if value
            for metadata, path in (value.split(b"\t", 1),)
        }
        encoding = __import__("tiktoken").get_encoding("o200k_base")
        counts = dict.fromkeys(LIMITS, 0)
        for path in index:
            target = root / path
            if target.is_symlink() or not target.is_file():
                raise RuntimeError(path)
            category = (
                "vendor"
                if path.startswith("skills/remek/vendor/")
                else "tests"
                if path.startswith("tests/")
                else "shipped"
                if path in {"gate", "remek"} or path.startswith("skills/")
                else "documentation"
                if path.lower().endswith(".md") or path.startswith("docs/")
                else "other"
            )
            text = target.read_text()
            counts[category] += len(encoding.encode(text))
            for line, value in enumerate(text.splitlines(), 1):
                if BRAND.sub("remek", value) != value:
                    violations.append(f"{path}:{line}")
    except (OSError, RuntimeError, UnicodeError, subprocess.SubprocessError):
        sys.stderr.write("repo-tokens: invalid tracked tree\n")
        return 2
    if "skills/remek/SKILL.md" not in index or any(
        path.startswith("skills/") and not path.startswith("skills/remek/") for path in index
    ):
        violations.append("invalid skill roots")
    if any(
        set(Path(path).parts)
        & {"vendor", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
        or path.endswith((".pyc", ".pyo"))
        for path in index
    ):
        violations.append("tracked vendor or cache")
    for path, mode in MODES.items():
        executable = bool((root / path).stat().st_mode & 0o100)
        if index.get(path) != mode or executable != (mode == "100755"):
            violations.append(f"invalid mode: {path}")
    for name, source in {"gate": "toolchain/assets/gate", "remek": "scripts/cli.py"}.items():
        if (root / name).read_bytes() != (root / "skills/remek" / source).read_bytes():
            violations.append(f"invalid root shim: {name}")
    total, files = sum(counts.values()), len(index)
    if total > 100_000:
        violations.append(f"total {total:,} exceeds 100,000 tokens")
    if files > 70:
        violations.append(f"{files} files exceeds 70")
    for name, limit in LIMITS.items():
        if counts[name] > limit:
            violations.append(f"{name} {counts[name]:,} exceeds {limit:,}")
    for violation in violations:
        sys.stderr.write(f"repo-tokens: {violation}\n")
    for name, value in counts.items():
        print(f"{name}: {value:,}")
    print(f"total: {total:,} tokens in {files} files")
    return bool(violations)


if __name__ == "__main__":
    raise SystemExit(main())
