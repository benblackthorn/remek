#!/usr/bin/env python3
"""Enforce repository ceilings and identities."""

import re
import subprocess
import sys
from pathlib import Path

LIMITS = {
    "shipped": 70_000,
    "tests": 35_000,
    "documentation": 15_000,
    "vendor": 0,
    "other": 10_000,
}
EXECUTABLE = {"gate", "remek", "tools/repo_tokens.py", "tools/verify_release_manifest.py"}
PLAIN = {
    "skills/remek/scripts/cli.py",
    "skills/remek/toolchain/scripts/cli.py",
    "skills/remek/toolchain/assets/gate",
}
BRAND = re.compile(r"\bremek\b", re.I)


def _main():  # noqa: PLR0912
    root = Path.cwd()
    violations = []
    try:
        index = {}
        entries = subprocess.check_output(["git", "ls-files", "--stage", "-z"]).split(b"\0")
        for entry in entries:
            if entry:
                metadata, path = entry.split(b"\t", maxsplit=1)
                index[path.decode()] = metadata[:6].decode()
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
        sys.stderr.write("repo-tokens: invalid\n")
        return 2
    if "skills/remek/SKILL.md" not in index or any(
        path.startswith("skills/") and not path.startswith("skills/remek/") for path in index
    ):
        violations.append("skill roots")
    if any(
        set(Path(path).parts)
        & {"vendor", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
        or path.endswith((".pyc", ".pyo"))
        for path in index
    ):
        violations.append("vendor/cache")
    for path in sorted(EXECUTABLE | PLAIN):
        executable = path in EXECUTABLE
        mode = "100755" if executable else "100644"
        actual = bool((root / path).stat().st_mode & 0o100)
        if index.get(path) != mode or actual != executable:
            violations.append(f"mode: {path}")
    for name, source in (("gate", "toolchain/assets/gate"), ("remek", "scripts/cli.py")):
        if (root / name).read_bytes() != (root / "skills/remek" / source).read_bytes():
            violations.append(f"shim: {name}")
    total, files = sum(counts.values()), len(index)
    if total > 125_000:
        violations.append(f"total={total}>125000")
    if files > 70:
        violations.append(f"files={files}>70")
    for name, limit in LIMITS.items():
        if counts[name] > limit:
            violations.append(f"{name}={counts[name]}>{limit}")
    sys.stderr.writelines(f"repo-tokens: {value}\n" for value in violations)
    for name, value in counts.items():
        print(f"{name}: {value:,}")
    print(f"total: {total:,} tokens in {files} files")
    return bool(violations)


if __name__ == "__main__":
    raise SystemExit(_main())
