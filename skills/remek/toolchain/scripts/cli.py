#!/usr/bin/env -S python3 -I -S -B
"""Trusted entrypoint."""

import os
import sys
from hashlib import sha256
from json import dumps
from pathlib import Path
from stat import S_ISDIR, S_ISREG, S_IXUSR
from unicodedata import category, normalize

ROOT = Path(__file__).absolute().parent.parent
BAD = RuntimeError("invalid inventory")


def _read(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        info, data = os.fstat(descriptor), source.read(limit + 1)
    if (
        not S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or len(data) > limit
        or len(data) != info.st_size
    ):
        raise BAD
    return data


def _manifest(root: Path) -> bytes:
    if not S_ISDIR(root.lstat().st_mode):
        raise BAD
    directories: dict[str, int] = {}
    files: dict[str, list[object]] = {}
    pending, seen = [(root, 0)], set[str]()
    count = total = 0
    while pending:
        parent, depth = pending.pop()
        with os.scandir(parent) as entries:
            for local, entry in enumerate(entries, 1):
                count += 1
                if local > 1024 or count > 4096:
                    raise BAD
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                parts = relative.split("/")
                normalized = [normalize("NFD", part).casefold() for part in parts]
                key = "/".join(normalized)
                if (
                    key in seen
                    or any(
                        part in {"__pycache__", ".pytest_cache"}
                        or Path(part).suffix in {".pyc", ".pyo"}
                        for part in normalized
                    )
                    or any(category(char) in {"Cc", "Cf", "Cs"} for char in relative)
                ):
                    raise BAD
                seen.add(key)
                info = entry.stat(follow_symlinks=False)
                if S_ISDIR(info.st_mode):
                    if depth >= 32:
                        raise BAD
                    directories[relative] = 0o755
                    pending.append((path, depth + 1))
                elif S_ISREG(info.st_mode):
                    data = _read(path, 256 << 10 if relative == "manifest.json" else 2 << 20)
                    total += len(data)
                    if total > 32 << 20:
                        raise BAD
                    if relative != "manifest.json":
                        files[relative] = [
                            0o755 if info.st_mode & S_IXUSR else 0o644,
                            sha256(data).hexdigest(),
                        ]
                else:
                    raise BAD
    value = {
        "schema": "remek.1",
        "kind": "toolchain-manifest",
        "rootMode": 0o755,
        "directories": directories,
        "files": files,
    }
    return (dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


try:
    if (
        sys.version_info < (3, 11)
        or os.name != "posix"
        or not os.environ.get("REMEK_BOOTSTRAP")
        or not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode)
    ):
        raise BAD
    expected = _read(ROOT / "manifest.json", 256 << 10)
    if _manifest(ROOT) != expected or _manifest(ROOT) != expected:
        raise BAD
except (MemoryError, OSError, RuntimeError, UnicodeError, ValueError):
    sys.stderr.write("remek: unsafe toolchain\n")
    raise SystemExit(2) from None
sys.path.insert(0, str(ROOT / "runtime"))
try:
    from remek_core.app import main
except Exception as error:
    sys.stderr.write(f"remek: cannot load validated runtime: {type(error).__name__}\n")
    raise SystemExit(2) from None
if __name__ == "__main__":
    raise SystemExit(main(bundle=ROOT))
