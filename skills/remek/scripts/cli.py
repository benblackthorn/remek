#!/usr/bin/env -S python3 -I -S -B
"""Bootstrap."""

import os
import sys
from hashlib import sha256
from pathlib import Path
from stat import S_ISREG

HERE = Path(__file__).absolute()
if sys.version_info < (3, 11):  # noqa: UP036 - wrapper reports unsupported interpreters
    sys.stderr.write("remek: Python 3.11 or newer is required\n")
    raise SystemExit(2)
if os.name != "posix":
    sys.stderr.write("remek: a POSIX operating system is required\n")
    raise SystemExit(2)
try:
    flags = sys.flags
    if not (flags.isolated and flags.no_site and flags.dont_write_bytecode):
        raise ValueError
    base = HERE.parent
    if HERE.name == "remek":
        [root] = [
            path
            for relative in (".remek/toolchain", "skills/remek/toolchain")
            if os.path.lexists(path := base / relative)
        ]
    else:
        root = base.parent / "toolchain"
    entrypoint = root / "scripts/cli.py"
    for name, limit, pin in (
        (
            "manifest.json",
            256 << 10,
            "22d1b96788417a49a80d6b68d623cb2072078b6585be38d502b87d9340be5c29",
        ),
        (
            "scripts/cli.py",
            2 << 20,
            "4ff007f3a1bbad972301e20eaede621137af87506bb30a4761e87b1b98f53ec3",
        ),
    ):
        path = root / name
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as source:
            info, data = os.fstat(descriptor), source.read(limit + 1)
        if (
            not S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > limit
            or len(data) != info.st_size
            or sha256(data).hexdigest() != pin
            or bool(info.st_mode & 0o100)
        ):
            raise ValueError
except (MemoryError, OSError, ValueError):
    sys.stderr.write("remek: unsafe toolchain\n")
    raise SystemExit(2) from None
os.environ["REMEK_BOOTSTRAP"] = str(HERE)
os.execv(
    sys.executable,
    [sys.executable, "-I", "-S", "-B", str(entrypoint), *sys.argv[1:]],
)
