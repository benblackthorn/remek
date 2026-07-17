# ruff: noqa: D100, D103

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _pin(source: str, name: str, digest: str) -> str:
    pattern = rf'("{re.escape(name)}",\n\s+[^,]+,\n\s+")[0-9a-f]{{64}}(",)'
    updated, count = re.subn(pattern, rf"\g<1>{digest}\2", source)
    if count != 1:
        raise RuntimeError(f"missing {name} pin")
    return updated


def main() -> None:
    skill = ROOT / "skills/remek"
    toolchain = skill / "toolchain"
    entrypoint = toolchain / "scripts/cli.py"
    prefix, marker, _ = entrypoint.read_text().partition("\ntry:\n")
    if not marker:
        raise RuntimeError("entrypoint layout changed")
    namespace = {"__file__": str(entrypoint)}
    exec(compile(prefix, str(entrypoint), "exec"), namespace)
    manifest = namespace["_manifest"](toolchain)
    (toolchain / "manifest.json").write_bytes(manifest)
    wrapper = skill / "scripts/cli.py"
    data = _pin(
        _pin(wrapper.read_text(), "manifest.json", hashlib.sha256(manifest).hexdigest()),
        "scripts/cli.py",
        hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
    ).encode()
    wrapper.write_bytes(data)
    (ROOT / "remek").write_bytes(data)
    (ROOT / "gate").write_bytes((toolchain / "assets/gate").read_bytes())


if __name__ == "__main__":
    main()
