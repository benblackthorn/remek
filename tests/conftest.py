import os
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True
RUNTIME = Path(__file__).resolve().parents[1] / "skills" / "remek" / "toolchain" / "runtime"
os.environ["REMEK_BOOTSTRAP"] = str(RUNTIME.parents[1] / "scripts/cli.py")
sys.path.insert(0, str(RUNTIME))

SAFE_PATH = os.pathsep.join(
    entry for entry in os.environ.get("PATH", "").split(os.pathsep) if Path(entry).is_absolute()
)


@pytest.fixture(autouse=True)
def trusted_external_path(monkeypatch):
    for key in list(os.environ):
        if key.startswith("GIT_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("PATH", SAFE_PATH)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


@pytest.fixture
def root(tmp_path):
    path = tmp_path / "root"
    path.mkdir()
    return path.resolve()
