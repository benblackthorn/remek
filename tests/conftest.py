import os
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True
RUNTIME = Path(__file__).resolve().parents[1] / "skills" / "remek" / "toolchain" / "runtime"
os.environ["REMEK_BOOTSTRAP"] = str(RUNTIME.parents[1] / "scripts/cli.py")
sys.path.insert(0, str(RUNTIME))

MAX_COLLECTED_TESTS = 250


@pytest.fixture
def root(tmp_path):
    path = tmp_path / "root"
    path.mkdir()
    return path.resolve()


def pytest_collection_modifyitems(items):
    if len(items) > MAX_COLLECTED_TESTS:
        raise pytest.UsageError(
            f"collected {len(items)} tests; repository limit is {MAX_COLLECTED_TESTS}"
        )
