import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import TOOLCHAIN, git_commit, initialized, mirror, ready_source
from remek_core.app import _parser, main
from remek_core.filesystem import portable_path
from remek_core.model import Finding, RemekError
from remek_core.plans import operation_document
from remek_core.repository import _toolchain
from remek_core.workflows import release_plan, verify_materialized_release


def run(arguments):
    return main(arguments, bundle=TOOLCHAIN)


def execute(path, *arguments, cwd=None):
    return subprocess.run(
        [str(path), *arguments], cwd=cwd, check=False, capture_output=True, text=True
    )


def execute_python(path, *arguments, cwd=None):
    return subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(path), *arguments],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


def test_json_result_uses_remek_1(tmp_path, capsys):
    root = initialized(tmp_path)
    assert run(["--root", str(root), "--json", "check"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["schema"] == "remek.1"
    assert document["exitCode"] == 0
    assert run(["--root", str(root), "--json", "remove", "missing"]) == 2
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == "refused" and document["exitCode"] == 2


def test_init_plan_show_apply_through_cli(tmp_path, capsys, monkeypatch):
    root = tmp_path / "source"
    plan = tmp_path.parent / f"{tmp_path.name}-init.json"
    assert run(["init", str(root), "--output", str(plan)]) == 0
    assert plan.is_file() and not root.exists()
    capsys.readouterr()
    assert run(["plan", "show", str(plan), "--max-bytes", "512"]) == 0
    rendered = capsys.readouterr().out
    assert "exact plan reconstructed" in rendered
    assert rendered.index("  tree ") < rendered.index("\nadd ")
    monkeypatch.setattr("remek_core.app.plan_diff", lambda _plan, *, max_bytes: "\\" * max_bytes)
    assert run(["--json", "plan", "show", str(plan)]) == 0
    json.loads(capsys.readouterr().out)
    assert run(["apply", str(plan)]) == 0
    assert (root / "remek.json").is_file()
    assert ".DS_Store" in (root / ".gitignore").read_text()
    occupied = tmp_path / "occupied"
    (occupied / "skills/foreign").mkdir(parents=True)
    assert run(["init", str(occupied)]) == 2
    assert "--project" in capsys.readouterr().err


def test_apply_reports_final_post_cleanup_findings(tmp_path, capsys, monkeypatch):
    root = tmp_path / "source"
    plan = tmp_path.parent / f"{tmp_path.name}-post-cleanup.json"
    assert run(["init", str(root), "--output", str(plan)]) == 0
    capsys.readouterr()
    calls = 0

    def findings(_inspection):
        nonlocal calls
        calls += 1
        return (
            Finding("evidence.routing", "warning", "missing")
            if calls == 1
            else Finding("transaction.residue", "error", "residue"),
        )

    monkeypatch.setattr("remek_core.app.check", findings)
    assert run(["apply", str(plan)]) == 1
    assert "transaction.residue" in capsys.readouterr().out


def test_scaffold_is_only_direct_mutation(tmp_path, capsys):
    root = initialized(tmp_path)
    source = tmp_path / "source.md"
    source.write_text("completed")
    workspace = tmp_path / "workspace"
    assert (
        run(
            [
                "--root",
                str(root),
                "scaffold",
                "--name",
                "new-skill",
                "--origin",
                "captured",
                "--source",
                str(source),
                "--workspace",
                str(workspace),
            ]
        )
        == 0
    )
    assert workspace.is_dir()
    assert "workspace created" in capsys.readouterr().out


def test_gate_is_root_bound_from_another_directory(tmp_path):
    root = initialized(tmp_path)
    assert (root / "remek").read_bytes() == (TOOLCHAIN.parent / "scripts/cli.py").read_bytes()
    completed = execute(root / "gate", cwd=tmp_path)
    assert completed.returncode == 0 and "check passed" in completed.stdout
    members = [root, *root.rglob("*")]
    for directory_mode, file_mode in ((0o700, 0o600), (0o775, 0o664)):
        for path in members:
            path.chmod(
                directory_mode if path.is_dir() or path.stat().st_mode & 0o100 else file_mode
            )
        assert execute(root / "gate", cwd=tmp_path).returncode == 0
    (root / "skills/remek").mkdir(parents=True)
    shutil.copytree(root / ".remek/toolchain", root / "skills/remek/toolchain")
    completed = execute(root / "remek", "--version")
    assert completed.returncode == 2 and "unsafe toolchain" in completed.stderr


def test_release_verify_two_word_syntax_is_recognized(tmp_path, capsys):
    assert run(["release", "--help"]) == 0
    help_text = capsys.readouterr().out
    assert "release DIST" in help_text and "release verify DIST" in help_text
    assert "managed mirror" in help_text and "unverified staging" in help_text
    root = initialized(tmp_path)
    assert (
        run(["--root", str(root), "release", "verify", "org-private", "--mirror", str(root)]) == 2
    )
    assert "unknown distribution" in capsys.readouterr().err


def test_wrapper_accepts_installer_projection_and_metadata(tmp_path):
    skill = tmp_path / "remek"
    shutil.copytree(TOOLCHAIN.parent, skill)
    skill_md = skill / "SKILL.md"
    skill_md.write_text(skill_md.read_text() + "\ninstaller metadata changed wrapper bytes\n")
    for path in skill.rglob("*"):
        if path.is_file():
            path.chmod(0o644)
    completed = execute_python(skill / "scripts/cli.py", "--version")
    assert completed.returncode == 0 and completed.stdout == "remek 1.0.2\n"


def test_repair_reports_unrepairable_blockers(tmp_path, capsys):
    root = initialized(tmp_path)
    (root / "remek").write_text("damaged\n")
    (root / ".remek/unknown").write_text("foreign\n")
    plan = tmp_path / "repair.json"
    assert run(["--root", str(root), "--json", "repair", "--output", str(plan)]) == 1
    result = json.loads(capsys.readouterr().out)
    codes = {item["code"] for item in result["findings"]}
    assert result["status"] == "issues" and {"repo.shim", "governance.layout"} <= codes
    assert not plan.exists() and (root / "remek").read_text() == "damaged\n"


@pytest.mark.parametrize(
    "tamper",
    (
        "modify",
        "unknown",
        "runtime",
        "symlink",
        "hardlink",
        "special",
        "mode",
        "manifest-large",
        "entrypoint",
    ),
)
def test_bootstrap_refuses_toolchain_tamper(tamper, tmp_path):
    skill = tmp_path / "remek"
    shutil.copytree(TOOLCHAIN.parent, skill)
    marker = None
    if tamper == "modify":
        (skill / "toolchain/assets/gate").write_text("tampered\n")
    elif tamper == "unknown":
        (skill / "toolchain" / "unknown.txt").write_text("unknown\n")
    elif tamper == "symlink":
        (skill / "toolchain/assets/gate").unlink()
        (skill / "toolchain/assets/gate").symlink_to("../manifest.json")
    elif tamper == "hardlink":
        os.link(skill / "toolchain/assets/gate", tmp_path / "external-gate")
    elif tamper == "special":
        os.mkfifo(skill / "toolchain/special")
    elif tamper == "mode":
        (skill / "toolchain/manifest.json").chmod(0o755)
    elif tamper == "manifest-large":
        (skill / "toolchain/manifest.json").write_bytes(b" " * ((256 << 10) + 1))
    else:
        marker = tmp_path / "executed"
        relative = "runtime/remek_core/model.py" if tamper == "runtime" else "scripts/cli.py"
        target = skill / "toolchain" / relative
        target.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
        path = skill / "toolchain/manifest.json"
        document = json.loads(path.read_text())
        document["files"][relative][1] = hashlib.sha256(target.read_bytes()).hexdigest()
        path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    completed = execute_python(skill / "scripts/cli.py", "--help")
    assert completed.returncode == 2
    assert "unsafe toolchain" in completed.stderr
    if marker is not None:
        assert not marker.exists()


def test_toolchain_identities_agree_on_unicode(tmp_path):
    root = tmp_path / "repo"
    bundle = root / "skills/remek/toolchain"
    shutil.copytree(TOOLCHAIN, bundle)
    unicode_file = bundle / "runtime/remek_core/café.py"
    unicode_file.write_text("pass\n")
    namespace = {"__file__": str((TOOLCHAIN / "scripts/cli.py").absolute())}
    exec((TOOLCHAIN / "scripts/cli.py").read_text().split("\ntry:\n", 1)[0], namespace)
    build = namespace["_manifest"]
    (bundle / "manifest.json").write_bytes(build(bundle))
    assert {item.code for item in _toolchain(root)[1]} == {"repo.shim"}
    for value in ("café", "café", "CAFÉ"):
        wrapper = namespace["normalize"]("NFD", value).casefold()
        assert wrapper == portable_path(value)
    collision = unicode_file.with_name("café.py")
    collision.write_text("pass\n")
    if not collision.samefile(unicode_file):
        with pytest.raises(RuntimeError):
            build(bundle)
        assert any(item.code == "filesystem.collision" for item in _toolchain(root)[1])
        collision.unlink()
    (bundle / "manifest.json").chmod(0o755)
    assert {item.code for item in _toolchain(root)[1]} == {"toolchain.identity"}


def test_release_apply_rolls_back_failed_postcondition(tmp_path, monkeypatch):
    root = ready_source(tmp_path)
    git_commit(root)
    target = mirror(tmp_path)
    monkeypatch.setattr(
        "remek_core.workflows.verify_github_target",
        lambda value: {
            "provider": "github",
            "hostname": value["hostname"],
            "nameWithOwner": value["nameWithOwner"],
            "visibility": value["expectedVisibility"],
        },
    )
    plan = release_plan(root, "org-private", mirror=target)
    plan_path = tmp_path / "release-plan.json"
    plan_path.write_bytes(operation_document(plan, TOOLCHAIN)[0])
    plan_path.chmod(0o600)

    def fail(_root):
        raise RemekError("test.postcondition", "forced failure")

    monkeypatch.setattr("remek_core.app.verify_materialized_release", fail)
    assert run(["apply", str(plan_path)]) == 2
    assert not (target / "skills").exists() and not (target / "release-manifest.json").exists()
    monkeypatch.setattr("remek_core.app.verify_materialized_release", verify_materialized_release)
    assert run(["apply", str(plan_path)]) == 0


def test_documented_remek_commands_parse():
    files = [
        Path("README.md"),
        Path("skills/remek/references/workflows.md"),
    ]
    commands = []
    for path in files:
        for block in re.findall(r"```bash\n(.*?)```", path.read_text(), re.DOTALL):
            for line in re.sub(r"\\\n\s*", " ", block).splitlines():
                arguments = shlex.split(line)
                if arguments and arguments[0] in {"remek", "./remek"}:
                    commands.append(arguments[1:])
    assert commands
    for arguments in commands:
        _parser().parse_args(arguments)


def test_local_markdown_links_resolve():
    files = [Path("README.md"), *Path("docs").glob("*.md"), Path("skills/remek/SKILL.md")]
    for path in files:
        for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", path.read_text()):
            if "://" not in target and not target.startswith(("#", "mailto:")):
                assert (path.parent / target.split("#", 1)[0]).exists(), (path, target)
