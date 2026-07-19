from pathlib import Path

import pytest
from remek_core.frontmatter import FrontmatterError, parse_skill, render_skill

ROOT = Path(__file__).parents[1]


def test_current_remek_skill_parses_and_preserves_body():
    text = (ROOT / "skills/remek/SKILL.md").read_text(encoding="utf-8")
    fields, body = parse_skill(text)

    assert fields["name"] == "remek"
    assert fields["license"] == "MIT"
    assert isinstance(fields["description"], str)
    assert body.startswith("\n# remek\n")


def test_strings_metadata_lists_and_quotes_do_not_coerce():
    fields, body = parse_skill(
        "---\n"
        "name: 'sample-skill'\n"
        'description: "A colon: and a \\"quote\\"."\n'
        "truth: 'true'\n"
        "count: '42'\n"
        "empty: ''\n"
        "tags: [one, 'two, too', \"three\"]\n"
        "metadata:\n"
        "  remek-internal: 'false'\n"
        "  owner: 'Ben''s'\n"
        "---\n"
        "# Body\n"
    )

    assert fields == {
        "name": "sample-skill",
        "description": 'A colon: and a "quote".',
        "truth": "true",
        "count": "42",
        "empty": "",
        "tags": ["one", "two, too", "three"],
        "metadata": {"remek-internal": "false", "owner": "Ben's"},
    }
    assert body == "# Body\n"


def test_literal_and_folded_block_scalars():
    fields, _ = parse_skill(
        "---\n"
        "literal: |\n"
        "  First line.\n"
        "  Second line.\n"
        "folded: >\n"
        "  First line.\n"
        "  Second line.\n"
        "\n"
        "  New paragraph.\n"
        "---\n"
    )

    assert fields["literal"] == "First line.\nSecond line.\n"
    assert fields["folded"] == "First line. Second line.\nNew paragraph.\n"


@pytest.mark.parametrize(
    "text",
    [
        "name: no-fence\n",
        "---\nname: missing-space\n--- trailing\n",
        "---\nname: missing-close\n",
        "---\nnot-a-mapping\n---\n",
    ],
)
def test_malformed_framing_and_lines_are_rejected(text):
    with pytest.raises(FrontmatterError):
        parse_skill(text)


@pytest.mark.parametrize(
    "frontmatter",
    [
        "name: one\nname: two\n",
        "metadata:\n  owner: one\n  owner: two\n",
        "unknown:\n  child: value\n",
        "metadata:\n  child:\n",
        "metadata:\n  owner: one\n    child: value\n",
        "metadata:\n      child: value\n",
        "name:\n  child: value\n",
    ],
)
def test_duplicates_depth_and_unknown_mappings_are_rejected(frontmatter):
    with pytest.raises(FrontmatterError):
        parse_skill(f"---\n{frontmatter}---\n")


@pytest.mark.parametrize("character", ["\0", "\x1b", "\x7f", "\x85"])
def test_controls_are_rejected_anywhere(character):
    with pytest.raises(FrontmatterError, match="control character"):
        parse_skill(f"---\nname: safe\n---\nbody{character}")


def test_body_preserves_tabs_crlf_and_trailing_whitespace():
    body = "# Body\r\n\tstep with trailing spaces   "
    _, parsed = parse_skill(f"---\r\nname: safe\r\n---\r\n{body}")
    assert parsed == body


@pytest.mark.parametrize(
    "value",
    [
        "&anchor value",
        "*alias",
        "!tag value",
        "[one, *alias]",
        "{nested: value}",
        "null",
        "foo # comment",
        "Use this skill when: the user asks",
    ],
)
def test_unsafe_yaml_is_rejected(value):
    with pytest.raises(FrontmatterError):
        parse_skill(f"---\nvalue: {value}\n---\n")


def test_byte_limit_is_inclusive_and_uses_utf8_bytes():
    prefix = "---\ndescription: "
    suffix = "\n---\n"
    maximum = 256 * 1024
    exact = prefix + "x" * (maximum - len(prefix) - len(suffix)) + suffix

    fields, body = parse_skill(exact)
    assert isinstance(fields["description"], str)
    assert body == ""
    with pytest.raises(FrontmatterError, match="maximum"):
        parse_skill(exact[: -len(suffix)] + "é" + suffix)


def test_agent_skills_optional_fields_follow_the_open_spec():
    fields = {
        "name": "sample-skill",
        "description": "A sample.",
        "compatibility": "x" * 500,
        "allowed-tools": "Read Grep Bash(git:*)",
    }
    rendered = render_skill(fields, "# Sample\n")
    assert parse_skill(rendered.decode())[0] == fields
    for compatibility in ("", "x" * 501):
        with pytest.raises(FrontmatterError, match="compatibility"):
            render_skill({**fields, "compatibility": compatibility}, "# Sample\n")
    with pytest.raises(FrontmatterError, match="allowed-tools must be a string"):
        render_skill({**fields, "allowed-tools": ["Read"]}, "# Sample\n")


def test_github_cli_four_space_metadata_parses_and_renders_canonically():
    fields, body = parse_skill(
        "---\n"
        "description: Installed by GitHub CLI.\n"
        "metadata:\n"
        "    github-path: skills/sample-skill\n"
        "    github-ref: refs/tags/v1.0.4\n"
        "    github-repo: https://github.com/owner/repository\n"
        "    github-tree-sha: abcdef0123456789\n"
        "name: sample-skill\n"
        "---\n"
        "# Sample\n"
    )

    assert fields["metadata"] == {
        "github-path": "skills/sample-skill",
        "github-ref": "refs/tags/v1.0.4",
        "github-repo": "https://github.com/owner/repository",
        "github-tree-sha": "abcdef0123456789",
    }
    assert b"\n  github-path:" in render_skill(fields, body)
