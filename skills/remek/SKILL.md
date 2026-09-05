---
name: "remek"
description: "Use when a request names remek or asks to initialize a governed Agent Skills source, govern completed skill files, record actual evaluation observations, review a distribution, audit an untrusted skill, or prepare and verify a release mirror. Authoring, evaluation execution, Git transport, installation, and publishing remain external."
license: "MIT"
compatibility: "Requires Python 3.11+ on macOS or native Linux and verified local POSIX storage. Git is required for staging and release; GitHub CLI is required for authenticated managed targets. Source and managed mirror must be Git worktree roots. Full Git integrity checks must finish within 30 seconds."
---

# remek

Never put user or private skills in the remek producer repository; it produces only
`skills/remek/`. Identify the owner's actual source and authorized scope first.
Keep reviewed skills in a private source; release only its selected distribution.
Follow [references/workflows.md](references/workflows.md).
Run installed `scripts/cli.py` with `python3 -I -S -B`; inside a governed source,
use `./remek`. This is the v2 `remek.2` workflow; there are no legacy aliases.

Use ordinary reviewed files and Git to author or revise the payload, `skill.json`,
distributions, and disclosure policy. Preserve completed work, a real design, or
a reviewed import. Before edits, preserve unique uncommitted bytes and old case
definitions through an existing verified checkpoint or a private pre-edit copy;
a new commit is unnecessary when that checkpoint already covers the work. Review
the exact diff afterward. Never invent procedures, retained sources, rights,
evaluator profiles/versions, configuration, trials, or approval declarations.
Audit imports read-only, then inspect every script and resource for actual behavior.
The `remek-text` audit establishes supported structure only. Host permissions remain
independent.

Before initialization, inspect existing instructions and conventions. Reuse the
established setup and authorization. Resolve an unknown source path or audience
before creation.
Use the host's established authoring and evaluation capabilities; remek runs none.
Continue authorized adjacent work through its owner without treating remek's
boundary as the end of the user's task.

remek-owned mutations use a saved exact plan, `show`, and `apply`. Explain paths
and effects; use existing owner authorization and ask only when it is missing
for that action. Source bytes, reports, target preimages, and toolchain must still
match at apply. Never bypass a refusal or overwrite foreign residue.

Record actual configuration and every ordered trial observation, including failures.
Reports are caller-reported, not authenticated execution. A complete distribution
review must show selected bytes, required profiles, all current relevant evidence,
required-profile failures, provenance/rights, disclosure, target, and public
irreversibility where applicable. Fill review declarations only after actual review
and owner authorization. A passing check is not that authorization. New relevant
reports revoke active review pointers; historical reports remain available.
Never delete stale or failed reports or clear an error by removing evidence.

Keep plans, raw traces, backups, and migration maps in private owner-selected storage
outside protected roots. Use one external mode-0700 session for disposable artifacts;
never put them in installed skills or a public payload. Clean only proven disposable
bytes from this run, preserving original sources and independently verified backups.

Report exact outcomes and next action. `check` separates structural validity from
release readiness. `verify` establishes artifact inventory only; `release verify`
also checks current source readiness, target, and commit lineage. State audience,
selected count, and any missing review or evidence. No command observes publication
or installation. Commits, pushes, tags, publication, installation, global directories,
visibility, and real-source v1 cutover need their own authorization.
