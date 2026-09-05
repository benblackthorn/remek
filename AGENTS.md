# remek repository

This repository produces only `skills/remek/`; user skills never belong here.
Write `remek` only in lowercase. Architecture, formats, and trust live in
`docs/design.md`, `docs/contracts.md`, and `docs/threat-model.md`.

## Product and safety contract

Preserve init, ordinary file/Git authoring, check, audit, reported evaluation,
complete distribution review, exact plan show/apply, release plan/verification,
artifact verification, and embedded update. The normal CLI has ten verbs and
thirteen leaves, five mutation intents, and one `remek.2` family. The source-only
v1 converter is isolated from normal runtime; no compatibility aliases exist.

- Authoring preserves completed work, actual designs, or reviewed imports and
  invents no procedure or provenance. One skill record owns exposure, provenance,
  and both case sets. README and authored declarations use ordinary file/Git edits.
- Every remek mutation saves an exact plan; apply reconstructs intent and refuses
  drift. Filesystem owns identity, transaction owns mutation, and plans own intent.
  Preserve foreign data and report exact outcomes, changed paths, and residue.
- Checks, audit, evaluation preparation/recording, and review are deterministic and
  offline. No provider runner belongs here. Retain actual caller-reported trials
  and configuration; never fabricate observations or review declarations.
- One review binds full distribution/skill/policy context and every relevant report.
  Required-profile failures need acknowledgement and cannot waive passes. New
  relevant reports atomically clear affected active pointers. History is retained.
- Release Git queries disable repository-configured execution, reject active
  content filters, hiding index flags, and submodules, and bind every owned
  regular file to its raw HEAD blob and Git-representable mode.
- Check warns on missing/stale evidence; malformed records fail without hiding a
  valid skill. Release requires current complete review/evidence, clean Git,
  branch, audience, credential-free remote, and authenticated target. It never
  commits or pushes. Manifests hash private context and bind review identity.
  V2 needs fresh manifest lineage; update keeps one layout.
- Shipped Python is 3.11+, standard-library only, and scoped to verified POSIX
  local filesystems. Validate the runtime tree before import; no Windows claim.
- Trust the loaded bundle, interpreter, OS, intent, selected roots, and external
  ancestors. Other inputs are hostile. Resolve post-bootstrap Git/GitHub tools
  canonically outside selected roots and filter child PATH for every launch.
  Exclude noncooperating writers, process death, and power loss.

## Anti-bloat contract

- Start with outcome and owner in `docs/design.md`; prefer deletion,
  consolidation, or extension. Move callers and former owners together.
- Keep one semantic owner. Add an abstraction only when it removes more concepts
  or maintenance than it adds. Prefer direct functions and immutable data.
- Extend an existing workflow before adding a command. Persist only state that
  must survive process exit.
- New commands, persisted kinds or schemas, runtime dependencies, compatibility
  paths, platform guarantees, adapters, registries, plugins, and release surfaces
  require explicit owner approval.
- Future reuse, symmetry, completeness, and reviewer preference are not evidence.
  Approved surface records outcome, evidence, owner, additions/deletions, and
  before/after tokens, files, tests, commands, kinds, and dependencies.
- Tests cover observable behavior, reproduced defects, malformed input, and
  destructive boundaries, not matrices, repeated variants, architecture
  parity, or implementation snapshots.
- Documentation states current truth; completed plans and history belong in Git.
- Never alter accounting or ceilings to admit work. A raise needs isolated owner
  approval. Simplify or delete excess; headroom is not capacity.

Expected failures use `RemekError` without tracebacks. Never weaken tests.

## Fixed ceilings

- At most 141,000 tracked `o200k_base` tokens and at most 70 files: at most
  70,000 shipped, 51,000 test, 15,000 documentation, and 12,500 other tokens,
  with zero vendor tokens.
- Report collected tests without a test-count cap; fixed token/file ceilings and
  observable safety coverage remain binding. Exactly `skills/remek`, one normal
  `remek.2` schema family, and zero third-party runtime dependencies.

These owner-authorized ceilings permit readable safety boundaries and distinct
destructive tests, not feature expansion. Existing checks enforce them; only
the owner may raise them.

## Definition of done

```bash
./gate
uv run --no-project --with-requirements requirements-dev.txt -m pytest tests/ -q
uv run --no-project --with-requirements requirements-dev.txt -m pytest tests/ --collect-only -q
uvx ruff@0.15.20 check skills tests tools gate remek
uvx ruff@0.15.20 format --check skills tests tools
uvx mypy@2.1.0 --strict skills/remek/scripts/cli.py
uvx mypy@2.1.0 --strict skills/remek/toolchain/scripts/cli.py skills/remek/toolchain/runtime
uvx mypy@2.1.0 --strict tools/verify_release_manifest.py tools/migrate_v1.py
python3 tools/verify_release_manifest.py --self-test
actionlint .github/workflows/gate.yml
uv run --no-project --with tiktoken==0.11.0 python tools/repo_tokens.py
git diff --check
```

Also validate links, CLI examples, shim parity, and residue.
Run disposable workflows only when shipped behavior changes.

Preserve unrelated work and privacy. Ask before changing outcomes or contracts,
invoking providers, publishing, tagging, releasing, changing visibility, or
taking other remote action. Never add dependencies, commit secrets, mutate
global agent directories, force-push, or rewrite history.
