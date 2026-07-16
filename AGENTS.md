# remek repository

This repository produces only `skills/remek/`; user skills never belong here.
Write `remek` only in lowercase. Architecture, formats, and trust live in
`docs/design.md`, `docs/contracts.md`, and `docs/threat-model.md`.

## Product and safety contract

Preserve the approved outcomes: init, scaffold, accept, governed distribution
and disclosure changes, retire, remove, check, repair, evidence preparation and
recording, approval preparation and recording, release and release verification,
plan inspection, audit, doctor, update, and apply.

- Scaffold preserves completed work, a design, or a reviewed import. Accept
  imports complete reviewed bytes and invents nothing.
- Governed-source and mirror mutations save exact `remek.1` plans; apply
  reconstructs intent and refuses drift. Filesystem owns identity, transaction
  owns mutation, and plans owns intent. Preserve foreign data and report residue.
- Checks, audits, evidence, and approvals are deterministic and offline; no
  provider runner belongs here.
- Release Git queries disable repository-configured execution, reject active
  content filters, hiding index flags, and submodules, and bind every owned
  regular file to its raw HEAD blob and Git-representable mode.
- Check warns on stale evidence; malformed receipts fail. Release names a
  distribution, requires current evidence and approval, and binds clean Git,
  branch, audience, credential-free remote, and authenticated target. It never
  commits or pushes. Public manifests hash private context. Update keeps one layout.
- Shipped Python is 3.11+, standard-library only, and scoped to verified POSIX
  local filesystems. Validate the runtime tree before import; do not claim
  Windows support.
- Trust the loaded bundle, interpreter, OS, intent, selected roots, and external
  ancestors. Other inputs are hostile. Exclude noncooperating writers, process
  death, and power loss.

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

- At most 100,000 tracked `o200k_base` tokens and at most 70 files: at most
  70,000 shipped, 30,000 test, 15,000 documentation, and 5,000 other tokens,
  with zero vendor tokens.
- At most 250 collected tests, exactly `skills/remek`, exactly one `remek.1`
  schema family, and zero third-party runtime dependencies.

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
uvx mypy@2.1.0 --strict tools/verify_release_manifest.py
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
