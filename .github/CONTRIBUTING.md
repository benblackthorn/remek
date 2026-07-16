# Contributing

Maintained best-effort, with no response-time commitment.

Small corrections can go directly to a pull request. Before adding a command,
schema, dependency, compatibility path, plugin mechanism, platform promise, or
raising a ceiling, open an issue; these changes require explicit owner approval
under [`AGENTS.md`](../AGENTS.md).

Do not post credentials, private paths or repository identifiers, client content,
or raw evaluation output. Report security or privacy issues privately. Be direct,
specific, and respectful.

## Make a change

1. Use a full clone and read [`AGENTS.md`](../AGENTS.md). For behavior or trust
   boundaries, also read the [design](../docs/design.md),
   [contracts](../docs/contracts.md), and [threat model](../docs/threat-model.md).
2. Start from observable operator behavior or a minimal reproduction. Fix the
   existing semantic owner; prefer deletion or consolidation to new surface.
3. After toolchain changes, run `python3 tools/refresh_toolchain.py`. Never
   hand-edit generated receipts, approvals, manifests, pins, or managed mirrors.
4. Add focused proof for changed behavior, malformed input, or a destructive
   boundary. Tests must not call providers or hosted services.
5. Verify documentation examples against current CLI help, run `./gate`, then
   run the complete definition of done in [`AGENTS.md`](../AGENTS.md).

Candidate, case, profile, distribution, or catalog changes stale bound evidence;
catalog changes stale all routing receipts. Provider-free pull requests may need
fresh maintainer observations. Keep raw output private and use synthetic or split
credential placeholders.

## Pull requests

Explain the operator-visible problem and why the change is the smallest correct
fix. Complete the pull-request template's surface delta and verification fields.
Do not mix unrelated changes.

Use imperative commit subjects. Explain the reason in the body when it is not
obvious.
