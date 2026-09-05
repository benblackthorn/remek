# Contributing

Send small corrections as pull requests. New surface or a higher ceiling needs
an issue and owner approval under [`AGENTS.md`](../AGENTS.md).
Reproduced defects, compatibility or security evidence, documentation fixes,
and narrow improvements are welcome. The governance model, persisted schema,
trusted surface, platform guarantees, and release semantics remain
maintainer-controlled and expand conservatively.

Never post credentials, private content, or raw evaluations. Report sensitive
issues privately.

## Make a change

1. Read [`AGENTS.md`](../AGENTS.md) and linked architecture documents.
2. Reproduce behavior, fix its owner, and consolidate first.
3. After toolchain changes, run `python3 tools/refresh_toolchain.py` to refresh
   the manifest, bootstrap pins, and shims together. Edit authored declarations as
   ordinary files; let remek produce immutable machine records.
4. Add focused tests, check examples, then run the full definition of done.

Candidate, case, or applicable routing-catalog changes stale affected evidence.
Distribution declarations and required-profile policy changes stale review and may
change required passing coverage; retained reports remain unchanged.
Retain actual configuration and bounded observations in private governance;
keep full traces and migration maps private. Review declarations require actual
owner-authorized review, not merely passing checks.

## Pull requests

State the problem, smallest fix, surface delta, and verification. Do not mix work.
Pull requests against release mirrors are proposals; accepted changes are
reproduced and re-proved in the authoritative governed source before release.

## Release the source project

Release this repository from `main`. Check `./remek --version`, update affected
docs, and complete the [`AGENTS.md`](../AGENTS.md) definition of done before the
source commit. Commit and push under owner authorization, then require the Gate
workflow to pass for that exact commit. Tag it `v<VERSION>` and publish the GitHub
release with concise change and migration notes under publication authorization.

The GitHub source archive contains the tagged repository. It is not a verified
governed distribution artifact. To release selected skills to a mirror, follow
the [distribution workflow](../skills/remek/references/workflows.md#release-verify-and-update):
actual profile evidence, complete review, clean source and mirror, and authenticated
target verification still apply. A source tag does not supply those records.
