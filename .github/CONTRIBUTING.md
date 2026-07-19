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
3. After toolchain changes, run `python3 tools/refresh_toolchain.py`; never edit
   generated records, manifests, pins, or mirrors.
4. Add focused tests, check examples, then run the full definition of done.

Candidate, case, profile, distribution, or catalog changes stale evidence. Keep
raw observations private.

## Pull requests

State the problem, smallest fix, surface delta, and verification. Do not mix work.
Pull requests against release mirrors are proposals; accepted changes are
reproduced and re-proved in the authoritative governed source before release.
