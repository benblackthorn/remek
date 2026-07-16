# Threat model

## Trusted inputs

Trust covers the loaded bundle, interpreter, OS, explicit intent, selected roots,
and external ancestors. First execution is trust-on-first-use. Installer metadata
is outside identity. The wrapper pins manifest and entrypoint by SHA-256; the
entrypoint validates the complete toolchain twice before import.

Repository and workflow inputs, Git state, remotes, and subprocess output are
hostile. The runtime never imports or executes candidate content.

## Defended boundaries

- Bounded reads reject links, special files, unstable identities, bytecode, and
  excess depth, entries, files, or bytes.
- Authored paths must be portable. Selected absolute paths are canonicalized against opened roots and may not overlap protected inputs or destinations.
- Plans contain identities, not payload bytes. Reconstruction must exactly match the reviewed plan before diff or apply.
- Mutations stage before replacement, use descriptor-relative no-follow
  operations, verify destinations, roll back cooperative failures, preserve
  foreign race winners, and name residue.
- Checks screen credential shapes without matched text. Disclosure rules cover
  owner-defined private material; credentials cannot be excepted.
- Evidence binds candidate, cases, catalog, evaluator profile, trials, and a
  private report digest. Input changes stale proof; receipts do not prove honesty.
- Release binds readiness, raw HEAD identities, branch, credential-free remotes,
  and authenticated exact target visibility. Hostile Git features and overrides
  refuse; [contracts](contracts.md) lists the exact checks.
- Mirrors receive only open payload and `release-manifest.json`; governance and
  retained sources stay private.
- Public manifests retain only digests of private source-branch, distribution, target-verification, and remote values.
- `release verify` rechecks the clean one-commit mirror state and current target immediately before the separately authorized push.

## Subprocess and network boundary

Ordinary workflows are offline; release uses installed `git` for state and `gh
repo view` for target identity and visibility. Git execution is isolated and
bounded; unsafe repository features fail closed. remek never wraps install,
commit, push, tag, publish, or visibility.

## Honest limitations

Guarantees apply only through remek. People, agents, hooks, or other processes
can bypass it; branch protection and forge review remain separate.

Transactions cover cooperative local POSIX filesystems, not hostile writers or
ancestors, compromised execution, process or machine failure, power loss,
network filesystems, Windows, or history outside retained lineage. There is no
journal; post-replacement failure may leave named residue and exit 3.

Path overlap is case-sensitive POSIX text. On case-insensitive filesystems, trusted selected roots must use canonical casing.

Screening can be wrong, and visibility can change after verification. Public
history, forks, tags, releases, caches, and clones retain bytes; use separate
history rather than converting a private mirror.

The manifest is not a signature. It exposes the lineage commit and hashes other
private context. Replacing the trusted bundle is outside the model. Authorized
writers can fabricate evidence; audit validates structure, not independence,
grader quality, or provenance.
