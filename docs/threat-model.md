# Threat model

## Trusted inputs

Trust covers the loaded bundle, interpreter, OS, intent, roots, and ancestors.
First use is trust-on-first-use; installer metadata is outside identity. The
pinned entrypoint inventories twice before import. Repository inputs, Git,
remotes, and subprocess output are hostile; candidate content never executes.

## Defended boundaries

- Bounded reads reject unsafe objects, unstable identities, bytecode, excess
  depth or size, and overlap with protected paths.
- Identity-only plans must reconstruct exactly before diff or apply.
- No-follow mutations stage and verify before replacement, roll back cooperative
  failures, preserve foreign race winners, and name residue.
- Credential checks never show matched text; credentials cannot be excepted.
- Evidence binds bytes, cases, profile, trials, and private report digest. Input
  changes stale proof; receipts do not prove honesty.
- Release binds readiness, raw HEAD, branch, clean remotes, and authenticated
  target visibility; hostile Git features refuse.
- Mirrors receive payload and manifest only; governance stays private and private
  context appears by digest.
- `release verify` rechecks the clean commit and target before a separate push.

## Subprocess and network boundary

Ordinary workflows are offline. Release uses bounded `git` and `gh repo view` for
state and target identity. remek never wraps install, commit, push, tag, publish,
or visibility.

## Honest limitations

People, agents, hooks, and processes can bypass remek; forge controls are separate.

Transactions assume cooperative local POSIX storage, not hostile writers,
compromised execution, failure, power loss, network storage, Windows, or
unretained history. No journal exists; late failure may leave residue and exit 3.
Paths are case-sensitive; trusted roots need canonical casing elsewhere.

Screening can err; public history and copies retain bytes, so use separate
history. Manifests are not signatures. Replacing the trusted bundle is out of
scope. Writers can fabricate proof; audit checks structure, not independence,
grader quality, or provenance.
