# Threat model

## Trusted inputs

Trust covers the loaded bundle, caller-selected interpreter, OS, intent, roots,
and ancestors. First use is trust-on-first-use; installer metadata is outside
identity. Convenience wrappers select Python through `/usr/bin/env`, so PATH and
interpreter selection before remek code loads remain trusted inputs. Strict
adversarial invocation uses an explicitly trusted absolute Python path. The
pinned entrypoint inventories twice before import. Repository inputs, child-tool
PATH entries, Git, remotes, and subprocess output are hostile after bootstrap;
candidate content never executes.

## Defended boundaries

- Bounded reads reject unsafe objects, unstable identities, bytecode, excess
  depth or size, and overlap with protected paths.
- Identity-only plans must reconstruct exactly before diff or apply.
- No-follow mutations stage and verify before replacement, roll back cooperative
  failures, preserve foreign race winners, and name residue.
- Credential checks never show matched text; credentials cannot be excepted.
- Evidence binds bytes, cases, profile, trials, and private report digest. Input
  changes stale proof; receipts do not prove honesty or freeze unbound live data.
- Release approval binds reviewed distribution context; it never grants runtime,
  tool, or script permission, which the host enforces independently.
- Release binds readiness, raw HEAD, branch, clean remotes, and authenticated
  target visibility; hostile Git features refuse.
- Every post-bootstrap `git` and `gh` launch resolves an absolute canonical,
  single-linked regular executable outside all selected source, mirror,
  workspace, staging, and audit roots. Relative or empty PATH entries refuse;
  missing, non-directory, nonregular, hardlinked, symlinked-forbidden, and
  forbidden-root entries are excluded from the child PATH. Resolution is
  repeated for each root set and never globally cached.
- Mirrors receive payload and manifest only; governance stays private and private
  context appears by digest.
- `release verify` rechecks the clean commit and target before a separate push.

## Subprocess and network boundary

Ordinary workflows are offline. Release uses bounded `git` and `gh repo view` for
state and target identity. remek never wraps install, commit, push, tag, publish,
or visibility. These checks constrain child tools only after trusted Python has
loaded verified remek bytes; they do not authenticate the interpreter or repair
pre-bootstrap PATH selection.

## Honest limitations

People, agents, hooks, and processes can bypass remek; forge controls are separate.

Transactions assume cooperative local POSIX storage, not hostile writers,
compromised execution, failure, power loss, network storage, Windows, or
unretained history. No journal exists; late failure may leave residue and exit 3.
Paths are case-sensitive; trusted roots need canonical casing elsewhere.

Screening can err; public history and copies retain bytes, so use separate
history. Manifests are not signatures. Replacing the trusted bundle is out of
scope. Writers can fabricate proof. Candidate audit checks structure, not
benign intent, script safety, upstream trust, or host execution; evidence
validation does not prove evaluator independence or grader quality. Approval's
reviewer field is a declaration, not authentication or separation-of-duties
proof, and approval does not attest a particular evidence receipt.
