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
- Credentials cannot be excepted. Output redacts matched free text and dynamic
  keys while preserving trusted protocol vocabulary.
- Evidence retains reported configuration and per-trial observations bound to bytes,
  cases, profile, and routing context. Input changes stale evidence; reports do not
  prove honesty or freeze unbound live data.
- A batch release review binds full distribution context and all current relevant
  evidence; it never grants runtime, tool, or script permission, which the host
  enforces independently.
- Release binds readiness, raw HEAD, branch, clean remotes, and authenticated
  target visibility; hostile Git features refuse.
- Every post-bootstrap `git` and `gh` launch resolves an absolute canonical,
  single-linked regular executable outside all selected source, mirror,
  staging, and audit roots. Relative or empty PATH entries refuse;
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

Organizations may create the mirror commit under an external Git signing policy
before `release verify`, or sign a tag pointing to the verified commit. remek
holds no signing keys, does not verify signatures, and treats them as neither
evaluation evidence nor release review.

## Honest limitations

People, agents, hooks, and processes can bypass remek; forge controls are separate.

Transactions assume cooperative local POSIX storage, not hostile writers,
compromised execution, process death, power loss, network storage, Windows, or
unretained history. No journal exists; late failure may leave residue and exit 3.
Reporting failure after known mutation retains that outcome even if normal output
cannot be rendered.
Paths are case-sensitive; trusted roots need canonical casing elsewhere.

Screening can err; public history and copies retain bytes, so use separate
history. Manifests are not signatures. Replacing the trusted bundle is out of
scope. Writers can fabricate reports. Candidate audit checks structure, not
benign intent, script safety, upstream trust, or host execution; evidence
validation does not prove evaluator independence or grader quality. A review's
reviewer field is a declaration, not authentication or separation-of-duties
proof. It binds explicit reported evidence identities but cannot prove the reviewer
read them or the observations were honest. Newly recorded relevant evidence clears
active review pointers atomically; historical evidence remains inspectable.

## Source-only conversion

The v1 converter trusts only the validated producer checkout. It inventories old
bytes without importing old code and binds a verified private backup, source,
rehearsal target, mapping, and toolchain. It writes only inventoried owned target
paths. Old source, installed hosts, mirrors, raw reports, foreign work, and Git
history remain separate custody concerns. Legacy aggregate receipts cannot become
current per-trial evidence, and old approvals cannot authorize the new review scope.
Normal runtime rejects v1; privacy screening still recognizes legacy private
record shapes embedded in candidate payloads.
