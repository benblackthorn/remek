# Design

## Outcome and owners

remek governs Agent Skill intake, proof, approval, projection, and verification.
Agents author and evaluate, Git transports, and installers place copies. remek's
boundary does not end the authorized task.

Semantic ownership inside the runtime is narrow:

| Concern | Owner |
| --- | --- |
| Canonical documents | `contract.py` |
| Frontmatter | `frontmatter.py` |
| Paths, descriptors, trees, and identities | `filesystem.py` |
| Atomic mutation outcomes and residue | `transaction.py` |
| Cases and evidence identities | `evaluation.py` |
| Governed state, findings, approvals, and readiness | `repository.py` |
| Authoring, maintenance, and release intent | `workflows.py` |
| Payload-free saved plans and reconstructed diffs | `plans.py` |
| CLI and stable exits | `app.py` |

## Ratified state model

Lifecycle (`draft`, `ready`, `retired`) and exposure (`source-only`,
`private-only`, `public-eligible`) are independent; distributions are allowlists.
Candidate changes force draft, cannot raise exposure, and stale proof. Promotion
keeps bytes; selected skills cannot be removed. Failed proof persists without
satisfying readiness. Immutable records are validated intrinsically before
current-state applicability; one malformed record does not erase its skill.

## Mutation protocol

Identity-only plans reconstruct before `apply`. Only `scaffold` directly creates
a mode-0700 workspace. No-follow transactions preserve foreign races and name
residue; there is no journal or power-loss claim.

## Release boundary

Targets bind GitHub identity, branch, expected and observed visibility, and
committed bytes. Historical target identity excludes the local remote alias,
which remains approval context and per-release remote binding. Audience is
history-immutable; delivery is not access. Verification rechecks before push.
Installer metadata is outside identity; the pinned entrypoint inventories twice.

## Constraints

The Python 3.11+ standard-library runtime is POSIX-only and offline except
read-only Git and target queries. One `remek.1` family and fixed ceilings keep it
reviewable. New surface needs owner approval. See [contracts](contracts.md) and
[threat model](threat-model.md).
