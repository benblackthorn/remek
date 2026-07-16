# Design

## Outcome and owners

remek governs Agent Skill sources and releases: structure, authoring intake, checks, cases, evidence, approvals, release projections, and pre-push verification. Fresh external sessions evaluate; Git owns history/transport; hosts and installers own discovery/installation; agents author in disposable workspaces. remek never calls models, executes skills, commits, pushes, tags, publishes, changes visibility, or updates copies.

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

Skills move among `draft`, `ready`, and `retired`, with `source-only`,
`private-only`, or `public-eligible` exposure. Distributions are exact private or
public allowlists. Candidate changes force draft, cannot raise exposure, and
stale evidence and approvals; promotion requires identical bytes and a new
reason. Removal refuses while selected.

Catalog, distribution-context, and release-set identities make relevant changes
stale. Receipts bind exact candidates, cases, evaluator profiles, results, and a
private report digest. Failed records persist but do not satisfy readiness. See
[contracts](contracts.md) for exact fields.

## Mutation protocol

Mutations save pure-identity plans without payloads or diffs. `plan show`
reconstructs exact intent before rendering a bounded diff; `apply` requires
equality. Only `scaffold` directly creates one absent mode-0700 workspace.
Transactions hold no-follow POSIX boundaries, stage all objects before public
replacement, preserve foreign race winners, and name residue. The guarantee is
process-lifetime only; there is no journal or power-loss claim.

## Release boundary

Targets bind GitHub identity, remote, branch, and exact public or private
visibility. Audience is history-immutable; delivery is not access control.
Release binds committed source and payload bytes to the authenticated target;
`release verify` rechecks one clean release commit before a separate push.
[Contracts](contracts.md) and the [threat model](threat-model.md) define the
exact refusals and limitations.

Installer metadata is outside toolchain identity. The trust-on-first-use wrapper
pins the manifest and verifier; the verifier inventories the complete tree twice
before import.

## Constraints

The shipped runtime is Python 3.11+, POSIX-only, standard-library-only, offline except read-only `git` state queries and `gh` target verification during release. One `remek.1` schema family and the fixed repository ceilings in `AGENTS.md` keep the product reviewable. New commands, persisted kinds, dependencies, platforms, adapters, or compatibility paths require owner approval.
