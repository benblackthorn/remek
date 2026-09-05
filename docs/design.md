# Design

## Outcome and semantic owners

remek supports a trustworthy private Agent Skills library and deliberate release
to another audience. Ordinary files and Git own authoring, revision, deletion,
exposure, selection, and disclosure editing. remek owns deterministic checking,
reported evidence, complete distribution reviews, exact projection, verification,
and bounded toolchain replacement. Providers and installers remain external.

| Concern | Owner |
| --- | --- |
| Strict documents, canonical machine records, trusted-kind bounds | `contract.py` |
| Read-only `remek-text` frontmatter parsing | `frontmatter.py` |
| Paths, descriptors, trees, and identities | `filesystem.py` |
| Atomic mutation, restoration, outcomes, and residue | `transaction.py` |
| Cases, profiles, retained trials, and evidence applicability | `evaluation.py` |
| Source declarations, inspection, structural and disclosure findings | `repository.py` |
| Complete review context, selected evidence, failures, and release readiness | `review.py` |
| Five mutation intents and hardened Git/release boundary | `workflows.py` |
| Payload-free saved plans and exact reconstructed diffs | `plans.py` |
| CLI, diagnostic redaction, complete output, and truthful machine results | `app.py` |
| Isolated, source-only v1 conversion | `tools/migrate_v1.py` |

## Source model

One `skill.json` contains exposure, provenance, and both case sets. Exposure is a
ceiling: `source-only`, `private-only`, or `public-eligible`; a distribution is an
explicit allowlist. No lifecycle or promotion state exists. A source skill can be
useful privately before release evidence exists. Deletion is ordinary reviewed
file/Git work; stale references fail checking. Foreign data is never pruned.

Authored JSON permits whitespace and key order without automatic rewriting.
Semantic normalized hashes bind reviews; exact filesystem bytes bind saved plans
and raw Git release checks. Evidence and review history is append-only through
remek and remains after authored changes. Staleness is calculated, not persisted.

## Review model

Evaluation reports retain caller-declared configuration, ordered observations,
and optional artifact identities. They never claim authenticated execution.
A batch review binds the full distribution, complete selected skill records,
candidates/cases, full disclosure policy, and every currently relevant report.
Required profiles need a pass and acknowledgement of each current failure.
Other-profile experiments remain visible and bound without adding requirements.

The only mutable review state is each distribution's `activeReview` pointer.
Recording new relevant evidence and clearing affected pointers is one transaction;
identical evidence does neither. Deleting the newly recorded report cannot
silently restore an active review. An empty distribution still needs review.

## Mutation and release

Every CLI mutation is an exact saved plan followed by `show` and `apply` under
existing owner authorization. Plans contain identities and intent, not payload
copies. Reconstruction refuses drift in source bytes, external reports, bundle,
and target preimages. No-follow transactions stage, verify, replace, restore,
and report residue. There is no persisted journal or power-loss claim.

Release retains the defensive Git kernel: full object integrity, raw HEAD bytes
and executable intent, no active filters or hidden index state, safe executable
resolution, clean source/mirror, complete historical lineage, authenticated target,
and exact mirror parent/changed paths. A v2 manifest binds the review digest.
V2 starts fresh manifest lineage; old v1 histories remain untouched.

## Ratified surface and ceilings

The v2 surface is ten verbs and thirteen leaves, five normal mutation intents,
one `remek.2` family, one produced skill, and zero third-party runtime dependencies.
The former authoring/lifecycle/repair/doctor/per-skill approval commands are removed.
The retained source-only converter is the sole v1 reader; privacy fingerprints
recognize legacy private documents without accepting them as runtime records.

Owner-approved record bounds support full observations and batch reviews. Test
counts are reported, with no collected-test cap; observable safety coverage and
fixed token/file limits constrain growth. Do not raise accounting or ceilings to
admit work. Final before/after measurements belong in the reviewed change, not a
permanent implementation plan. Repository ceilings are in [AGENTS.md](../AGENTS.md);
record limits and schemas are in [contracts](contracts.md). Trust assumptions are
in the [threat model](threat-model.md).

Inspections are recomputed at mutation and verification boundaries. Within one
unchanged preflight, immutable inspected values may be reused. Each tree snapshot
reads the selected tree twice to detect concurrent mutation. This deliberate
linear I/O is retained; there is no long-lived cache or alternate identity owner.
