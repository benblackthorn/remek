# Contracts

Canonical documents are bounded, sorted, newline-terminated UTF-8 with exact
`kind` and `"schema": "remek.1"`; owned JSON uses two-space indentation. The
compact toolchain manifest omits itself. Digests are SHA-256 identities, not
signatures. Invalid or noncanonical input refuses.

## Repository layout

`remek.json` names the repository, payload root, and governed skills. `.remek/`
holds runtime, policy, provenance, cases, retained source, receipts,
distributions, and disclosure. The producer embeds its runtime under
`skills/remek/toolchain/` and governs only `skills/remek/`. Foreign neighbors
are never pruned.

## Plans and mutation

An `operation-plan` binds intent, inputs, hostile sources, toolchain, path states,
and digest without payload or diff. `apply` must reconstruct it exactly.
Workspaces bind origin, retained source, candidate, policy, provenance, and cases;
receipts are forbidden.

## Skills, policy, and provenance

Payloads are canonical `SKILL.md` UTF-8 regular-file trees. Binary assets, links,
special files, bytecode, empty directories, remek metadata, credentials, and unresolved
core templates refuse; script templates warn. Limits: 256 KiB `SKILL.md`, 2 MiB
per other file, 256 files, 8 MiB, 75,000 lexical tokens, and 128 skills. Routing
needs positive and contrastive prompts; behavior cases need one to twelve bounded
expectations. Policy binds lifecycle, exposure, and reason. Provenance binds
retained source, upstream, and rights; imports and releases require completeness.

## Distributions, disclosure, evidence, and approvals

A distribution binds audience, skills, GitHub target, delivery, profiles, and
disclosure. Public requires `PUBLIC` and blocked private material; private
requires `PRIVATE`; `INTERNAL` is unsupported. Release forbids `smoke`; manual
and external profiles need three trials per case.

Disclosure ids immutably bind class, constrained match, and value; omission
creates a tombstone. Credentials cannot be excepted; other exceptions bind id
and content digest.

Cases and routing catalog have separate digests. Profiles bind host, claim, run
configuration, trials, and threshold; changing evaluation inputs needs new proof.
Evidence binds bytes, cases, context, full profile, ordered results, and one
private report digest. Every case must pass; failures persist. Approval binds
candidate, provenance, distribution, target, exceptions, date, rights, and public
irreversibility review. Identical recording is a no-op.

Records are at most 64 KiB, 128 per skill, 4 MiB per skill, and 16 MiB per source.
Raw configurations, reports, transcripts, reasoning, and provider output stay
outside; receipts retain digests and bounded summaries.

## Toolchain and release manifests

`toolchain-manifest` binds toolchain modes and digests except itself; the
enclosing tree covers it. Unknown entries, unsafe objects, or drift refuse.

`release-manifest` binds lineage, distribution, payload, target, prior HEAD,
remotes, and commit paths while hashing private context. One complete lineage
allows 256 manifest changes and one source, distribution, audience, target, and
ancestor; audience or target changes need fresh history. remek manages only
`skills/` and the manifest, preserves other mirror files, and exports no governance.

Owned files equal raw HEAD blobs and modes. Export uses 0644/0755, without empty
directories or `.gitattributes`. Bounded HEAD integrity must pass; filters,
hidden index state, submodules, auxiliary indexes, and local Git execution or
transport overrides refuse. Subprocesses allow 30 seconds and 4 MiB UTF-8 I/O;
target queries allow 64 KiB. `plan show` allows 768 KiB text or one third of its
1 MiB JSON bound; `--max-bytes` only lowers limits.

## Stable exits and finding classes

- `0`: success or warning-only result
- `1`: blocking findings
- `2`: safe pre-mutation refusal
- `3`: mutation completed with residue or ambiguity
- `70`: unexpected internal failure
- `130`: interruption

Finding prefixes name their owner; credential findings expose only code and path.
