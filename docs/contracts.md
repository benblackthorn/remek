# Contracts

Canonical JSON is bounded UTF-8, newline-terminated, key-sorted, and carries `"schema": "remek.1"` plus exact `kind`. Owned documents use two-space indentation; the compact toolchain manifest alone omits itself. Invalid or noncanonical owned fields refuse. Digests are lowercase SHA-256 integrity identities, not signatures.

## Repository layout

```text
remek.json
skills/<name>/ or .agents/skills/<name>/       pure Agent Skill payload
.remek/toolchain/                               initialized-source runtime
.remek/skills/<name>/
  policy.json, provenance.json
  routing-cases.json, behavior-cases.json
  sources/<portable-label>
  evidence/<sha256>.json
  approvals/<sha256>.json
.remek/distributions/<name>.json
.remek/disclosure-policy.json
```

The producer embeds its manifest-owned runtime at `skills/remek/toolchain/` and governs only `skills/remek/`. `remek.json` identifies the repository, skill root, and governed skills. Foreign neighbors are never pruned.

## Plans and mutation

An `operation-plan` records root, command, normalized inputs, generated identities, exact toolchain identity, absolute hostile-source identities, path-level before/after identities, bindings, and covering `planDigest`; it holds no payload or diff. Commands are `init`, `accept`, `distribution-accept`, `disclosure-accept`, `retire`, `remove`, `eval-record`, `approve-record`, `release`, `repair`, and `update`. `apply` reconstructs current intent and requires byte-equal projection and bundle identity.

A workspace records mode, skill, origin, retained source, and base candidate, policy, provenance, and case identities. New bases are null; revision bases match current state. Evidence and approvals are forbidden.

## Skills, policy, and provenance

Payloads are UTF-8 regular-file trees with canonical `SKILL.md`. Binary assets, links, special files, bytecode, empty directories, remek metadata, credential shapes, and unresolved templates in `SKILL.md` or references refuse; scripts receive advisory template findings. Limits: `SKILL.md` 256 KiB, other files 2 MiB, candidates 256 files/8 MiB/75,000 lexical tokens, and sources 128 skills. Routing needs unique ids/prompts and positive/contrastive cases; behavior cases need one to twelve unique bounded expectations.

Policy stores skill, lifecycle, exposure, and reason. Provenance stores origin, retained-source digest and portable label, optional upstream identity, and rights, basis, and license. Imports require all upstream fields; release requires complete rights.

## Distributions, disclosure, evidence, and approvals

A distribution binds id, audience, sorted skills, canonical GitHub target, delivery, evaluator profiles, and private-disclosure handling. Public requires `PUBLIC` and blocked private disclosure; private requires `PRIVATE`; `INTERNAL` is unsupported. Release forbids `smoke`; `manual-host` and `external` require three trials per case.

Disclosure entries contain `id`, class (`credential`, `public-disclosure`, `note`), match (`literal` or constrained `glob`), and value. Omitting an id stores a canonical `retired` tombstone; authored retirement refuses. Meaning is immutable by id. Credentials cannot be excepted; other exceptions bind active id and content digest.

Case-set digests cover canonical cases; routing-catalog digest covers ordered name/description pairs. Profiles bind kind (`manual-host`, `test-suite`, `external`), bounded name/version, claim (`smoke`, `regression`, `comparative`), frozen run-config digest, trials, and minimum passes. The distribution binds the full profile, so harness, model, budget, grader, baseline, or threshold changes require new evidence and approval.

Evidence binds skill, kind, candidate, case set, applicable catalog/distribution, complete profile, ordered aggregate passes, and bounded artifact digests. Exactly one `evaluation-report` binds the private observations, trial outcomes, and trace locations or digests. Every case must reach threshold. Passing and failed canonical receipts are content-addressed.

Approval binds candidate, provenance, distribution context, audience, target, delivery, exceptions, date, rights and proprietary-content reviews, plus public irreversibility review when public. Identical recording is a no-op.

Records are at most 64 KiB each, 128 per skill, 4 MiB governance per skill, and 16 MiB per repository. Configurations, reports, transcripts, reasoning, and raw provider output stay outside; receipts retain digests and bounded summaries.

## Toolchain and release manifests

`toolchain-manifest` lists tree modes and file digests, excluding itself and non-toolchain paths. The enclosing tree covers it. Unknown entries, unsafe objects, or identity changes refuse.

`release-manifest` binds audience, source lineage, distribution and payload identities, exact candidates and files, target verification, prior mirror HEAD, remotes, and expected commit paths. Private context is hashed. A complete non-shallow branch permits at most 256 manifest-changing commits and retains one source, distribution, audience, target, and ancestor source commit. Audience or target changes require fresh history. remek manages only `skills/` and this manifest, preserves mirror-owned files, and exports no governance.

Owned source and managed-mirror files equal raw HEAD blobs and Git modes. Export uses 0644 files, 0755 executables/directories, no empty directories, and no `.gitattributes`. Commit-graph and multi-pack-index reads are disabled; bounded full HEAD integrity must pass. Active filters, hidden/unresolved index entries, submodules, and local push-program, credential-helper, push-option, or HTTPS overrides refuse. Subprocesses allow 30 seconds and 4 MiB UTF-8 I/O; target queries allow 64 KiB.

`plan show` allows 768 KiB text diffs; JSON uses one third of its 1 MiB output bound to absorb escaping. `--max-bytes` only lowers these ceilings.

## Stable exits and finding classes

- `0`: success or warning-only result
- `1`: deterministic blocking findings
- `2`: safe refusal before mutation, including stale plan, dirty Git, missing tool, and target mismatch
- `3`: mutation completed with residue or ambiguity
- `70`: unexpected internal failure
- `130`: interruption

Finding prefixes identify their semantic owner. Credential diagnostics expose only code and path, never matched content.
