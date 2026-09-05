# Contracts

## Documents and storage

Normal documents use `"schema":"remek.2"` and an exact expected `kind`. Duplicate
keys, invalid UTF-8, non-finite numbers, excessive nesting, and unknown semantic
fields refuse. Authored `repository`, `skill-record`, `distribution`, and
`disclosure-policy` documents accept arbitrary JSON whitespace/key order and are
never automatically reformatted. Set-like lists are sorted and unique; case
order is significant. Immutable `evaluation` and `release-review` records,
`operation-plan`, and `release-manifest` use sorted two-space JSON with one final
newline. The compact `toolchain-manifest` omits itself.

The trusted caller selects the kind and its limits before reading hostile bytes:

| Document | Maximum bytes | Maximum JSON values |
| --- | --- | --- |
| Ordinary authored record | 64 KiB | 4,096 |
| `skill-record` | 256 KiB | 4,096 |
| `evaluation` | 512 KiB | 4,096 |
| `release-review` | 512 KiB | 16,384 |
| `operation-plan` and other bounded machine documents | 2 MiB | 4,096 |
| Rendered `command-result` | 1 MiB | 32,768 |

Maximum nesting is 12. The larger result budget applies only to trusted rendering;
parsing a `command-result` still has 4,096 values. Per-skill governance is 4 MiB
with at most 128 evidence files; source governance is 16 MiB including global
reviews. Filesystem traversal has separate bounded depth/entry/byte checks.
No limit can be raised by a document's self-declared kind.

`remek.json` records `repositoryId`, `skillsRoot`, and sorted `governedSkills`.
Consumer runtime is `.remek/toolchain`; the producer uses only
`skills/remek/toolchain` and governs exactly `skills/remek`. Exactly one layout is
accepted. `.remek/distributions/ID.json`, `.remek/disclosure-policy.json`,
`.remek/skills/NAME/skill.json`, optional `sources/`, `evidence/HASH.json`, and
`.remek/reviews/HASH.json` hold governance. Unknown governance paths fail; foreign
neighbors are preserved. Missing active review files and malformed historical
records fail without hiding an otherwise valid skill.

## Authored skill and payload

A `skill-record` has `skill`, `exposure`, `provenance`, and
`cases:{routing:[...],behavior:[...]}`. Provenance has `origin` (`captured`,
`designed`, or `imported`), `source`, `sourceNote`, `upstreamRepository`,
`upstreamRef`, `rights`, `rightsBasis`, and `license`. `source` is null or
`{path:"sources/RELATIVE",type:"file"|"tree",digest:SHA256}` under this skill's
private governance. File descriptors hash exact bytes; tree descriptors use the
retained candidate tree identity. No links or path escapes are accepted.
`sourceNote` is nonblank and at most 1,000 characters. A missing original must be
stated truthfully, never reconstructed as invented provenance.

Payloads implement the deliberately narrower `remek-text` profile: UTF-8 regular
files with supported `SKILL.md` frontmatter. CRLF is accepted and preserved;
parsing never rewrites bytes. Frontmatter supports the documented scalar fields
and bounded scalar `metadata`; arbitrary YAML, binary assets, links, special
files, bytecode, empty directories, private governance documents, and credentials
refuse. Limits are 256 KiB for `SKILL.md`, 2 MiB per other file, 256 files, 8 MiB,
75,000 lexical tokens, and 128 governed skills. Audit never executes code.

Empty case sets are valid for private source use and warn. Nonempty sets have at
most 50 unique cases. Routing cases contain `id`, `prompt`, `shouldActivate` and
need both positive and contrastive cases. Behavior cases contain `id`, `prompt`,
and one to twelve unique bounded `expectations`. Releases require both sets and
current evidence for each selected skill. Public payload `license` must exactly
equal reviewed provenance.

## Distribution and disclosure

A distribution has `id`, `audience`, `skills`, `target`, `delivery`,
`evidencePolicy`, `privateDisclosure`, and `activeReview`. The target binds
`provider:"github"`, `hostname`, `nameWithOwner`, local `remote`, `branch`, and
`expectedVisibility`. Public requires `PUBLIC`, eligible exposure and blocked
private material; private requires `PRIVATE`; `INTERNAL` is unsupported.
`delivery` is a declaration, not installation or access authorization.

`evidencePolicy` has sorted `routingProfiles` and `behaviorProfiles`. Each profile
has `kind`, `name`, `version`, `claim`, `runConfigDigest`, `trialCount`, and
`minimumPassCount`. Profiles permit 1–10 trials and a threshold from 1 to that
count. Release rejects `smoke`; manual-host and external profiles require at least
three trials. Run configuration hashes bind the exact UTF-8 configuration text.

Disclosure policy has sorted entries `{id,class,match,value}`. Ordinary edits
replace the active policy; there are no tombstones. A complete semantic policy
change stales reviews. Credentials cannot be excepted. Review exceptions bind a
selected skill, entry ID, entry content digest, and nonblank reason.

## Reported evaluation

An `evaluation` records `skill`, `evidenceKind`, `candidate`, `caseSetDigest`,
`routingCatalogDigest`, nullable `distribution`, six-field `profile` (without
`runConfigDigest`), `runConfiguration`, `trials`, and `artifacts`.
The actual configuration is nonblank, at most 16 KiB UTF-8, and its digest is
computed internally. A caller-supplied profile digest is refused.

Every case/trial pair appears once in exact case order and trial order, with
`{caseId,trial,outcome,observation}`. `outcome` is `pass`, `fail`, or `error`;
`observation` is 1–500 characters. Unreported templates cannot be recorded. Counts
and reported passing are derived; every case must reach the threshold. Artifact
references are optional, at most 32 `{label,digest}` pairs. remek validates their
shape, not external bytes or authenticity. Full traces can remain external;
record both actual failures and successes.

Behavior evidence forbids a distribution. Named routing evidence binds that
selected catalog. Whole-source routing evidence cannot qualify a named release.
Intrinsic validation precedes current candidate/case/catalog/profile matching.
Stale history remains stored. Identical recording is a no-op; new relevant reports
atomically append and clear every affected non-null `activeReview` pointer.

## Complete release review

A `release-review` records `context`, `contextDigest`, `selectedEvidence`,
`failureAcknowledgements`, `disclosureExceptions`, `reviewer`, valid ISO
`reviewedOn`, and four booleans: `rightsReviewed`, `evidenceReviewed`,
`proprietaryContentReviewed`, `publicIrreversibilityAcknowledged`.
The first three must be true; the last must be true for public release.
Templates contain false booleans, blank declarations, and deterministic proposals.
Only actual review and owner authorization justify filling them.

Context contains the full normalized distribution except `activeReview`, sorted
members `{skill,candidateDigest,skillRecordDigest,routingCaseDigest,
behaviorCaseDigest,evidenceSetDigest}`, and `disclosurePolicyDigest`.
Each evidence set binds all intrinsically valid currently applicable reports,
including failures and non-required profiles. Selected sorted report IDs must
cover all required member/kind/profile slots with current reported passes.
Every current required-profile failure needs exactly one acknowledgement
`{report,reason}`; no acknowledgement waives a required pass. Reasons are nonblank,
at most 1,000 characters. Non-required failures remain bound and visible without
becoming new profile requirements. Exceptions are at most 64 per selected skill.
Even an empty distribution requires review.

`review plan` returns the complete template and compact packet: exact members,
profile/report identities, failure IDs and private paths, additional-report counts,
provenance limitations, and disclosure findings. Observations are read from their
named private records. Oversized complete output refuses instead of truncating a
review. A selected missing review file is structurally invalid; null and stale
pointers mean not ready. Old review files are not automatically pruned.

## Identities and plans

SHA-256 digests are identities, not signatures. Candidate tree hashing retains
`remek.candidate.v1\0` and exact bytes plus Git-representable modes; this name does
not enable v1 document loading. Skill records and virtual case-set documents hash
normalized canonical semantics. Report/review IDs hash canonical record bytes.
Evidence sets hash `remek.evidence-set.v2\0` plus their canonical sorted report-ID
document. Context hashes `remek.review-context.v2\0` plus canonical context.
Only active pointers, stored reviews, and Git HEAD are excluded from review
subject identity; all selection, target, delivery, profile and policy fields bind.

Operation plans bind intent, inputs, source identities, toolchain, target states,
and a digest without embedding payload or diff. Normal mutation intents are `init`,
`eval-record`, `review-record`, `release`, `update`. `show` reconstructs a bounded
diff; `apply` reconstructs again and refuses drift. Reformatting authored JSON may
preserve review semantics but changes raw plan identity. The source-only converter
has its own `migrate-v1` reconstruction; normal apply rejects it.

## Release and executable boundary

`release-manifest` binds source/distribution identities, clean source commit and
branch digest, `reviewDigest`, release and payload IDs, candidate/file/directory
inventory, target verification digest, pre-release HEAD, remote URL hashes, and
exact expected commit paths. The review digest participates in release identity.
Private context stays hashed. A managed mirror owns only `skills/` and the manifest;
other files remain unchanged. Empty releases omit `skills/` entirely.

Lineage permits 256 manifest changes and binds source, distribution, audience,
target, and source ancestry. Target lineage binds provider, canonical host/repo,
expected and observed visibility, and branch. A remote alias is excluded from
historical target identity but bound by the review and each release. Audience or
semantic target changes require fresh mirror history. V1 manifests are refused.

Every owned regular file equals its raw HEAD blob and Git-representable mode.
Export uses 0644/0755 and no empty directories or payload `.gitattributes`.
Full object database integrity must pass. Active filters, hidden index flags,
submodules, auxiliary indexes, execution/transport overrides, dirty state, and
unexpected release commit paths refuse. Source and mirror equal their Git roots;
project mode inherits full monorepo integrity cost.

After trusted bootstrap, every Git/GitHub executable is resolved canonically,
absolute, regular, single-linked, and outside all selected roots. Child PATH is
filtered; empty/relative entries refuse. Resolution repeats for each launch/root
set. Subprocesses allow 30 seconds and 4 MiB UTF-8 I/O; target queries allow 64 KiB.
The tool never commits, pushes, installs, signs, tags, or changes visibility.

## Result and exit contract

`--json` emits one `command-result` envelope with `schema`, `kind`, `command`,
`status`, `changed`, `summary`, `findings`, `changes`, `data`, `nextAction`, and
`exitCode`. Normal results are complete; output failure uses an independent minimal
fallback preserving mutation outcome and reporting changed paths and residue, or
explicitly signaling omitted identifiers. A broken output stream never turns a
completed or ambiguous mutation into unchanged success.

Credential redaction covers free text and dynamic source-binding keys; trusted
protocol fields retain their defined values. It changes only displayed output,
never saved plan bytes or record identities. Key collisions fail output instead of
merging bindings.

| Operation | Important data |
| --- | --- |
| `check` | `structuralValid`, skills and identities/exposure, nullable `distribution`, `releaseReady`, `reviewStatus` |
| `audit` | `profile:"remek-text"`, `supported` |
| `eval plan` | template, candidate/case/catalog identities, `execution:"not-performed"` |
| `eval record` | report ID, derived `reportedPassing`, revoked distributions |
| `review plan/record` | complete packet/template; review/context IDs, distribution, prior pointer |
| `release plan` | review/release IDs, `mode`, `targetVerified`, `publicationPerformed:false` |
| `verify` | `artifactVerified:true`; source readiness and target false; declared review/release IDs |
| `release verify` | artifact/source/target/commit-lineage verification, exact source/mirror commits |
| `apply` | `outcome`, `changedPaths`, `residue`, operation-specific IDs |
| `update` | old/new bundle identities |

Review status is null without selection, otherwise `missing`, `stale`, `current`,
or `invalid`. Mutation outcomes are `unchanged`, `applied`, `restored`, `residue`, or
`unknown`. Publication is never claimed. `show` allows 768 KiB text diff; JSON mode
lowers diff to one third of 1 MiB, and `--max-bytes` can only lower it further.

Exits: 0 success/warnings; 1 blocking findings; 2 refused unchanged or completely
restored; 3 known mutation with failed reporting/final checks, residue, or ambiguity;
70 unexpected pre-mutation failure; 130 interruption with unchanged or fully
restored state. Mutation-aware errors, including saved-plan artifact failures,
take precedence over interruption/internal error codes.
