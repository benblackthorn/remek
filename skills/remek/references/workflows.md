# remek workflows

## Choose the source and preserve work

A private governed source is the normal home for one owner's skills. Same-owner
machines clone/pull that source. Use a separate private team mirror or public mirror
when crossing an audience boundary. A distribution is selection for another
repository/audience, not source synchronization. Reuse existing conventions and
explicit authorization; resolve unknown names, paths, and audience before creation.
The remek producer repository contains only `skills/remek/`; never author user or
private skills there. Locate the owner's separate governed source first.

Use absolute paths and put global `--root`/`--json` before the command. `init`,
`audit`, and `verify` take explicit paths and forbid `--root`. Plans belong outside
source, bundle, input, target, and transaction-parent roots. An absent init target's
parent is protected: keep its plans in a different private directory.

Create disposable artifacts under one external mode-0700 run directory when needed.
Keep persistent original sources, traces, backups, and maps under owner-selected
private storage. Never store private artifacts inside installed skills or public
payloads. An ignored repository scratch directory is coordination-only and requires
verified containment, no symlink components, and actual Git ignore status. Preserve
foreign files; remove only this run's proven disposable bytes after verifying custody.

## Initialize and author

From a reviewed installed bundle:

```bash
python3 -I -S -B /abs/installed/remek/scripts/cli.py init /abs/sources/private-skills --output /abs/private-plans/init.json
python3 -I -S -B /abs/installed/remek/scripts/cli.py show /abs/private-plans/init.json
python3 -I -S -B /abs/installed/remek/scripts/cli.py apply /abs/private-plans/init.json
```

Use `apply` after inspecting exact effects under existing authorization. Initialization
preserves README and foreign files; it refuses populated `skills/`. `--project`
intentionally governs `.agents/skills/`. For an existing ungoverned collection, make
verified private copies first, initialize a separate source, then copy reviewed
payloads and author records. Do not move/delete original work to satisfy a refusal.

Before ordinary edits, verify that an existing checkpoint preserves the exact
pre-edit payload and old case definitions. Preserve unique uncommitted bytes in a
verified private backup if that checkpoint does not cover them. An existing verified
checkpoint is sufficient; do not require a new commit for each edit. Ordinary edits
do not have remek's transaction or stale-plan protection.

Create `skills/NAME/SKILL.md` and resources with ordinary file edits,
add NAME to sorted `remek.json.governedSkills`, and write
`.remek/skills/NAME/skill.json`. This example is an authored declaration to adapt
truthfully; its empty case sets allow source use and cannot qualify a release:

```json
{
  "schema": "remek.2",
  "kind": "skill-record",
  "skill": "example",
  "exposure": "source-only",
  "provenance": {
    "origin": "designed",
    "source": null,
    "sourceNote": "Describe the actual reviewed source and any retention limitation.",
    "upstreamRepository": "",
    "upstreamRef": "",
    "rights": "",
    "rightsBasis": "",
    "license": ""
  },
  "cases": {"routing": [], "behavior": []}
}
```

Retain a real brief or completed procedure under this skill's `sources/` and use a
checked `{path:"sources/brief.md",type:"file",digest:SHA256}` descriptor when available.
A tree descriptor binds exact retained files and executable modes. Imports preserve
reviewed upstream bytes; missing original material is an explicit limitation, never
an invented upstream claim. Match directory/frontmatter names, and describe script
side effects, commands, dependencies, and access in `compatibility`. `allowed-tools`
is host guidance, not cross-host permission.

```bash
./remek audit /abs/reviewed-copy/NAME
./remek check
```

The supported `remek-text` profile accepts bounded UTF-8 regular files and supported
scalar frontmatter, including preserved CRLF. It is narrower than general YAML and
Agent Skills interchange. Correct only reviewed structure in a copy; audit never
normalizes upstream or installed files. It does not establish benign intent.

Revise payload and declarations with ordinary edits, inspect the Git diff, and run
`check`. Keep historical evidence when revisions make it stale.
Change exposure directly. To retire without deletion, choose `source-only` and remove
selection from distributions. To remove, review and delete the owned payload/record
and its references together; preserve any valuable sources/history first.

## Author distribution and disclosure

Write `.remek/distributions/DIST.json` directly. It has this shape (replace identity
and profile placeholders before validation):

```json
{"schema":"remek.2","kind":"distribution","id":"dist","audience":"private","skills":["example"],"target":{"provider":"github","hostname":"github.com","nameWithOwner":"OWNER/REPO","remote":"origin","branch":"main","expectedVisibility":"PRIVATE"},"delivery":["gh"],"evidencePolicy":{"routingProfiles":[{"kind":"manual-host","name":"HOST","version":"VERSION","claim":"regression","runConfigDigest":"CONFIG_SHA256","trialCount":3,"minimumPassCount":3}],"behaviorProfiles":[{"kind":"test-suite","name":"SUITE","version":"VERSION","claim":"regression","runConfigDigest":"CONFIG_SHA256","trialCount":1,"minimumPassCount":1}]},"privateDisclosure":"block","activeReview":null}
```

Profiles bind exact configuration text by SHA-256. Preserve real configuration or
revise a profile under owner authorization; a historical hash cannot recover its
preimage. Public requires `audience:"public"`, `PUBLIC`, blocked private disclosure,
`public-eligible` skills, reviewed rights, exact frontmatter/provenance license, and
explicit irreversibility review. GitHub is the only authenticated target implemented.
Delivery declarations do not perform installation or provide access.

Edit `.remek/disclosure-policy.json` as one complete active policy. Entries have
`id`, `class`, `match`, and `value`; there are no retired entries/tombstones. Changing
any semantic policy field stales reviews. Credentials cannot be excepted. Other
exceptions bind skill, entry ID and digest, and a substantive reviewer-owned reason.

## Evaluate outside remek and record observations

Author nonempty routing cases with positive and contrastive prompts, and behavior
cases with explicit observable expectations. Then prepare templates:

```bash
./remek --json eval plan NAME --kind behavior
./remek --json eval plan NAME --kind routing --distribution DIST
```

Use a compatible authorized external runner or actual manual trials. Record the
actual `runConfiguration`: host/model/version, relevant inputs, baseline, isolation,
permissions, retry/budget policy, logging and grader limitations. Freeze or identify
dynamic inputs and explain freshness limits. Keep full private traces separately.
remek does not invoke the runner or verify provider execution.

Fill every ordered `trials` row with `pass`, `fail`, or `error` and a 1–500 character
observation. Do not omit failures, infer successes from missing output, aggregate
away uncertainty, or invent observations from old receipts. The template's
`unreported` rows and blank configuration refuse recording. The six-field report
profile omits `runConfigDigest`; remek computes it from retained configuration.
Optional artifact references bind hashes, but their external bytes need separate
verification. Named routing reports cover that distribution; behavior reports have
no distribution. Whole-source routing does not qualify named release.

```bash
./remek eval record NAME --from /abs/private-inputs/behavior.json --output /abs/private-plans/behavior.json
./remek show /abs/private-plans/behavior.json
./remek apply /abs/private-plans/behavior.json
./remek eval record NAME --from /abs/private-inputs/routing.json --output /abs/private-plans/routing.json
./remek show /abs/private-plans/routing.json
./remek apply /abs/private-plans/routing.json
```

Each new relevant report and all affected review-pointer clearances apply atomically.
Identical canonical reports are a no-op and do not revoke. Historical evidence is
retained. Missing/stale evidence warns for private use; release requires current
coverage for each selected skill and required profile.

## Review one complete distribution

```bash
./remek --json review plan DIST
```

Inspect the complete packet: exact selection/candidate identities, full declarations
and provenance, required evaluator profiles and selected report paths, every current
relevant failure, additional reports, disclosure findings, target, and visibility.
Read observations in the named private files. The packet contains deterministic
passing-report proposals, false booleans, and blank reviewer/date/reasons. Missing
evidence may yield an incomplete template with blocking findings; do not record it.

Review published manifest metadata too: selected names/paths, modes and digests,
source and prior-mirror commit IDs, audience, source/distribution/branch/target/remote
identity hashes, release/review digests, and expected commit paths. Hashes of guessable
private labels are not confidential redaction. Inspect the exact manifest bytes in
the release plan diff before applying it.

A required-profile failure needs a substantive acknowledgement, and a current pass
is still required for the same slot. Non-required failures are visible and bound
without becoming new requirements. No declared pass or reason proves honesty.
Only actual owner-authorized review justifies `rightsReviewed`, `evidenceReviewed`,
`proprietaryContentReviewed`, and public irreversibility acknowledgement. The review
binds all currently relevant evidence, not just selected successes. Even an empty
selection needs review because clearing a mirror changes its audience's payload.

```bash
./remek review record DIST --from /abs/private-inputs/review.json --output /abs/private-plans/review.json
./remek show /abs/private-plans/review.json
./remek apply /abs/private-plans/review.json
./remek check --distribution DIST
```

Review files are immutable; the distribution points to the active hash. New relevant
reports clear it. Changes to reviewed candidates, declarations, policies, or relevant
reports stale its context.
Deleting new evidence does not automatically reactivate an old pointer. A missing
referenced file or malformed historical record is an error and preserves visibility
of an otherwise valid skill. Do not repair by hiding failures or deleting history.

## Release, verify, and update

Source and managed mirror must be clean Git worktree roots with committed HEADs.
The mirror's branch must match the authored target.
The full object database must pass within the fixed 30-second subprocess limit;
large project repositories inherit that cost. Use a dedicated source if necessary.
remek refuses active filters, hidden index flags, submodules, raw-HEAD mismatch,
unsafe executables/PATH, remote credentials, and incompatible lineage.

```bash
./remek release plan DIST --mirror /abs/mirror --output /abs/private-plans/release.json
./remek show /abs/private-plans/release.json
./remek apply /abs/private-plans/release.json
```

Only `skills/` and `release-manifest.json` are materialized. Foreign mirror files
stay unchanged. Under separate authorization, use Git to inspect and commit exactly
the declared changed paths in one commit over the bound parent. Then:

```bash
./remek release verify DIST --mirror /abs/mirror
./remek verify /abs/mirror
```

`release verify` checks artifact, source readiness, target, and commit lineage at
that time. `verify` checks only the declared artifact inventory. Staging is offline:

```bash
./remek release plan DIST --staging /abs/staging-runs/release --output /abs/private-plans/staging.json
./remek show /abs/private-plans/staging.json
./remek apply /abs/private-plans/staging.json
./remek verify /abs/staging-runs/release
```

Staging has no authenticated target claim. A v2 mirror needs fresh manifest lineage;
leave old v1 mirrors/history intact. Signatures, if required externally, neither
replace evidence nor review. Publishing, pushing, tags, visibility, host installation,
and consumer updates remain separate owner-authorized actions. Report publication
and installation only when independently observed; private audiences do not imply
anonymous access. Mirror change proposals must be reproduced in the owning source,
then evaluated/reviewed/released again.

Repair authored declarations by editing their owner; repair embedded toolchain/shims
using a new reviewed installed bundle:

```bash
python3 -I -S -B /abs/new/remek/scripts/cli.py --root /abs/source update --output /abs/private-plans/update.json
python3 -I -S -B /abs/new/remek/scripts/cli.py show /abs/private-plans/update.json
python3 -I -S -B /abs/new/remek/scripts/cli.py apply /abs/private-plans/update.json
```

The source's old shim only offers its own embedded version. Update maintains one
layout and never upgrades v1 in place.

## V1 rehearsal and rollback custody

Normal v2 commands reject `remek.1`. From a validated producer checkout, use the
source-only converter; it never loads old Python or touches global installations.
Inventory actual sources, installed copies, mirrors, incomplete workspaces, raw
reports, ignored/untracked work, and Git refs before any real cutover. Make a private
byte/mode-preserving worktree backup and separately verify a Git bundle of relevant
history. A Git archive alone is not an exact uncommitted/ignored-work backup.

The converter checks every owned byte it will transform against an independent
mode-0700 backup. Source, backup, and rehearsal are disjoint non-ancestor roots.
An existing mode-0700 rehearsal must match the inventoried v1 owned bytes. An absent
rehearsal receives owned paths, README and `.gitignore` only; use a verified complete
copy to retain foreign source work. Private plans and mapping files are outside all
protected roots, including an absent rehearsal's parent:

```bash
python3 tools/migrate_v1.py plan --source /abs/old-source --target /abs/rehearsals/source --archive /abs/verified-backup --output /abs/private-plans/migrate.json
python3 tools/migrate_v1.py show /abs/private-plans/migrate.json
python3 tools/migrate_v1.py apply /abs/private-plans/migrate.json
```

Ordinary skill bytes/modes remain exact. Tool-owned runtime changes are separately
listed. Old declarations become one skill record; retired skills become source-only
and leave selections. All distributions begin without active reviews. Old receipts
and approvals remain historical backup bytes, never current v2 evidence. Missing
original sources or configuration/trial details are explicit limitations. README and
foreign objects remain unchanged. Exact completed conversion is a no-op; partial or
unrelated v2 targets refuse. Source/archive/target/bundle drift refuses apply.

Accept the rehearsal only after independent byte/mode comparison, foreign-data
checks, v2 structural checks, truthful missing evidence/review, and confirmation that
the original v1 toolchain remains usable against preserved old state. Real source
replacement and host installation need separate explicit authorization. Keep original,
backup, history, and incomplete work until the owner selects a retention policy.

## Completion and failures

State structural validity, evidence/review readiness, audience/count, artifact versus
source/target/lineage verification, and next action. Machine results distinguish
`unchanged`, `applied`, `restored`, `residue`, and `unknown`. Exit 3 never means the
filesystem stayed unchanged. Preserve named residue; inspect before exact recovery.
No hypothetical cleanup or rerun may overwrite a foreign object to quiet a check.
