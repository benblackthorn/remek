# remek workflows

Use absolute paths; keep plans outside protected inputs. Put global `--root`
and `--json` before the command. For every `--output P`, show it, explain its
paths and effects, await approval, then apply with the same entrypoint:

```bash
# Installed
python3 -I -S -B /abs/installed/remek/scripts/cli.py plan show P
python3 -I -S -B /abs/installed/remek/scripts/cli.py apply P
# Source
./remek plan show P
./remek apply P
```

Later examples use reviewed source `./remek`.

## Whole-request workflow

Before first initialization, quietly inspect instructions, memory, project and
skill roots, Git, and read-only GitHub context. Reuse established setup.
Otherwise learn whether a skill repository exists and any skill may become
public. The three normal topologies are one private governed source for one
owner, a private governed source plus a distinct private team-consumer mirror,
and a private governed source plus a distinct public mirror for selected skills.
Same-owner machines normally clone or pull the governed source. A distribution
crosses into a different consumer repository or audience; it is not a source
synchronization mechanism.

Explain the split; confirm names and absolute paths. Creation, remotes, and
visibility need separate authorization. Reuse it unless project-local.

### Authoring handoff

Lifecycle: read-only discovery → authoring selection → completed
candidate/design/import → remek scaffold/accept → optional Git/install → summary.

Quietly inspect the active host and native capabilities; installed descriptions
covering Agent Skill creation, improvement, or evaluation; project, user, and
agent instructions and known preferences; repository conventions and prior
workflows; and compatibility with host tools. Match capability, not a name such
as `skill-creator`.

- Known compatible preference: use it. One compatible choice: use it silently.
- Native plus another credible installed choice, with no preference: ask once.
  Recommend native unless the task, repository history, or documented workflow
  justifies the alternative. State only the material difference, never a catalog.
- Exclude incompatible choices; mention them only if material. With none, use
  the normal workflow and continue.
- Remember via existing memory or instructions only, never remek. Never silently
  install an authoring skill or mix workflows.

Finish one candidate, design, or reviewed import, then hand it to remek.
Authoring may design or run external evaluations; its output is not trusted
automatically. remek binds reviewed results to exact bytes. After acceptance,
continue requested Git or installation work through its owner.

Before handoff, inspect every shipped script and referenced resource. Identify
side effects, external commands, dependencies, and filesystem, network,
credential, and tool access; state runtime requirements in `compatibility`.
Treat `allowed-tools` as experimental host guidance, not cross-host
authorization, and cover dangerous or irreversible paths in behavior cases.

Lead with the outcome, hide internal routing and routine findings, and show
exact plans and refusals. End with lifecycle/exposure, Git, consumer
installation/synchronization, evidence freshness, release readiness, and the
next action. `source-only` is exposure, not installation.

## Private source

```bash
python3 -I -S -B /abs/installed/remek/scripts/cli.py init /abs/source --output /tmp/init.json
python3 -I -S -B /abs/installed/remek/scripts/cli.py plan show /tmp/init.json
# Explain the exact paths and effects, then wait for owner approval.
python3 -I -S -B /abs/installed/remek/scripts/cli.py apply /tmp/init.json
cd /abs/source
./remek check
```

Choose `captured` work, a `designed` brief, or an `imported` reviewed skill.
For `captured`, first write the confirmed procedure to one file the user
reviews; remek retains that exact file, never the chat. Audit untrusted imports
read-only first, then review their intent, resources, and scripts: audit proves
structure, not safety. Runtime-only code or class definitions, live dynamic
resources, and MCP sources require a reviewed file snapshot; remek governs that
snapshot, not the live source. Complete candidate, provenance, policy, and both
case sets in the owner-only workspace; `accept` invents nothing.

```bash
./remek scaffold --name NAME --origin captured --source /abs/work.md --workspace /abs/work/NAME
./remek accept --workspace /abs/work/NAME --output /tmp/accept.json
```

Revise with `./remek scaffold --skill NAME --workspace /abs/work/NAME-v2`. Base
drift leaves source unchanged; scaffold again. Promote with a byte-identical
revision: edit the workspace policy's lifecycle or exposure with a fresh
stateReason, then accept; promotion is not release. `retire` keeps the governed
record; `remove` refuses while any distribution selects the skill.

For a source remek already governs, use the shorter `./remek` import above. A
first-time in-place migration must use the installed entrypoint because no local
wrapper exists and `init` never claims populated `skills/`. First create a
recoverable Git checkpoint. Copy every ungoverned skill to an external
owner-only directory and verify a path, mode, and SHA-256 manifest against each
original. Before moving any original, audit every verified copy and scaffold it
into a separate completed `imported` workspace:

```bash
remek_cli=/abs/installed/remek/scripts/cli.py
source_root=/abs/existing-source
python3 -I -S -B "$remek_cli" audit /abs/verified-copy/NAME
python3 -I -S -B "$remek_cli" --root "$source_root" scaffold --name NAME --origin imported --source /abs/verified-copy/NAME --workspace /abs/work/NAME-import
# Repeat audit and scaffold for every existing skill.
```

Review every normalized candidate and completed provenance. Only after all
workspaces are complete, move the colliding originals out so `skills/` is empty.
Then initialize with the installed entrypoint before any local accept cycle:

```bash
python3 -I -S -B "$remek_cli" init "$source_root" --output /abs/review/init.json
python3 -I -S -B "$remek_cli" plan show /abs/review/init.json
# Explain the exact paths and effects, then wait for owner approval.
python3 -I -S -B "$remek_cli" apply /abs/review/init.json
"$source_root/remek" --root "$source_root" accept --workspace /abs/work/NAME-import --output /abs/review/NAME-accept.json
"$source_root/remek" --root "$source_root" plan show /abs/review/NAME-accept.json
# Explain the exact paths and effects, then wait for owner approval.
"$source_root/remek" --root "$source_root" apply /abs/review/NAME-accept.json
# Repeat the accept cycle for every completed workspace.
```

Consumer installation, if requested, is separate. `--project` intentionally
governs `.agents/skills/`; it is a different topology, not a migration repair.

## Quality and distribution

`check` reports quality. Missing evidence is expected for a new
`draft`/`source-only` skill; candidate, case, profile, or catalog changes stale
evidence. Source and mirror repositories require committed `HEAD`s.

`/abs/distribution.json` and `/abs/disclosure.json` have these exact shapes:

```json
{"schema":"remek.1","kind":"distribution","id":"DIST","audience":"private","skills":["NAME"],"target":{"provider":"github","hostname":"github.com","nameWithOwner":"OWNER/REPO","remote":"origin","branch":"main","expectedVisibility":"PRIVATE"},"delivery":["gh"],"evidencePolicy":{"routingProfiles":[{"kind":"manual-host","name":"HOST","version":"VERSION","claim":"regression","runConfigDigest":"CONFIG_SHA256","trialCount":3,"minimumPassCount":3}],"behaviorProfiles":[{"kind":"test-suite","name":"SUITE","version":"VERSION","claim":"regression","runConfigDigest":"CONFIG_SHA256","trialCount":1,"minimumPassCount":1}]},"privateDisclosure":"block"}
```

```json
{"schema":"remek.1","kind":"disclosure-policy","entries":[{"id":"review-note","class":"note","match":"literal","value":"Reviewed."}]}
```

```bash
./remek distribution accept --from /abs/distribution.json --output /tmp/distribution.json
./remek disclosure accept --from /abs/disclosure.json --output /tmp/disclosure.json
./remek --json eval plan NAME --kind behavior
./remek --json eval plan NAME --kind routing --distribution DIST
./remek eval record NAME --from /abs/behavior.json --output /tmp/b.json
./remek eval record NAME --from /abs/routing.json --output /tmp/r.json
./remek --json approve plan DIST --skill NAME
./remek approve record DIST --skill NAME --from /abs/approval.json --output /tmp/a.json
```

Before evaluation, hash a private config covering the claim, baseline, hosts,
models, catalog, script runner and runtime, isolation, filesystem, network,
credential and tool permissions, runtime approval, retries, resource, time,
turn, token and cost budgets, logging, and graders. Use clean contexts and at
least three trials per host. A multi-host `external` profile must preserve each
host's identity and results. Freeze or digest material dynamic inputs in the
private report, or state their freshness limit; host caching and reload remain
host responsibilities. Record aggregate passes and the private
`evaluation-report` digest; keep trials and traces outside the source. Record
failures. Routing and behavior profiles may name different evaluators or hosts;
remek runs none. GitHub is the only implemented authenticated release target.

Evidence and release approval are independent gates. Approval binds candidate,
provenance, distribution, exceptions, a reviewer declaration, and date; it does
not attest a particular receipt, authenticate the reviewer, prove separation of
duties, or grant runtime, tool, or script permission. External controls own
authentication and the active host owns runtime authorization. Public also
requires a nonempty candidate frontmatter `license` exactly matching reviewed
provenance, `public-eligible`, fresh history and proof, blocked private
disclosure, `audience:"public"`, and `expectedVisibility:"PUBLIC"`. Mirrors omit
governance and retained sources.

| Intent | Owner |
| --- | --- |
| Move governed source | Git |
| Update installed remek | Installer |
| Replace embedded toolchain | `remek update` |
| Update consumer copies | Installer or consumer tooling |

Run `update` through the new installed entrypoint with `--root /abs/source`;
the old source shim offers only its embedded toolchain.

## Release

```bash
./remek check --release DIST
./remek release DIST --mirror /abs/mirror --output /tmp/release.json
./remek plan show /tmp/release.json
# Explain the exact paths and effects, then wait for owner approval.
./remek apply /tmp/release.json
git -c core.fsmonitor=false -C /abs/mirror add -A -- skills release-manifest.json
git --no-pager -c core.fsmonitor=false -C /abs/mirror diff --cached --no-ext-diff --no-textconv -- skills release-manifest.json
git -c core.fsmonitor=false -c core.hooksPath=/dev/null -C /abs/mirror commit --no-gpg-sign -m "Release DIST"
(cd /abs/mirror && gh skill publish --dry-run)
./remek release verify DIST --mirror /abs/mirror
git -C /abs/mirror push --no-verify --no-follow-tags --no-signed REMOTE 'HEAD:refs/heads/BRANCH'
```

Staging is not push-ready; commit, validation, push, tag, publish, and visibility
remain separate. A released mirror is a plain Git repository that an installer
or package manager may consume; remek is neither of those tools. Issues and pull
requests against a mirror are proposals: reproduce a reviewed change in the
owning private source, then re-prove, re-approve, and release it. An independently
owned organization instead uses reviewed import into its own governed source;
current import provenance does not claim to preserve release-derived lineage.

`check` and `check --release` are offline. `repair` must clear every blocker.
`audit` reports structural compatibility, not benign intent, trustworthy
provenance, or execution safety; it executes no candidate content. `doctor`
reports the source and trusted-toolchain diagnosis. `eval plan` and `approve
plan` print the precise recording command as their next action. `apply` reports
whether state was unchanged, changed, restored, or left with named residue;
exit 3 never means the mirror stayed unchanged. Release alone authenticates the
GitHub target.
