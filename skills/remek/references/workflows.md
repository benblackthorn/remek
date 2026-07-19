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

## Scratch and private artifacts

When needed, create one external mode-0700 run root under verified local POSIX
temporary storage with `umask 077`, outside pre-existing protected roots.
Separate plans, workspaces, inputs, raw reports, environments, and checkouts.

`<git-root>/.tmp/remek/<skill-or-project>/<run-id>/` is coordination-only. Use a
fresh absent mode-0700 leaf after proving canonical containment, nonsymlink
components, an untracked path, and `git check-ignore` success:

- Init generates `/.tmp/` if the target or its `.gitignore` is absent.
- An existing `.gitignore` stays byte-identical; if it lacks `/.tmp/`, offer an
  owner-approved edit and use the external root until that lands.
- Project mode follows those rules at its worktree root.
- Ungoverned Git uses repository scratch only when already ignored.
- A plain project or installed-only run uses only the external root. Initialization
  may create its governed source and generated ignore; scratch alone never does.

Never store artifacts in installed skill directories or common personal
folders. Keep persistent raw evidence in an owner-approved external store; owner
paths never override overlap refusals. Clean only this run after proving its
bytes were accepted or moved; report retained paths and sizes.

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

Inspect compatible native and installed capabilities, instructions, preferences,
and prior workflows. Use a known or sole choice silently; if several remain, ask
once, recommend native absent contrary evidence, and state only the material
difference. Never install, mix, or store choices in remek.

Finish one candidate, design, or reviewed import, then hand it to remek.
Authoring may design or run external evaluations; its output is not trusted
automatically. remek binds reviewed results to exact bytes. After acceptance,
continue requested Git or installation work through its owner.

Before handoff, inspect every shipped script and referenced resource. Identify
side effects, external commands, dependencies, and filesystem, network,
credential, and tool access; state runtime requirements in `compatibility`.
Treat `allowed-tools` as experimental host guidance, not cross-host
authorization, and cover dangerous or irreversible paths in behavior cases.

End with lifecycle, Git/install, evidence, release status, and next action;
`source-only` is exposure, not installation. Never infer publication from policy
or local preparation.

## Private source

```bash
python3 -I -S -B /abs/installed/remek/scripts/cli.py init /abs/source --output /abs/session/plans/init.json
python3 -I -S -B /abs/installed/remek/scripts/cli.py plan show /abs/session/plans/init.json
# Explain the exact paths and effects, then wait for owner approval.
python3 -I -S -B /abs/installed/remek/scripts/cli.py apply /abs/session/plans/init.json
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

GitHub CLI projections with consistently four-space scalar `metadata` parse;
imported scaffold strips only named installer tracking keys and renders the
remaining frontmatter canonically. Run `audit` on an owner-only working copy. On
`audit.profile-unsupported`, correct only its named tree or frontmatter
boundary; on `audit.open-invalid`, correct the named structural defect. Retain the
original path, mode, and SHA-256 manifest; keep resources byte-identical and make
only reviewed `SKILL.md` changes. Make the directory basename and frontmatter
`name` match, JSON-quote scalar strings, use supported top-level fields, and use
two-space scalar `metadata` children. `audit.metadata` names the exact installer
keys imported scaffold strips; other metadata is preserved. Repeat audit then
scaffold; on `scaffold.import`, fix only its named detail and restart from audit.
Never normalize the installed or upstream copy in place.

```bash
./remek scaffold --name NAME --origin captured --source /abs/session/inputs/work.md --workspace /abs/session/workspaces/NAME
./remek accept --workspace /abs/session/workspaces/NAME --output /abs/session/plans/accept.json
```

Revise with
`./remek scaffold --skill NAME --workspace /abs/session/workspaces/NAME-v2`.
Base
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
python3 -I -S -B "$remek_cli" audit /abs/session/inputs/verified-copy/NAME
python3 -I -S -B "$remek_cli" --root "$source_root" scaffold --name NAME --origin imported --source /abs/session/inputs/verified-copy/NAME --workspace /abs/session/workspaces/NAME-import
# Repeat audit and scaffold for every existing skill.
```

Review every normalized candidate and completed provenance. Only after all
workspaces are complete, move the colliding originals out so `skills/` is empty.
Then initialize with the installed entrypoint before any local accept cycle:

```bash
python3 -I -S -B "$remek_cli" init "$source_root" --output /abs/session/plans/init.json
python3 -I -S -B "$remek_cli" plan show /abs/session/plans/init.json
# Explain the exact paths and effects, then wait for owner approval.
python3 -I -S -B "$remek_cli" apply /abs/session/plans/init.json
"$source_root/remek" --root "$source_root" accept --workspace /abs/session/workspaces/NAME-import --output /abs/session/plans/NAME-accept.json
"$source_root/remek" --root "$source_root" plan show /abs/session/plans/NAME-accept.json
# Explain the exact paths and effects, then wait for owner approval.
"$source_root/remek" --root "$source_root" apply /abs/session/plans/NAME-accept.json
# Repeat the accept cycle for every completed workspace.
```

Consumer installation, if requested, is separate. `--project` intentionally
governs `.agents/skills/`; it is a different topology, not a migration repair.
Managed release requires the governed source and mirror to be Git worktree roots.
It checks the full Git object database under the fixed 30-second subprocess bound;
project mode therefore inherits the enclosing repository's object-database cost.
Use a dedicated governed source when a large monorepo cannot meet that boundary.

## Quality and distribution

`check` reports quality. Missing evidence is expected for a new
`draft`/`source-only` skill; candidate, case, profile, or catalog changes stale
evidence. Source and mirror repositories require committed `HEAD`s.

`/abs/session/inputs/distribution.json` and
`/abs/session/inputs/disclosure.json` have these exact shapes:

```json
{"schema":"remek.1","kind":"distribution","id":"DIST","audience":"private","skills":["NAME"],"target":{"provider":"github","hostname":"github.com","nameWithOwner":"OWNER/REPO","remote":"origin","branch":"main","expectedVisibility":"PRIVATE"},"delivery":["gh"],"evidencePolicy":{"routingProfiles":[{"kind":"manual-host","name":"HOST","version":"VERSION","claim":"regression","runConfigDigest":"CONFIG_SHA256","trialCount":3,"minimumPassCount":3}],"behaviorProfiles":[{"kind":"test-suite","name":"SUITE","version":"VERSION","claim":"regression","runConfigDigest":"CONFIG_SHA256","trialCount":1,"minimumPassCount":1}]},"privateDisclosure":"block"}
```

```json
{"schema":"remek.1","kind":"disclosure-policy","entries":[{"id":"review-note","class":"note","match":"literal","value":"Reviewed."}]}
```

```bash
./remek distribution accept --from /abs/session/inputs/distribution.json --output /abs/session/plans/distribution.json
./remek disclosure accept --from /abs/session/inputs/disclosure.json --output /abs/session/plans/disclosure.json
./remek --json eval plan NAME --kind behavior
./remek --json eval plan NAME --kind routing --distribution DIST
./remek eval record NAME --from /abs/session/inputs/behavior.json --output /abs/session/plans/behavior.json
./remek eval record NAME --from /abs/session/inputs/routing.json --output /abs/session/plans/routing.json
./remek --json approve plan DIST --skill NAME
./remek approve record DIST --skill NAME --from /abs/session/inputs/approval.json --output /abs/session/plans/approval.json
```

Before evaluation, hash a private config covering claim, baseline, hosts, models,
catalog, runner/runtime, isolation, permissions, runtime approval, retries,
budgets, logging, and graders. Use clean contexts and at least three trials per
host. A multi-host `external` profile preserves each host identity and result.
Freeze or digest material dynamic inputs in the private report, or state their
freshness limit; caching and reload remain host responsibilities. Before
recording, verify every report digest and cited identity against preserved
artifacts. Record aggregate passes and the private `evaluation-report` digest;
keep trials and traces outside the source and record failures. Profiles may name
different evaluators or hosts; remek runs none. GitHub is the only implemented
authenticated release target.

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
./remek release DIST --mirror /abs/session/mirror --output /abs/session/plans/release.json
./remek plan show /abs/session/plans/release.json
# Explain the exact paths and effects, then wait for owner approval.
./remek apply /abs/session/plans/release.json
git -c core.fsmonitor=false -C /abs/session/mirror add -A -- skills release-manifest.json
git --no-pager -c core.fsmonitor=false -C /abs/session/mirror diff --cached --no-ext-diff --no-textconv -- skills release-manifest.json
git -c core.fsmonitor=false -c core.hooksPath=/dev/null -C /abs/session/mirror commit --no-gpg-sign -m "Release DIST"
(cd /abs/session/mirror && gh skill publish --dry-run)
./remek release verify DIST --mirror /abs/session/mirror
git -C /abs/session/mirror push --no-verify --no-follow-tags --no-signed REMOTE 'HEAD:refs/heads/BRANCH'
```

The sample commit is deliberately unsigned. If organizational policy requires
signatures, replace that command with an externally governed signed commit before
`release verify`, or sign a tag pointing to the verified commit. remek holds no
keys and signatures replace neither evaluation evidence nor release approval.

Staging is not push-ready; commit, validation, push, tag, publish, and visibility
remain separate. A released mirror is a plain Git repository that an installer
or package manager may consume; remek is neither of those tools. Issues and pull
requests against a mirror are proposals: reproduce a reviewed change in the
owning private source, then re-prove, re-approve, and release it. An independently
owned organization instead uses reviewed import into its own governed source;
current import provenance does not claim to preserve release-derived lineage.

Checks are offline. `repair` plans only managed structure, preserves foreign
data, reports residue, and clears blockers. `audit` executes nothing and reports
structure, not intent, provenance, or safety. Credential findings expose only
code and path, never matched text. `doctor` reports the
source and trusted-toolchain diagnosis. `eval plan` and `approve
plan` print the precise recording command as their next action. `apply` reports
whether state was unchanged, changed, restored, or left with named residue;
exit 3 never means the mirror stayed unchanged. Release alone authenticates the
GitHub target.
