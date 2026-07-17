# remek workflows

Use absolute paths; keep plans outside protected inputs. Put global `--root`
and `--json` before the command. For every `--output P`, show it, explain it,
await approval, then apply with the same entrypoint:

```bash
# Installed
python3 -I -S -B scripts/cli.py plan show P
python3 -I -S -B scripts/cli.py apply P
# Source
./remek plan show P
./remek apply P
```

Later examples use reviewed source `./remek`.

## Whole-request workflow

Before first initialization, quietly inspect instructions, memory, project and
skill roots, Git, and read-only GitHub context. Reuse established setup.
Otherwise learn whether a skill repository exists and any skill may become
public, then recommend:

- internal-only: private `agent-skills` under the established project root;
- selective release: private `skills-home` plus a separate `agent-skills`
  release repository, public only when authorized.

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

Lead with the outcome, hide internal routing and routine findings, and show
exact plans and refusals. End with lifecycle/exposure, Git, consumer
installation/synchronization, evidence freshness, release readiness, and the
next action. `source-only` is exposure, not installation.

## Private source

```bash
python3 -I -S -B scripts/cli.py init /abs/source --output /tmp/init.json
cd /abs/source
```

Choose `captured` work, a `designed` brief, or an `imported` reviewed skill.
Complete candidate, provenance, policy, and both case sets in the owner-only
workspace; `accept` invents nothing.

```bash
./remek scaffold --name NAME --origin captured --source /abs/work.md --workspace /abs/work/NAME
./remek accept --workspace /abs/work/NAME --output /tmp/accept.json
```

Revise with `./remek scaffold --skill NAME --workspace /abs/work/NAME-v2`. Base
drift leaves source unchanged; scaffold again.

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
models, catalog, tools, permissions, retries, budgets, and graders. Use clean
contexts and at least three trials per host. A multi-host `external` profile
must preserve each host's identity and results. Record aggregate passes and the
private `evaluation-report` digest; keep trials and traces outside the source.
Record failures. remek runs no evaluator.

Approval binds candidate, provenance, distribution, exceptions, reviewer, and
date—not access. Public requires `public-eligible`, fresh history and proof,
blocked private disclosure, approval, `audience:"public"`, and
`expectedVisibility:"PUBLIC"`. Mirrors omit governance and sources.

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
git -c core.fsmonitor=false -C /abs/mirror add -A -- skills release-manifest.json
git --no-pager -c core.fsmonitor=false -C /abs/mirror diff --cached --no-ext-diff --no-textconv -- skills release-manifest.json
git -c core.fsmonitor=false -c core.hooksPath=/dev/null -C /abs/mirror commit --no-gpg-sign -m "Release DIST"
(cd /abs/mirror && gh skill publish --dry-run)
./remek release verify DIST --mirror /abs/mirror
git -C /abs/mirror push --no-verify --no-follow-tags --no-signed REMOTE 'HEAD:refs/heads/BRANCH'
```

Staging is not push-ready; commit, validation, push, tag, publish, and visibility
remain separate.

`check` and `check --release` are offline. `repair` must clear every blocker.
`audit` executes no candidate content; `doctor` reports state. Release alone
authenticates the GitHub target.
