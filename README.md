# remek

**Your skills are an asset. Govern them like one.**

remek is the local-first governed source and release layer for reviewed,
file-based [Agent Skills](https://agentskills.io/). It sits between authoring
and publishing.

- Agent Skills defines the portable skill artifact.
- remek governs which exact bytes are ready for which audience and target.
- Agents author and evaluate, Git transports, and installers place copies.

## Why remek exists

An owner or team shipping skills eventually needs answers that a repository,
installer, or one-time scan cannot provide alone:

- What exact skill bytes are under review?
- What changed since the last accepted version?
- Which evaluation results apply to this candidate, and are they still current?
- Who declared approval for this release context?
- Is the release intended for a private audience or the public?
- Does the committed release mirror still match the approved projection?

If Agent Skills answers **“what is a skill?”**, remek answers **“which exact
skill release is ready for this audience, and why?”**

Use remek when mistakes are costly: a private skill library, shared team
workflows, client work under NDA, high-stakes procedures, or selected private
and public releases. Cost matters more than contributor count. If you only want
to install an unrelated third-party skill, use an installer directly.

## How remek works

1. **Exact-byte identity.** A candidate is a canonical UTF-8 file tree. Its
   digest identifies the bytes under review; digests are identities, not
   signatures.
2. **Explicit provenance and policy.** Retained source, upstream identity,
   rights, lifecycle, exposure, and case sets remain in the governed source.
3. **Evidence bound to its subject.** Evidence records the candidate, cases,
   routing catalog, evaluator profile, trials, run-configuration digest, results,
   and one private report digest. Relevant changes make it stale.
4. **Approval separate from evidence.** Observations inform a release decision;
   they do not make it. Approval binds a reviewer declaration to the exact
   candidate, provenance, distribution, target, exceptions, and date.
5. **One authoritative source.** Consumer mirrors receive an approved one-way
   projection. They never become a second governed source.

```text
authoring — your agent's own workflow
      │  completed bytes, a design, or a reviewed import
      ▼
governed source — candidate, provenance, policy, cases, evidence, approval
      │  exact reviewed plan
      ▼
release mirror — approved skills/ + manifest, no private governance records
      │  separate Git push, publication, and installation
      ▼
consumer copies — owned by installers, not remek
```

Feedback returns as an issue or patch proposal. Reproduce accepted changes in
the governed source, then prove, approve, and release them again.

## Review every durable change before it lands

Only `scaffold` mutates directly, creating an owner-only disposable workspace
outside Git. Every durable source or mirror mutation follows:

```text
prepare → save plan → inspect exact diff → explain paths and effects
→ owner approval → apply → check
```

`apply` reconstructs intent from current inputs and requires an exact match. A
changed bound input refuses instead of landing. This refusal transcript is
literal CLI output and is checked byte-for-byte by the repository suite:

```console
$ ./remek apply …/accept.json
apply: plan differs at plan.bindings.candidate; nothing applied; recreate and review
  ERROR plan.stale: plan differs at plan.bindings.candidate; nothing applied; recreate and review
```

Transactions restore cooperative local failures when possible and report
whether state stayed unchanged, changed, was restored, or has named residue.
There is no journal or guarantee for process death, power loss, hostile writers,
or network storage.

## Install

Install remek as a user-scoped Agent Skill. GitHub CLI 2.90+ will ask which
agent should receive it:

```bash
gh skill install benblackthorn/remek remek --scope user
```

Alternatively, run `npx skills add benblackthorn/remek -g`. Non-interactive
`gh` callers should detect the active host and pass `--agent <host>` because the
default is `github-copilot`. Use `gh` by default for private distributions;
`npx skills` does not provide a complete private-repository contract.

This installs a skill for your coding agent, not a shell command. Ask the agent
to use remek. The installer owns that copy; update it with
`gh skill update remek`, or `npx skills update remek` if npx installed it.
remek has no telemetry. [GitHub CLI](https://cli.github.com/telemetry) and
[`npx skills`](https://github.com/vercel-labs/skills/blob/main/README.md#telemetry)
document theirs.

## Start a private governed source

For one owner, one private governed source is normally enough. Same-owner
machines clone or pull it. Use a distinct private consumer mirror for a team
audience, and a distinct public mirror with separate history for selected
public skills.

Start by asking your agent:

> Set up my governed skills source with remek. Discover my existing conventions
> and repositories first. If no setup exists, ask whether any skills may become
> public, then confirm the repository name and absolute path before creating it.

Your agent resolves the installed entrypoint. The manual sequence below keeps
the review plan outside the source being initialized:

```bash
remek_cli=/absolute/path/to/installed/remek/scripts/cli.py

python3 -I -S -B "$remek_cli" init /absolute/path/to/skills-home --output /absolute/path/to/review/init.json
python3 -I -S -B "$remek_cli" plan show /absolute/path/to/review/init.json
# Explain every path and effect, then wait for owner approval.
python3 -I -S -B "$remek_cli" apply /absolute/path/to/review/init.json
cd /absolute/path/to/skills-home
./remek check
```

`init` adds governance, a pinned toolchain, and a repository-local `./remek`
wrapper. It does not create Git history or a GitHub repository. Foreign files
are preserved, and a populated `skills/` makes `init` refuse rather than claim
existing work silently. `init --project` intentionally governs only
`.agents/skills/` in one project.

For a private library, `install → initialize → capture or import → check` is a
complete outcome. Git history and a private remote are separate, explicitly
authorized steps. Evidence and approval are not required until you prepare a
distribution.

## Capture, design, import, or revise a skill

remek governs completed work; it does not write the procedure. Your authoring
workflow hands it one of three inputs:

| Origin | Input |
| --- | --- |
| `captured` | Completed owned work that should become a skill |
| `designed` | A reviewed design brief an agent completes into a skill |
| `imported` | An existing reviewed skill directory |

After completing real work, “Capture this as a skill with remek” is enough. Your
agent writes the confirmed procedure to one reviewed file, then uses it as the
retained source:

```bash
./remek scaffold \
  --name deploy-safely \
  --origin captured \
  --source /absolute/path/to/completed-procedure.md \
  --workspace /absolute/path/outside-git/deploy-safely
# Your agent completes the candidate, provenance, policy, and both case sets.
./remek accept --workspace /absolute/path/outside-git/deploy-safely --output /absolute/path/to/review/accept.json
./remek plan show /absolute/path/to/review/accept.json
# Explain every path and effect, then wait for owner approval.
./remek apply /absolute/path/to/review/accept.json
./remek check
```

The agent completes the candidate, provenance, policy, and both case sets in the
workspace. `accept` validates those complete reviewed bytes and invents nothing.
New skills enter as `draft` and `source-only`; promotion is a separate reviewed
change. Revise with:

```bash
./remek scaffold --skill deploy-safely --workspace /absolute/path/outside-git/deploy-safely-v2
```

If the governed base changes after scaffolding, `accept` refuses; scaffold
again. Candidate changes return the skill to `draft`, cannot raise exposure in
the same step, and make existing evidence and approval stale.

For an existing skill, start with:

```bash
./remek audit /absolute/path/to/existing-skill
./remek scaffold \
  --name existing-skill \
  --origin imported \
  --source /absolute/path/to/existing-skill \
  --workspace /absolute/path/outside-git/existing-skill-import
```

Then complete the workspace and use the same accept cycle. `audit` reads an
untrusted payload without executing it and checks structural compatibility, not
intent, script safety, upstream trust, or host safety. The directory basename
and `SKILL.md` name must match `--name`. First-time in-place migration requires
a byte-verified external copy and per-skill review because `init` never claims a
populated `skills/`. Follow the
[private-source workflow](skills/remek/references/workflows.md#private-source)
for the complete sequence.

## Evidence and approval

Models, credentials, hosts, budgets, graders, and raw output stay outside remek.
An agent, test suite, or harness runs the trials. `eval plan` describes what to
test; `eval record` stores bounded results and a digest of the private report.
Failed receipts persist. Release evidence forbids `smoke` claims, and manual-host
or external profiles require at least three trials per case.

Evidence covers the exact governed bytes and recorded run configuration. It
does not prove evaluator honesty or freeze live APIs, databases, MCP sources,
dynamic resources, or host caches. Material dynamic inputs belong in the
private report by digest or with a stated freshness limit.

Approval is an independent gate. Its `reviewer` field is a declaration, not
authentication, separation-of-duties proof, or attestation of a particular
receipt. Approval grants no runtime, tool, or script permission; the active host
owns those controls.

Sharing starts with a byte-identical revision that changes policy to `ready`
and `private-only` or `public-eligible`, with a fresh reason, followed by the
same accept cycle. The
[quality-and-distribution workflow](skills/remek/references/workflows.md#quality-and-distribution)
owns distribution, evidence-recording, and approval details.

## Release

```text
author or import → accept → evaluate externally → record evidence
→ approve → stage and verify release → publish separately through Git/GitHub
```

A distribution names an audience, skill allowlist, GitHub target, delivery
methods, and evidence policy. Once every readiness, disclosure, Git, and target
gate passes—including current evidence and approval—remek prepares a managed
mirror projection. The
[release workflow](skills/remek/references/workflows.md#release) owns the exact
Git and push boundaries; the complete pre-push sequence is:

```bash
./remek check --release team
./remek release team --mirror /absolute/path/to/mirror --output /absolute/path/to/review/release.json
./remek plan show /absolute/path/to/review/release.json
# Explain every path and effect, then wait for owner approval.
./remek apply /absolute/path/to/review/release.json
git -c core.fsmonitor=false -C /absolute/path/to/mirror add -A -- skills release-manifest.json
git --no-pager -c core.fsmonitor=false -C /absolute/path/to/mirror diff --cached --no-ext-diff --no-textconv -- skills release-manifest.json
git -c core.fsmonitor=false -c core.hooksPath=/dev/null -C /absolute/path/to/mirror commit --no-gpg-sign -m "Release team"
(cd /absolute/path/to/mirror && gh skill publish --dry-run)
./remek release verify team --mirror /absolute/path/to/mirror
```

remek never commits or pushes. A push happens only after verification and needs
separate authorization. Staging-only output is unverified and never push-ready.

The mirror receives only approved `skills/` and `release-manifest.json`. The
manifest binds paths, modes, hashes, lineage, target, and private context as
digests. Source-side `release verify` rechecks the clean committed mirror,
governed source, manifest-bound remote, branch, and authenticated GitHub target.
The repository's [standalone manifest verifier](tools/verify_release_manifest.py)
can validate mirror payload integrity without the private source, but it cannot
reconstruct private evidence or approval.

Public release additionally requires separate history, blocked private
disclosure, `public-eligible` policy, an approval acknowledging irreversibility,
public target visibility, and a nonempty candidate `license` exactly matching
reviewed provenance. Credential findings cannot be excepted.

## CLI reference

Run `./remek --help` or `./remek COMMAND --help` for exact arguments. Put global
`--root` and `--json` before the command.

| Command | Outcome |
| --- | --- |
| `init` | Initialize or wire a governed source and pinned wrapper. |
| `scaffold` | Create a disposable workspace for captured, designed, imported, or revised work. |
| `accept` | Validate a complete workspace and save an exact acceptance plan. |
| `distribution` / `disclosure` | Govern release targets, audiences, delivery, evidence policy, and private-material rules. |
| `retire` / `remove` | Retire work with history or remove an eligible unselected skill. |
| `check` | Run deterministic offline repository, skill, and release-readiness contracts. |
| `repair` | Plan bounded mechanical corrections without rewriting authored intent. |
| `update` | Replace the embedded toolchain from one reviewed installed remek bundle. |
| `eval` | Prepare or record evidence produced by external evaluators; remek runs none. |
| `approve` | Prepare or record reviewer approval for an exact release context. |
| `release` / `release verify` | Plan a managed mirror or staging-only projection; only a committed managed mirror can pass verification. |
| `plan show` | Reconstruct and display an exact bounded change before mutation. |
| `audit` | Inspect an untrusted skill payload read-only without executing it. |
| `doctor` | Diagnose the governed source and trusted toolchain. |
| `apply` | Apply one unchanged reviewed plan; refuse drift or replay. |

## What remek does not do

remek is not an authoring environment, hosted catalog, installer, package
manager, general-purpose scanner, model or benchmark runner, runtime permission
engine, skill host, secret manager, signing service, CI/CD platform, or
autonomous improvement loop. It never creates repositories, runs candidate
scripts, installs consumer copies, commits, pushes, tags, publishes, or changes
repository visibility.

Source-only exposure is governance state, not installation state. Runtime-only
code, live dynamic resources, and remote MCP sources enter governance only when
their relevant content is materialized as a reviewed file snapshot. remek
governs that snapshot, not the live source or cache.

## Security and supported environment

Repository inputs are hostile after a trusted remek bundle and caller-selected
Python interpreter load. remek rejects unsafe filesystem objects, unbounded
input, hostile executables and Git features, and stale plans. It detects stale
evidence and mirror drift; release refuses them. Candidate content never
executes. The [threat model](docs/threat-model.md) states the exact trusted inputs
and honest limitations.

Supported execution is Python 3.11+ on macOS or native Linux with verified
POSIX local storage. The runtime uses only the standard library. Normal
workflows are offline; release alone authenticates the GitHub target. Local
bounded Git queries are used where required. Git is required for scaffold,
staging, and release, and GitHub CLI for verified targets. Payloads are bounded
UTF-8 text. Binary assets, links, special files, Windows, WSL, and network
filesystems are unsupported.

## Documentation and contributing

- [remek.dev](https://remek.dev/): short tour and quick start
- [Workflow reference](skills/remek/references/workflows.md): executable sequences and record shapes
- [Design](docs/design.md): outcomes, ownership, and architecture
- [Contracts](docs/contracts.md): canonical formats, limits, and refusal semantics
- [Threat model](docs/threat-model.md): trusted inputs, hostile bytes, and unsupported guarantees
- [Contributing](.github/CONTRIBUTING.md) and [security policy](.github/SECURITY.md)

## Skills

<!-- remek-skills:start -->
| Skill | Description |
| --- | --- |
| `remek` | Use when a request names remek or asks to initialize a governed Agent Skills source; capture, import, or revise governed skills; record reviewed external evidence or distribution approval; audit an untrusted skill; or prepare and verify a release mirror you own. remek governs completed skill bytes and reviewed results; authoring, evaluation runs, Git, installation, and publishing use compatible capabilities. |
<!-- remek-skills:end -->

remek — [ˈrɛmɛk], Hungarian for excellent — is [MIT licensed](LICENSE) and
maintained best-effort, with no response-time commitment.
