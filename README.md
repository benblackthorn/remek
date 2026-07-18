# remek

**Your skills are an asset. Govern them like one.**

remek is the governed source and release layer for reviewed, file-based
[Agent Skills](https://agentskills.io/) represented as canonical UTF-8 file
trees. Git records history and installers place copies; remek replaces neither.
It connects the governance questions those tools leave separate: which exact
bytes were reviewed, what evidence still applies, who approved which release,
and whether a committed release mirror still matches those local decisions
before a separate push or publication.

```text
authoring — your agent's own workflow
      │  completed bytes, a design, or a reviewed import
      ▼
governed source — candidate identity, provenance, policy, cases,
      │           evidence, approvals, exact mutation plans
      │  approved one-way projection
      ▼
release mirror — approved skills/ + manifest, no private governance records
      │  gh skill / npx skills
      ▼
installed copies — placed and updated by installers, not remek
```

Feedback flows the other way — as an issue or patch into the governed
source — never as a silent copy of mirror edits.

Use remek when mistakes are costly: private skill libraries, shared team
workflows, client deliverables under NDA, high-stakes procedures, and selected
private or public releases. Cost matters more than contributor count. To install
an unrelated third-party skill without governing it, use an installer directly.

## What it protects

| Problem | remek's answer |
| --- | --- |
| An agent changes more than you reviewed | Durable mutations use an exact plan; changed inputs make `apply` refuse before landing them. |
| Results outlive the skill they tested | Evidence binds bytes, cases, evaluator profile, trials, and a private report digest; relevant changes make it stale. |
| Unapproved private material enters a public release | Separate histories, disclosure policy, and the manifest bind what crosses; credential findings cannot be excepted. |
| A mirror becomes a second source of truth | Mirrors receive a one-way projection; edits fail verification and must return as patch proposals. |
| Source, installations, and releases blur together | Governance, installation, Git transport, and release state remain independent. |

Digests are SHA-256 identities, not signatures. Proof, approval, and release
bind to exact bytes; relevant drift makes proof stale or causes plan and release
gates to refuse. remek does not provide package-manager or lockfile semantics.

## Every change is a reviewed plan

Only `scaffold` mutates directly, creating an owner-only disposable workspace
outside Git. Everything durable follows
`prepare → save plan → inspect exact diff → explain paths and effects → owner
approval → apply → check`:

The commands below are schematic: paths are shortened, and this is not a
transcript.

```bash
./remek scaffold --name deploy-safely --origin captured --source /absolute/path/to/completed-procedure.md --workspace /absolute/path/outside-git/deploy-safely
# Your agent completes candidate, provenance, policy, and both case sets.
./remek accept --workspace … --output …/accept.json
./remek plan show …/accept.json
# Your agent explains every path and effect, then waits for your approval.
```

Only after that approval, `apply` reconstructs the plan from current inputs and
requires an exact match. A byte that changed after your review — here, the
candidate — refuses instead of landing. This refusal transcript is literal CLI
output and is checked byte-for-byte in the repository suite:

```console
$ ./remek apply …/accept.json
apply: plan differs at plan.bindings.candidate; nothing applied; recreate and review
  ERROR plan.stale: plan differs at plan.bindings.candidate; nothing applied; recreate and review
```

## Install

Install remek as a user-scoped Agent Skill and let `gh skill` (GitHub CLI
2.90+) ask which agent should receive it:

```bash
gh skill install benblackthorn/remek remek --scope user
```

An alternative is `npx skills add benblackthorn/remek -g`.

That `gh` command prompts a person for the target agent. Non-interactive
callers must detect the active host and pass its explicit
`--agent <host>`; otherwise `gh` defaults to `github-copilot`.

remek has no telemetry. [GitHub CLI](https://cli.github.com/telemetry) and
[`npx skills`](https://github.com/vercel-labs/skills/blob/main/README.md#telemetry)
document theirs and their opt-outs. Use `gh` by default for private distributions;
`npx skills` does not provide a complete private-repository contract.

This installs an Agent Skill, not a shell command: ask your coding agent to
use it. The installed copy stays installer-owned; update it with
`gh skill update remek`, or `npx skills update remek` if npx installed it.

## Set up a governed source

Start with:

> Set up my governed skills source with remek. Discover my existing
> conventions and repositories first. If no setup exists, ask whether any
> skills may become public, then confirm the repository name and absolute path
> before creating it.

For one owner, a single private governed source is enough, and same-owner
machines normally clone or pull it. A private team audience uses a distinct
private consumer mirror. Selected public skills use a distinct public mirror,
so private governance never enters public history. Distributions cross into a
different consumer repository or audience; they do not synchronize one owner's
source. For skills that belong to one project, `init --project` governs
`.agents/skills/` and leaves everything else foreign.

The exact sequence, if you would rather not delegate it:

```bash
remek_cli=/absolute/path/to/installed/remek/scripts/cli.py

python3 -I -S -B "$remek_cli" init /absolute/path/to/skills-home --output /absolute/path/to/review/init.json
python3 -I -S -B "$remek_cli" plan show /absolute/path/to/review/init.json
# Explain every path and effect, then wait for owner approval.
python3 -I -S -B "$remek_cli" apply /absolute/path/to/review/init.json
cd /absolute/path/to/skills-home
./remek check
```

`init` places a pinned toolchain and repository-local `./remek` wrapper. It
creates governance, not Git history or a GitHub repository; those are separate
steps. Foreign files are preserved, and a populated `skills/` makes `init`
refuse rather than claim them silently.

## Create or revise a skill

remek governs completed work; it does not author the procedure. Your agent uses
its own or your preferred authoring workflow, then hands remek one of:

| Origin | Input |
| --- | --- |
| `captured` | Completed owned work that should become a skill |
| `designed` | A reviewed design brief the agent completes into a skill |
| `imported` | An existing reviewed skill directory |

After finishing a piece of real work, capture is one sentence:

> Capture this as a skill with remek.

Your agent writes the confirmed procedure to one reviewed file. remek retains
that file as provenance—not the chat or neighboring files:

```bash
./remek scaffold \
  --name deploy-safely \
  --origin captured \
  --source /absolute/path/to/completed-procedure.md \
  --workspace /absolute/path/outside-git/deploy-safely
```

The agent completes the candidate, provenance, policy, and both case sets in
the workspace; the plan cycle lands them:

```bash
./remek accept --workspace /absolute/path/outside-git/deploy-safely --output /absolute/path/to/review/accept.json
./remek plan show /absolute/path/to/review/accept.json
# Explain every path and effect, then wait for owner approval.
./remek apply /absolute/path/to/review/accept.json
./remek check
```

`accept` validates a complete workspace and invents nothing. New skills enter
with lifecycle `draft` and exposure `source-only` — release eligibility, not
installation state — and promotion is a separate reviewed change. Revise with:

```bash
./remek scaffold --skill deploy-safely --workspace /absolute/path/outside-git/deploy-safely-v2
```

If the governed base changes after scaffolding, `accept` refuses the stale
workspace; scaffold again. A candidate change returns the skill to `draft`,
cannot raise exposure in the same step, and stales its evidence and approval.

## Bring an existing skill under governance

Imports are per-skill and reviewed; there is no bulk or silent migration.

```bash
./remek audit /absolute/path/to/existing-skill
./remek scaffold \
  --name existing-skill \
  --origin imported \
  --source /absolute/path/to/existing-skill \
  --workspace /absolute/path/outside-git/existing-skill-import
```

`audit` inspects any untrusted payload read-only, without executing it. It
checks structure, not intent, script safety, upstream trust, or host execution
safety. The imported directory basename and its `SKILL.md` frontmatter `name`
must both match `--name`; remek copies the payload and strips
installer-injected metadata.
Complete the provenance — upstream identity, rights, license — in the
workspace, then run the same accept cycle. If an ungoverned skill already
occupies the destination, remek refuses to overwrite it.

For a source remek already governs, use the shorter `./remek` import above.
A first-time in-place migration must instead use the installed entrypoint:
checkpoint Git; copy and byte-verify every existing skill in an owner-only
external directory; audit, scaffold, and review every copy before moving any
original; empty the colliding `skills/`; then initialize and accept the
completed workspaces. The [workflow reference](skills/remek/references/workflows.md#private-source)
owns the exact executable sequence. `init` never claims a populated
`skills/` directory.

An independently owned organization uses this reviewed-import path into its own
source; current provenance does not claim to retain release-derived lineage.

## Evidence

Models, credentials, hosts, budgets, and graders remain outside remek. An agent,
test suite, or harness runs the trials; `eval plan` identifies what to test and
`eval record` binds the candidate, cases, routing catalog, evaluator profile,
hashed private run configuration, per-case results, and one report digest. Raw
prompts, transcripts, and provider output stay outside. Failed receipts persist.
Release evidence forbids `smoke` claims and requires at least three trials per
case for manual-host and external profiles. Evidence covers the exact governed
bytes under the hashed run configuration; it does not freeze live APIs,
databases, MCP sources, dynamic resources, or host caches.
Routing and behavior profiles can describe different evaluators; GitHub remains
the only implemented authenticated release target.

## Release

```text
author or import → accept → evaluate externally → record evidence
→ approve → stage and verify release → publish through Git/GitHub
```

A distribution declares an audience, an allowlist of skills, a GitHub target,
delivery, and evidence policy. Evidence and approval are independent gates.
Approval records a reviewer declaration bound to the exact candidate,
provenance, and release context; remek does not authenticate that reviewer,
prove separation of duties, or treat approval as attestation of exact receipts.
It grants no runtime, tool, or script permission; the active agent host enforces
those separately. Release then projects the payload into a managed mirror; Git
commits it, and verification rechecks the committed result before you push:

```bash
./remek check --release team
./remek release team --mirror /absolute/path/to/mirror --output /absolute/path/to/review/release.json
./remek plan show /absolute/path/to/review/release.json
# Explain every path and effect, then wait for owner approval.
./remek apply /absolute/path/to/review/release.json
# Inspect and commit only skills/ and release-manifest.json in the mirror.
(cd /absolute/path/to/mirror && gh skill publish --dry-run)
./remek release verify team --mirror /absolute/path/to/mirror
```

The exact bounded Git commands between apply and verification are in the
[workflow reference](skills/remek/references/workflows.md).

The mirror receives only approved `skills/` and `release-manifest.json`, which
binds paths, modes, hashes, and private context as digests. Release requires
current evidence and approval, clean committed Git, the expected branch, a
credential-free remote, and an authenticated target with matching visibility.
Audience is bound to mirror history: public release needs a separate history,
blocked private disclosure, approval acknowledging irreversibility, and a
nonempty candidate frontmatter `license` exactly matching reviewed provenance.

Issues against a released mirror are welcome. A pull request editing a
mirror's `skills/` is a patch proposal: reproduce it in a governed revision,
re-prove, re-approve, and release with attribution. Merging it directly leaves
the mirror outside the approved release transaction, so verification refuses.
A mirror is a plain Git repository an installer or package manager can consume;
remek is neither.

## CLI map

Run `./remek --help` or `./remek COMMAND --help` for exact arguments. Global
`--root` and `--json` options go before the command.

| Command | Outcome |
| --- | --- |
| `init` | Initialize or wire a governed source and its pinned local wrapper. |
| `scaffold` | Create a disposable workspace for captured, designed, imported, or revised work. |
| `accept` | Validate a complete workspace and save an exact acceptance plan. |
| `plan show` | Reconstruct and display the exact bounded change before mutation. |
| `apply` | Apply one unchanged reviewed plan; refuse drift or replay. |
| `check` | Run deterministic offline repository and skill contracts. |
| `audit` | Inspect an untrusted skill payload read-only without executing it. |
| `doctor` | Diagnose the governed source and trusted toolchain. |
| `repair` | Plan bounded mechanical repairs; it does not rewrite authored intent. |
| `distribution` / `disclosure` | Govern release targets, audiences, delivery, evidence policy, and private-material rules. |
| `eval` | Prepare or record evidence produced by external evaluators. remek runs none. |
| `approve` | Prepare or record reviewer approval bound to the exact candidate and release context. |
| `release` / `release verify` | Plan a payload for one managed mirror or staging path, then verify the committed result. |
| `retire` / `remove` | Retire governed work with history or remove an eligible unselected skill. |
| `update` | Replace the embedded toolchain from one reviewed installed remek bundle. |

## Boundaries and requirements

remek is not an authoring skill, installer, model runner, Git client, package
manager, access-control system, or marketplace. It never calls models or
candidate scripts, creates repositories, installs consumer copies, commits,
pushes, tags, publishes, or changes visibility. Source-only exposure does not
uninstall a consumer copy. Your agent continues
authorized adjacent work — authoring, Git, installation — through the tool
that owns it.

Runtime-only code or class definitions, live dynamic resources, and remotely
sourced MCP skills are outside direct governance unless their relevant content
is materialized as a reviewed file snapshot. remek governs that snapshot, not
the live source or host cache.

Supported execution is Python 3.11+ on macOS or native Linux with verified
POSIX local storage; the runtime is standard-library only. Ordinary workflows
are offline; release alone authenticates the GitHub target. Git is required for
scaffold, staging, and release; GitHub CLI for verified targets. Payloads are
bounded UTF-8 text — binary assets, Windows, WSL, and network filesystems are
unsupported. The wrapper is trust-on-first-use; the
[threat model](docs/threat-model.md) states the exact boundary and non-claims.

## Documentation and contributing

- [remek.dev](https://remek.dev/): the short tour and quick start
- [Workflow reference](skills/remek/references/workflows.md): exact operational sequence and record shapes
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
