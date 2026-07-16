# remek

**Your skills are an asset. Govern them like one.**

remek is the governed source and release layer for [Agent Skills](https://agentskills.io/). It starts from completed work, a design, or a reviewed import; makes changes reviewable; binds external observations to exact bytes; and prepares approved payloads. Agents author. Installers place copies. remek governs the source.

1. Keep a reviewed private skill library.
2. Share approved skills privately.
3. Release selected skills without private material.

## Quick start

> Install remek for me with `gh skill install benblackthorn/remek remek --scope user`. Let me choose the agent when GitHub CLI asks.

[`gh skill`](https://cli.github.com/manual/gh_skill) requires GitHub CLI 2.90+ and is in public preview. It selects the agent interactively; the source must be public or accessible to your account.

```bash
gh skill install benblackthorn/remek remek --scope user
npx skills add benblackthorn/remek -g
```

remek has no telemetry. [GitHub CLI](https://cli.github.com/telemetry) and [`npx skills`](https://github.com/vercel-labs/skills/blob/main/README.md#telemetry) document theirs and opt-outs. `npx skills` has no complete private-repository contract, so private distributions default to `gh`.

> Initialize a governed private skills source in an existing private Git repository at an absolute path I confirm. Show and explain the plan before applying it.

> Capture this as a skill with remek.

Your agent writes the confirmed procedure to one file. remek captures that file—not the chat or neighboring files—and shows an accept plan. Installation creates no governed source.

## Review the exact change before it lands

These lines are from the disposable validation run; paths are shortened:

```console
$ ./remek scaffold --name backup-safely …
scaffold: disposable workspace created
$ # Agent completed candidate, provenance, policy, and both case sets.
$ ./remek accept --workspace … --output …/accept.json
accept: exact plan saved; review it with plan show before apply
$ ./remek plan show …/accept.json
plan show: plan reconstructed exactly; content diff follows
```

Nothing has landed yet. If a bound byte changes, the reviewed plan refuses:

```console
$ ./remek apply …/accept.json
apply: plan differs at plan.bindings.candidate; nothing applied; recreate and review
  ERROR plan.stale: plan differs at plan.bindings.candidate; nothing applied; recreate and review
```

Only `scaffold` mutates directly, creating an owner-only workspace outside protected trees and Git checkouts. Durable changes require a reviewed plan and `apply`.

## Skill lifecycle

1. **Author.** Open an owner-only workspace from completed work, a design, or a reviewed import.
2. **Accept.** Save exact intent; inspect its reconstructed diff before `apply`.
3. **Record evidence.** Bind externally run observations; remek runs none of them.
4. **Approve.** Bind the review and release context. Approval grants no access.
5. **Release.** Prepare the selected payload and manifest; verify the commit before a separate push.

`check` and `check --release DIST` are offline. Release preparation and verification authenticate the GitHub target. Receipts bind candidates, cases, profiles, trial policy, and private report digests; they cannot prove an evaluator or reviewer was honest.

## Boundaries

Agents author. remek governs and prepares. Git records and transports. Installers place copies. External harnesses evaluate.

remek never calls models, runs candidate scripts, creates repositories, commits, pushes, tags, publishes, changes visibility, controls access, or updates installed copies. Private sources and release mirrors have separate repositories and histories.

Requirements: Python 3.11+, macOS or native Linux, verified POSIX local storage, Git, and GitHub CLI for verified targets. Payload is UTF-8 text; binary assets, Windows, WSL, and network filesystems are unsupported. The wrapper is trust-on-first-use; see the [threat model](docs/threat-model.md).

## Documentation and contributing

Read the installed [workflow reference](skills/remek/references/workflows.md), [contracts](docs/contracts.md), [design](docs/design.md), and [threat model](docs/threat-model.md). Cloning is the contributor lane; [AGENTS.md](AGENTS.md) defines its scope, ceilings, and definition of done. See [CONTRIBUTING.md](.github/CONTRIBUTING.md) and [SECURITY.md](.github/SECURITY.md).

## Skills

<!-- remek-skills:start -->
| Skill | Description |
| --- | --- |
| `remek` | Use when a request names remek or asks to initialize or operate a governed Agent Skill source or approved mirror: capture, import, or revise source bytes; audit; record evidence or approval; or prepare or verify release. It governs finished skill bytes and external evaluation results. Do not use it to author or improve skills, run evaluations, install or update consumer copies, operate Git, publish, or change visibility. |
<!-- remek-skills:end -->

remek is [MIT licensed](LICENSE) and maintained best-effort, with no response-time commitment.
