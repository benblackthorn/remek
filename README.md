# remek

**Your skills are an asset. Govern them like one.**

remek is the governed source and release layer for [Agent Skills](https://agentskills.io/). It makes completed work reviewable, binds observations to exact bytes, and prepares approved payloads.

Keep a reviewed private library and release selected skills without private material.

## Quick start

> Install remek at user scope with `gh skill` and let me choose the agent interactively.

[`gh skill`](https://cli.github.com/manual/gh_skill) needs GitHub CLI 2.90+.

```bash
gh skill install benblackthorn/remek remek --scope user
npx skills add benblackthorn/remek -g
```

remek has no telemetry. [GitHub CLI](https://cli.github.com/telemetry) and [`npx skills`](https://github.com/vercel-labs/skills/blob/main/README.md#telemetry) document theirs and opt-outs. Private distributions default to `gh`; `npx skills` has no complete private-repository contract.

> Set up my governed skills source. Discover my conventions; if none exist, ask whether skills may become public, then confirm the repository name and path.

Internal-only: private `agent-skills`. Selective release: private `skills-home`
plus public `agent-skills`. Reuse existing setups.

> Capture this as a skill with remek.

Your agent authors one confirmed file; remek captures it and shows an accept plan.

## Review the exact change before it lands

Disposable proof, with shortened paths:

```console
$ ./remek scaffold --name backup-safely …
scaffold: disposable workspace created
$ # Agent completed candidate, provenance, policy, and both case sets.
$ ./remek accept --workspace … --output …/accept.json
accept: exact plan saved; review it with plan show before apply
$ ./remek plan show …/accept.json
plan show: exact plan reconstructed; 4 change(s) and content diff follow
```

Nothing has landed; bound-byte drift refuses:

```console
$ ./remek apply …/accept.json
apply: plan differs at plan.bindings.candidate; nothing applied; recreate and review
  ERROR plan.stale: plan differs at plan.bindings.candidate; nothing applied; recreate and review
```

Only `scaffold` mutates directly, creating an owner-only workspace outside Git.
Durable changes need a reviewed plan and `apply`.

## Skill lifecycle

**Author → accept → record evidence → approve → release.** remek governs from
reviewed input through verified payload; adjacent owners do the work it does not.

`check` is offline. Release authenticates its target. Receipts bind bytes, cases,
profiles, trials, and private report digests—not evaluator honesty.

## Boundaries

remek is not a skill authoring skill. Your agent uses its built-in or preferred workflow, then remek governs the resulting bytes. Git transports; installers place copies; external harnesses evaluate.

Exposure and installation are independent. After acceptance, your agent should
complete or offer user- or project-scope installation.

remek never calls models or candidate scripts, creates repositories, commits, pushes, tags, publishes, changes visibility, controls access, or updates installed copies. Sources and release mirrors have separate histories.

Requires Python 3.11+, macOS or native Linux, POSIX local storage, Git, and GitHub CLI for verified targets. Payload is UTF-8 text; binary assets, Windows, WSL, and network filesystems are unsupported. The wrapper is trust-on-first-use; see the [threat model](docs/threat-model.md).

## Documentation and contributing

Use the installed [workflow reference](skills/remek/references/workflows.md).
Contributors: [AGENTS.md](AGENTS.md), [design](docs/design.md),
[contracts](docs/contracts.md), [threat model](docs/threat-model.md),
[contributing](.github/CONTRIBUTING.md), and [security](.github/SECURITY.md).

## Skills

<!-- remek-skills:start -->
| Skill | Description |
| --- | --- |
| `remek` | Use when a request names remek or asks to govern, audit, evaluate, approve, distribute, or verify release of owned Agent Skill bytes or mirrors. remek governs completed bytes and external results; authoring, Git, installation, and provider work use compatible capabilities. |
<!-- remek-skills:end -->

remek is [MIT licensed](LICENSE) and maintained best-effort, with no response-time commitment.
