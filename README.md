# remek

**Governed release management for Agent Skills.**

remek is a local-first governance toolkit for **turning completed
[Agent Skills](https://agentskills.io/) into reviewed, releasable artifacts**.

It sits between authoring and publishing:

| Layer | Owns |
| --- | --- |
| Agent Skills | Portable skill artifact and open format |
| Git | History and transport |
| `gh skill` | Preview, installation, updates, version pins, and publication validation |
| remek | Exact candidate, provenance, evidence freshness, approval, disclosure, selected projection, and pre-push verification |
| Agent host | Routing, tools, runtime authorization, and execution |

In practical terms, remek helps you take a skill that already exists, bind it to
exact identity and provenance, review evidence against those exact bytes,
approve a release, and prepare a controlled projection for the right mirror or
audience.

---

## Preview, install, and start

> **Change the skill, and its old evidence and approval stop counting. remek
> refuses to release different bytes from the ones you reviewed.**

`gh skill` requires GitHub CLI 2.90 or newer and remains in public preview.
GitHub does not verify installed skills, so inspect the exact release first:

```bash
gh --version
gh skill preview benblackthorn/remek remek@v1.0.4
```

Install for Codex in user scope and verify the installed CLI:

```bash
gh skill install benblackthorn/remek remek --pin v1.0.4 --agent codex --scope user
python3 -I -S -B "$HOME/.codex/skills/remek/scripts/cli.py" --version
```

For Claude Code:

```bash
gh skill install benblackthorn/remek remek --pin v1.0.4 --agent claude-code --scope user
python3 -I -S -B "$HOME/.claude/skills/remek/scripts/cli.py" --version
```

Both checks should print `remek 1.0.4`; `gh skill list --scope user` should
report the install as pinned. The installer places a user-scoped skill for the
selected coding agent, not a shell command. Then ask:

> Set up my private governed skills source with remek. Discover my existing
> conventions and repositories first, then confirm the name and absolute path
> before creating anything.

You can also run `npx skills add benblackthorn/remek -g`. Use `gh` by default
for private distributions; `npx skills` does not provide a complete
private-repository contract. The
[workflow reference](skills/remek/references/workflows.md) contains exact
sequences.

---

## Why remek exists

The Agent Skills ecosystem is gaining better portability, scanners, evaluation
harnesses, and distribution paths. What is still under-served is
**governance**.

An owner or team shipping skills eventually needs to answer questions like:

- What exact skill bytes are we talking about?
- What changed since the last accepted release?
- Which scan or evaluation results apply to those exact bytes?
- Are those results still current or now stale?
- Who declared approval for the release?
- Is the release intended for a private audience or the public?
- Does the committed release mirror still match the approved source?

remek is built around those questions.

---

## What remek is

remek is a **governed source and release layer** for Agent Skills.

Today, the repository is designed around a few core ideas:

1. **Exact-byte identity.** A governed candidate is identified by the exact
   bytes under review. Digests are identities, not signatures.

2. **Provenance matters.** Retained source, upstream identity, and rights stay
   with the governed skill. Release manifests separately bind Git, target,
   remote, and projected payload state.

3. **Evidence is bound to the candidate.** Release evidence is tied to the
   exact candidate, cases, routing catalog, evaluator profile, trials, and
   distribution context it covers.

4. **Staleness is explicit.** If bound inputs change, affected evidence becomes
   stale. `check` reports it; release refuses it.

5. **Approval is separate from evidence generation.** Evaluations and other
   observations are inputs. They are not the release decision. The reviewer
   field is a declaration, not authentication or receipt attestation.

6. **Source and mirrors have different roles.** The governed source remains
   authoritative. Consumer mirrors receive approved one-way projections.

7. **Release projection is intentional.** remek prepares only what is eligible
   for a given audience rather than blindly copying repository state.

---

## What remek does today

The current repository supports a full local governance workflow for skills.

### Govern completed work

remek is intentionally biased toward **capturing already-completed work** and
turning it into a governed skill repository.

It supports workflows such as:

- initializing a governed source;
- scaffolding captured work, a design, or a reviewed import;
- accepting complete reviewed bytes without inventing missing content;
- revising lifecycle, exposure, distributions, and disclosure through plans;
- checking, repairing, retiring, removing, and updating governed state.

`scaffold` creates a disposable owner-only workspace. A human or agent
completes the candidate before remek accepts it.

### Preserve exact identity and provenance

remek tracks the exact candidate tree being reviewed and retains its source,
upstream identity, rights, policy, and cases. Release manifests separately bind
the source commit, branch, audience, target lineage, remote transport, prior
mirror state, selected paths, modes, and hashes.

### Generate deterministic plans before mutation

Only `scaffold` mutates directly. Durable source and mirror changes are saved
as exact plans, inspected, explained, approved by the owner, and then applied.

That gives remek a few important safety properties:

- proposed changes can be reviewed before apply;
- changed bound inputs refuse before execution;
- cooperative local failures can restore the prior state;
- residue is surfaced instead of silently ignored.

This refusal transcript is literal CLI output and checked byte-for-byte by the
repository tests:

```console
$ ./remek apply …/accept.json
apply: plan differs at plan.bindings.candidate; nothing applied; recreate and review
  ERROR plan.stale: plan differs at plan.bindings.candidate; nothing applied; recreate and review
```

There is no journal or guarantee for process death, power loss, hostile writers,
or network storage.

### Bind release evidence to the release subject

An agent, test suite, or external harness runs the trials; remek runs none.
Evidence is tied to inputs such as:

- candidate and case-set digests;
- evaluator identity, profile, and run configuration;
- routing catalog and intended distribution;
- ordered trial outcomes and thresholds;
- one private report digest.

Changing the skill or a material evaluation input invalidates affected proof.
Evidence does not prove evaluator honesty or freeze live APIs, databases, MCP
sources, dynamic resources, or host caches.

### Support check, doctor, and repair workflows

The repository can inspect repository health, detect drift or malformed
records, diagnose the trusted toolchain, and plan bounded mechanical repairs
without rewriting authored intent.

### Prepare controlled release projections

remek can prepare a managed mirror projection or an unverified staging-only
projection for an explicit distribution.

A managed mirror receives only approved `skills/` and
`release-manifest.json`, never private governance records. The manifest binds
paths, modes, hashes, lineage, target, and private context as digests.
Source-side verification rechecks the clean committed mirror, governed source,
manifest-bound remote and branch, and authenticated GitHub target.

The standalone manifest verifier can check mirror payload integrity without the
private source; it cannot reconstruct private evidence or approval. Staging-only
output is unverified and never push-ready.

Organizations that require cryptographic distribution assurance can create the
mirror commit under their existing Git signing policy before `release verify`,
or sign a tag pointing to the verified commit. remek holds no signing keys and
does not treat signatures as evidence or approval.

Release requires `ready` lifecycle, audience-eligible exposure, complete
rights, disclosure policy, current evidence and approval, clean committed Git,
the expected branch and audience, credential-free remotes, and matching
authenticated target visibility. Public release also requires separate history,
blocked private disclosure, `public-eligible` policy, irreversibility review,
and an exact candidate/provenance license match. Credentials cannot be excepted.

This repository dogfoods governed-source intake and evidence: its
[governed remek records](.remek/skills/remek/) contain the current policy,
provenance, retained design, cases, and evidence. No self-issued remek
distribution approval is claimed; managed mirrors omit the governance tree.

### Preserve last-known-good behavior through refusal

If a candidate loses required proof or no longer satisfies release readiness,
remek favors refusing the new release over silently accepting something weaker.
A pre-mutation blocker leaves the target unchanged. If mutation begins and a
cooperative local failure occurs, remek attempts exact restoration and reports
the actual final state, including any residue.

---

## What remek does **not** do

remek is **not** trying to be the entire Agent Skills stack.

It is not:

- an Agent Skills authoring environment;
- a hosted catalog;
- an installer or package manager;
- a general-purpose scanner;
- a benchmark runner or online evaluation service;
- a runtime permission engine;
- a skill execution host;
- a secret manager or signing service;
- a generic CI/CD platform;
- an autonomous skill-improvement loop.

remek never creates repositories, runs candidate scripts, installs consumer
copies, commits, pushes, tags, publishes, or changes repository visibility.
It does perform deterministic credential and disclosure screening within its
governed boundary. For outputs from separate systems, remek asks:

> Which exact bytes do these claims apply to, and were those bytes approved for
> this release?

---

## The workflow, at a glance

A simple way to think about remek is this:

1. **A skill exists** — written by a human or agent, designed from a reviewed
   brief, or imported from prior work.
2. **remek governs it** — the exact candidate, provenance, policy, and cases are
   accepted through a reviewed plan.
3. **A private source may stop here** — `draft` and `source-only` are valid;
   evidence and approval become required before releasing a selected
   distribution.
4. **Evidence is recorded** — external evaluations or observations are attached
   to the exact candidate and run context.
5. **A release is approved** — for a particular audience, distribution, target,
   and set of exceptions.
6. **A projection is prepared and verified** — as a controlled mirror with a
   release manifest.
7. **Publication remains separate** — Git, GitHub, and installers transport or
   place the verified bytes only after separate authorization.

That is the category remek occupies.

---

## Current command and workflow surface

The CLI stays centered on governance operations:

- **`init`**, **`scaffold`**, and **`accept`** govern completed captured,
  designed, imported, or revised work.
- **`distribution`**, **`disclosure`**, **`retire`**, and **`remove`**
  govern release context and lifecycle.
- **`check`**, **`repair`**, **`doctor`**, and **`audit`** inspect or
  mechanically repair state without executing candidate content.
- **`eval`** and **`approve`** prepare or record external evidence and a
  separate reviewer declaration.
- **`release`** plans a managed mirror or staging-only projection and verifies
  a clean committed managed mirror.
- **`plan`** and **`apply`** display and apply one unchanged reviewed plan.
- **`update`** replaces the embedded toolchain from a reviewed remek bundle.

Run `./remek --help` or `./remek COMMAND --help` for exact arguments. Put
global `--root` and `--json` before the command.

---

## Security and trust model

remek takes a narrow, defensive approach.

At a high level, the repository is designed to resist governance failures such
as:

- releasing bytes that differ from what was reviewed;
- treating stale evidence as current at release;
- allowing mirror state to become the de facto source of truth;
- silently absorbing bound Git or filesystem drift and hostile structure;
- mixing private governance state into public payloads;
- relying on mutable context instead of explicit subject identity.

Candidate content never executes. The shipped runtime is Python 3.11+,
standard-library only, and scoped to verified POSIX local storage on macOS or
native Linux. Ordinary workflows are offline; release alone authenticates the
GitHub target, while bounded local Git queries are used where required.
Managed release requires the governed source and mirror to be Git worktree roots
and checks the full Git object database under a fixed 30-second subprocess bound.
Project mode therefore inherits the enclosing repository's object-database cost;
use a dedicated governed source when a large monorepo cannot meet that boundary.

Governed payloads are bounded UTF-8 regular-file trees. Binary assets, links,
special files, Windows, WSL, and network filesystems are unsupported. `audit`
checks structural compatibility only, not benign intent, script safety,
upstream trust, provenance, or host execution safety.

The loaded bundle, caller-selected interpreter, OS, intent, selected roots, and
external ancestors remain trusted. Manifests and digests provide identity, not
signatures, and records cannot prove their author was honest. The
[threat model](docs/threat-model.md) states the exact boundary and limitations.

---

## Design principles

- **Local-first** — no hosted control plane is required.
- **Deterministic** — governed mutations should be understandable and
  reproducible.
- **Review before mutation** — plan first, then apply.
- **Separate evidence from decision** — observations inform approval; they do
  not replace it.
- **Do not over-trust downstream systems** — mirrors, catalogs, and installers
  do not substitute for source governance.
- **Keep the source authoritative** — release targets are projections, not
  independent truth.
- **Favor conservative release behavior** — if proof is stale or readiness
  fails, refuse the new release.

---

## Who remek is for

remek is for owners and teams who need more rigor than:

- a bare Git repository;
- a simple copy-to-catalog step;
- or a one-time scan attached to a release note.

It is especially relevant when you need to manage:

- a trustworthy private skill library;
- private versus public release boundaries;
- controlled downstream targets;
- repeatable release approval;
- evidence freshness;
- and strong correspondence between reviewed and released bytes.

It is a working, opinionated toolkit, intentionally narrow and not an ecosystem
standard, with a bounded, standard-library-only trusted core and explicit size
and surface ceilings.

---

## Documentation and contributing

For exact workflows and the implementation contract, see:

- [remek.dev](https://remek.dev/) — short tour and quick start
- [Workflow reference](skills/remek/references/workflows.md) — executable
  sequences and record shapes
- [Design](docs/design.md) — outcomes, ownership, and architecture
- [Contracts](docs/contracts.md) — canonical formats, limits, and refusal
  semantics
- [Threat model](docs/threat-model.md) — trusted inputs, hostile bytes, and
  unsupported guarantees
- [Contributing](.github/CONTRIBUTING.md) and
  [security policy](.github/SECURITY.md)

## Skills

<!-- remek-skills:start -->
| Skill | Description |
| --- | --- |
| `remek` | Use when a request names remek or asks to initialize a governed Agent Skills source; capture, import, or revise governed skills; record reviewed external evidence or distribution approval; audit an untrusted skill; or prepare and verify a release mirror you own. remek governs completed skill bytes and reviewed results; authoring, evaluation runs, Git, installation, and publishing use compatible capabilities. |
<!-- remek-skills:end -->

remek — [ˈrɛmɛk], Hungarian for excellent — is [MIT licensed](LICENSE) and
maintained best-effort, with no response-time commitment.
