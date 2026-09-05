# remek

**Review and release exact Agent Skill bytes.**

remek helps an owner maintain a trustworthy private skill library and deliberately
release selected skills to a different audience. Write skills with ordinary files
and Git. remek checks those files, retains reported evaluation observations, binds
one review to a complete distribution, and prepares an exact release artifact.

The runtime is Python 3.11+, standard-library only, for verified local POSIX
filesystems on macOS and native Linux. It runs no candidates or evaluators.
Git provides history and transport; the agent host owns execution permissions;
an installer places consumer copies.

## Start with a private source

From this reviewed producer checkout:

```bash
./remek --version
./gate
./remek init /abs/sources/private-skills --output /abs/private-plans/init.json
./remek show /abs/private-plans/init.json
./remek apply /abs/private-plans/init.json
```

Use existing owner authorization to apply the reviewed plan. Plans must be outside
all protected roots, including an absent target's transaction parent. Initialize a
source in its intended parent and keep plans in a separate private directory.
Use `--project` only when intentionally governing `.agents/skills` in a project.
`init` preserves existing README and foreign files and refuses populated `skills/`.

Then add completed, reviewed payload bytes under `skills/NAME/`, declare NAME in
`remek.json`, and write `.remek/skills/NAME/skill.json`. This single authored record
contains exposure, provenance, and routing/behavior cases. A missing evaluation
or an empty case set is a warning for private source use; release has stricter gates.
See the [workflow reference](skills/remek/references/workflows.md) for a complete
record example, evaluation, review, migration, and release steps.

```bash
./remek --root /abs/sources/private-skills check
./remek audit /abs/reviewed-import/NAME
./remek --root /abs/sources/private-skills --json eval plan NAME --kind behavior
./remek --root /abs/sources/private-skills --json eval plan NAME --kind routing --distribution DIST
./remek --root /abs/sources/private-skills --json review plan DIST
```

## What a release review means

Each evaluation stores the actual run configuration and bounded per-trial
observations. Passing is derived from the declared threshold. Reports are
caller-reported evidence, not proof that a provider ran or that an evaluator was
honest. Full private traces may remain in external files identified by digest.

One distribution review binds every selected candidate, the complete skill
records, cases, disclosure policy, distribution definition, and all currently
relevant evidence. It selects passing evidence for each required profile and
explicitly acknowledges failures from required profiles. New relevant evidence
atomically clears the active review. Identical reports are a no-op. Editing a
candidate leaves historical evidence in place and makes it stale.

A reviewer's name and date are declarations. The review neither authenticates the
reviewer nor authorizes scripts or tools. Public release additionally requires
eligible exposure, reviewed rights, an exact payload/provenance license match,
blocked private disclosure, explicit irreversibility review, and a public target.

## Prepare and verify a distribution

A distribution selects exact skills and a GitHub target. Source and managed mirror
must have clean committed HEADs; remek checks owned files against raw Git blobs and
executable modes. A managed release rechecks the authenticated target and records
only payload plus a manifest. Governance remains in the source; private identities
appear in the manifest as hashes.

```bash
./remek check --distribution DIST
./remek release plan DIST --mirror /abs/mirror --output /abs/private-plans/release.json
./remek show /abs/private-plans/release.json
./remek apply /abs/private-plans/release.json
```

After a separately authorized exact mirror commit:

```bash
./remek release verify DIST --mirror /abs/mirror
./remek verify /abs/mirror
```

`release verify` checks artifact, source readiness, target, and commit lineage at
that time. `verify` checks only the artifact's declared inventory; it cannot prove
private-source readiness or target identity. Staging also requires a saved plan:

```bash
./remek release plan DIST --staging /abs/staging --output /abs/private-plans/staging.json
./remek show /abs/private-plans/staging.json
./remek apply /abs/private-plans/staging.json
```

Applying this plan creates an artifact without target verification. None of these
commands commits, pushes, tags, publishes, installs, or changes visibility.

## Small command surface

| Purpose | Commands |
| --- | --- |
| Source setup and checking | `init`, `check`, `audit`, `update` |
| Reported observations | `eval plan`, `eval record` |
| Whole-distribution review | `review plan`, `review record` |
| Release | `release plan`, `release verify`, `verify` |
| Exact mutation | `show`, `apply` |

Put `--root` and `--json` before the command. `init`, `audit`, and `verify` take
explicit paths and forbid `--root`. `show` and `apply` treat a supplied root as an
assertion against the saved plan. Run `./remek --help` for the exact grammar.

Normal commands accept only `remek.2`; there are no legacy aliases.
The [source-only v1 converter](tools/migrate_v1.py) rehearses conversion against a
verified backup; it never upgrades a live installation automatically.

For this repository's releases from `main`, follow the
[maintainer instructions](.github/CONTRIBUTING.md#release-the-source-project).
Source release checks do not produce reported evaluation records or a governed
distribution review.

## Boundaries and documentation

Manifests are identities, not signatures. Candidate audit checks the supported
`remek-text` file profile, not intent or script safety. Credential screening can
miss secrets or produce false positives. Cooperative transaction failures restore
owned state when possible and report exact residue; process death, power loss,
noncooperating writers, network storage, and Windows are outside the guarantee.

- [Workflow reference](skills/remek/references/workflows.md): authoring and exact commands.
- [Design](docs/design.md): outcomes and semantic ownership.
- [Contracts](docs/contracts.md): formats, identities, limits, and result fields.
- [Threat model](docs/threat-model.md): trusted inputs and exclusions.
- [Contributing](.github/CONTRIBUTING.md) and [security policy](.github/SECURITY.md).

remek — [ˈrɛmɛk], Hungarian for excellent — is [MIT licensed](LICENSE) and
maintained best-effort, with no response-time commitment.
