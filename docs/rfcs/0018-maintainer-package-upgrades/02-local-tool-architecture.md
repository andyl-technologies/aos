# Local tool architecture

## Design center

The entire workflow is a foreground command run by a maintainer. Commands may
take a long time, but no command depends on a resident process. Durable local
state makes an interrupted operation inspectable and resumable by the next
invocation.

The architecture separates pure decisions from effects without turning either
side into a separately operated component:

```text
`aos-maintain` library
  schemas / canonical bytes / policy / planner / state transitions / verifier
                                |
                                v
`aos maintain` command
  Nix / network / filesystem / worktree / agent / test / Git effects
                                |
                                v
maintainer review and explicit local commit/push/PR operations
```

This boundary makes behavior unit-testable and commands composable while
remaining one local tool.

## Rust crate boundary

### `aos-maintain`

Add a pure library crate to the existing Rust workspace. It performs no
filesystem, network, subprocess, Git, Nix, agent, or clock I/O. Callers supply
all observations explicitly.

It owns:

- maintenance inventory, provider observation, candidate, plan, run, attempt,
  mutation, gate, and evidence types;
- closed-schema decoding, limits, canonical serialization, and digests;
- version normalization, comparison, filtering, and selection;
- unit/member/component/artifact/cohort graph validation;
- materialization and validation DAG construction;
- deterministic risk calculation;
- legal run-state transitions and invalidation rules;
- evidence completeness and final-head verification.

Every public item follows the repository's Rust documentation standard. Each
format has positive, boundary, unknown-field, duplicate, malformed, oversized,
and incompatible-version fixtures.

### `aos` CLI integration

The existing `aos` binary owns all effects through focused modules rather than
one large command implementation:

```text
commands/maintain/inventory.rs
commands/maintain/discovery.rs
commands/maintain/plan.rs
commands/maintain/worktree.rs
commands/maintain/mutation.rs
commands/maintain/materialize.rs
commands/maintain/agent.rs
commands/maintain/validation.rs
commands/maintain/evidence.rs
commands/maintain/git.rs
commands/maintain/state.rs
```

Network transfer and SRI hashing should reuse/refactor the AOS machinery behind
[`aos prefetch`](../../../crates/aos/src/commands/prefetch.rs). Nix and Git
operations reuse existing AOS process/repository abstractions where their
contracts are strong enough.

## Command surface

### Inventory and discovery

| Command | Effect |
| --- | --- |
| `aos maintain inventory` | Evaluate and print the canonical maintenance inventory |
| `aos maintain inventory --check` | Fail on coverage/schema/association errors |
| `aos maintain scan` | Refresh declared upstream and advisory observations |
| `aos maintain scan --offline` | Re-evaluate only sufficiently fresh cached observations |
| `aos maintain report --outdated` | Show selectable newer releases by unit/stream |
| `aos maintain report --unknown` | Show incomplete or contradictory discovery |
| `aos maintain report --family bazel` | Show every maintained stream and lifecycle in one family |

### Planning and execution

| Command | Effect |
| --- | --- |
| `aos maintain plan UNIT` | Create a closed plan without modifying source |
| `aos maintain plan UNIT --target VERSION` | Validate and plan an explicitly selected candidate |
| `aos maintain run UNIT` | Plan if necessary, create a worktree, and advance until a gate or human decision |
| `aos maintain run UNIT --until STAGE` | Stop at a named deterministic boundary |
| `aos maintain resume RUN` | Verify durable preconditions and continue |
| `aos maintain test RUN [--quick | --final]` | Run or rerun the selected gate plan |
| `aos maintain repair RUN` | Invoke one bounded agent iteration for the current typed failure |

### Inspection and handoff

| Command | Effect |
| --- | --- |
| `aos maintain status [RUN]` | Concise current state and next action |
| `aos maintain inspect RUN` | Full plan, diff, attempts, gates, logs, evidence, and budget view |
| `aos maintain diff RUN` | Exact worktree and semantic inventory diff |
| `aos maintain accept RUN` | Record maintainer acceptance of the current candidate edit |
| `aos maintain commit RUN` | Commit the accepted tree using reviewed text and maintainer Git identity |
| `aos maintain evidence RUN` | Generate and verify the final local dossier |
| `aos maintain prepare-pr RUN` | Render title/body/checklist without network mutation |
| `aos maintain publish-pr RUN` | Explicitly push the branch and create/update its PR |
| `aos maintain abandon RUN` | Mark the run abandoned without deleting its evidence or worktree |
| `aos maintain clean RUN` | Remove a completed/abandoned worktree after confirmation |

All commands support stable `--json` output where meaningful. Human output is a
rendering of the same typed result. Exit codes distinguish no-change, pending
human action, test failure, upstream unknown, quarantine, stale plan,
infrastructure failure, and invalid invocation.

High-level commands compose these operations rather than implement alternate
semantics. A maintainer can always stop after a stage and run the lower-level
command directly.

## Repository resolution

Every command resolves and records:

- canonical repository root;
- remote owner/name and expected canonical remote;
- current branch, HEAD, and worktree state;
- maintenance inventory source commit and digest;
- configured target/platform context;
- AOS CLI and policy identity.

Read-only commands can run from a dirty checkout but report which source commit
and working-tree state they observed. Planning a write requires a committed base
and explicit treatment of local changes. Execution never absorbs unrelated
dirty files into an update run.

## Local state layout

Default state follows the XDG base-directory convention and can be overridden
with `--state-dir`:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/aos/maintain/
  repositories/<repository-id>/
    index.json
    runs/<run-id>/
      plan.json
      journal.ndjson
      attempts/<attempt>/
        mutation.json
        gates.json
        evidence.json
        logs/
      final-evidence.json
    worktrees/<run-id>/
```

Cached public observations and fetched data use the XDG cache root rather than
durable state:

```text
${XDG_CACHE_HOME:-$HOME/.cache}/aos/maintain/
  observations/<content-digest>
  downloads/<content-digest>
  projections/
```

State directories are mode `0700` or stricter. Files are written atomically,
bounded, and validated before use. The append-only journal is authoritative;
indexes and reports are rebuildable projections. Logs and caches have explicit
retention and never contain authentication values.

The repository ID binds the canonical repository identity, not only a mutable
path, so moving a checkout does not silently create a second authority. A
state-directory mismatch requires an explicit import/adopt operation.

## Journal and locking

Every state-changing command acquires a local repository/run lock with a
generation/fencing value. One run cannot update the same unit/worktree
concurrently. A killed process leaves an intent record and temporary output;
resume determines whether the effect committed exactly, can be repeated
idempotently, or requires human reconciliation.

Each journal record includes:

- schema and monotonically increasing sequence;
- previous-record digest;
- run, attempt, operation, and actor class;
- expected input/base/head/tree/plan digests;
- result/output digests and structured disposition;
- wall-clock observation for explanation, never ordering authority.

Corrupt, truncated, reordered, duplicated, or unknown journal entries fail
closed. `inspect` explains the last verified boundary.

## Worktree model

`run` creates an isolated Git worktree at the plan's exact base under the local
state root unless `--worktree` selects another empty path. Branches follow the
repository rule:

```text
dplecki/upgrade-<unit>-<target-version>
```

Names are normalized to bounded lowercase kebab-case and gain a short plan
digest on collision. Before every mutation, the tool checks the expected Git
HEAD and tree. It never force-resets, force-pushes, or overwrites unrecorded
human changes.

The agent does not operate directly on Git metadata. It reads a bounded view of
the current tree and returns a patch. The deterministic mutation gateway applies
accepted patches to the worktree. Only the maintainer-facing Git command can
create commits or contact a remote.

Manual edits are supported:

1. `status` detects an unknown tree digest;
2. `aos maintain accept RUN --adopt-worktree` shows the semantic/filesystem
   delta and asks the maintainer to adopt it as a new human attempt;
3. scope, risk, plan, and tests are recalculated;
4. unapproved or out-of-scope changes remain untouched and block automation.

## Candidate commits

A final test result must bind to a Git commit, not only mutable worktree bytes.
After quick gates, `accept` and `commit` show:

- complete semantic and textual diff;
- generated commit message;
- files and package inputs touched;
- remaining final gates;
- special sign-off requirements.

The commit uses the maintainer's configured Git author, committer, and signing
policy. The tool adds no AI attribution, generated-by text, vendor/model name,
agent session link, or automatic DCO sign-off.

Final gates run against that exact commit. A repair creates a new accepted
candidate commit and invalidates prior final results. History can preserve
attempt commits locally; before publication the maintainer may choose the
policy-approved history shape, after which final tests run again on the exact
published head.

For QEMU-side changes, the tool cannot manufacture the required human legal-name
DCO sign-off. It stops with an explicit instruction for the authorized human to
review and create the signed-off commit, then adopts and retests that commit.

## Git and PR handoff

`prepare-pr` is fully offline. It renders a branch name, title, body, evidence
summary, review requirements, and exact commands/effects that publication would
perform.

`publish-pr` is intentionally separate from update execution. It:

1. requires a clean worktree and a final-gated exact head;
2. re-verifies commit signatures, author/committer identity, branch name, base,
   diff, contributor-authorization preconditions available locally, and PR
   text policy;
3. displays the remote, branch, base, commits, title, and body;
4. obtains explicit confirmation unless the maintainer supplied a narrowly
   documented non-interactive approval flag;
5. invokes the configured AOS/Git transport using the maintainer's existing
   authentication;
6. creates or updates only the matching PR;
7. records public identifiers and the remote head, but never credentials.

Authentication is loaded only for this final command and is not inherited by
discovery, source builds, tests, or agent tools. A publishing failure leaves the
tested local branch intact and is safely retryable against the expected remote
head.

The generated PR body contains unit/stream/current/target identity, upstream
evidence, source/artifact changes, impact/risk, deterministic and agent repair
summary, exact final head, gates, warnings, and local evidence digest. It does
not claim that RFC-0017 publication has occurred.

## Agent adapter

Agent integration is provider-neutral and local. A configured adapter exchanges
closed task/result documents with an agent runner. The runner may use a remote
model or local inference according to maintainer configuration, but package
metadata and evidence do not depend on a provider.

The trusted adapter retains any inference authentication outside the task and
worktree. Agent-invoked tools never receive that authentication, Git/GitHub
credentials, SSH agent access, or the maintainer's general environment. The
adapter records bounded usage and policy identity without copying prompts,
secrets, provider attribution, or session links into commits and PR text.

`--agent none` remains a complete supported mode: deterministic updates stop
with typed repair instructions for the maintainer. This is required for
debugging, sensitive packages, and proving that agent assistance is an optional
layer rather than the workflow authority.

## No hidden host tools

Commands run through the documented AOS development/package environment and use
AOS-built dependencies where AOS provides them. Package and test derivations
remain hermetic and never import nixpkgs or reach into host `/bin`/`/usr/bin`.

Local Git authentication and optional agent inference are explicit
maintainer-side effects outside derivations. They are invoked only by the
matching high-level command and never leak into a Nix builder environment.
