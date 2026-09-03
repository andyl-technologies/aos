# Local tool architecture

## Design center

The entire workflow is a foreground command run by a maintainer. Commands may
take a long time, but no command depends on a resident process. Durable local
state makes an interrupted operation inspectable and resumable by the next
invocation.

The architecture separates pure decisions from effects without turning either
side into a separately operated component:

```text
shared `aos-contract` + `aos-maintain` libraries
  canonical bytes / update schemas / policy / planner / transitions / verifier
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

### Shared contract primitives

Extract the canonical JSON, digest, bounded-decoding, and primitive contract
support already required by RFC-0017 into one small pure crate such as
`aos-contract`. Both `aos-release` and `aos-maintain` use it. The extraction
must preserve RFC-0017 fixtures and byte identities; update tooling does not
create a competing canonical format implementation.

### `aos-maintain`

Add a pure library crate to the existing Rust workspace. It performs no
filesystem, network, subprocess, Git, Nix, agent, or clock I/O. Callers supply
all observations explicitly.

It owns:

- maintenance inventory, provider observation, candidate, plan, run, attempt,
  mutation, gate, and evidence types;
- update-specific closed schemas and limits using the shared canonical/digest
  primitives;
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
commands/maintain/presentation.rs
```

Network transfer and SRI hashing should reuse/refactor the AOS machinery behind
[`aos prefetch`](../../../crates/aos/src/commands/prefetch.rs). Nix and Git
operations reuse existing AOS process/repository abstractions where their
contracts are strong enough.

## Command surface

`aos maintain` with no subcommand renders a read-only home view from current
inventory and cached observations. It does not refresh discovery or modify
source. The complete interaction and rendering contract is defined in
[`09-maintainer-interface.md`](09-maintainer-interface.md).

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
| `aos maintain plan UNIT --component NAME=IDENTITY ...` | Validate and plan an explicitly selected complete component vector; `--target VERSION` is a one-component shorthand |
| `aos maintain plan --campaign COHORT` | Close the component target vectors for an explicit multi-unit campaign |
| `aos maintain run UNIT` | Plan if necessary, create a worktree, and advance until a gate or human decision |
| `aos maintain run --campaign COHORT` | Plan if necessary and execute an explicit multi-unit campaign |
| `aos maintain run UNIT --until STAGE` | Stop at a named deterministic boundary |
| `aos maintain resume RUN` | Verify durable preconditions and continue |
| `aos maintain test RUN [--quick | --final]` | Run or rerun the selected gate plan |
| `aos maintain repair RUN` | Invoke one bounded agent iteration for the current typed failure |

### Inspection and handoff

| Command | Effect |
| --- | --- |
| `aos maintain status [RUN]` | Concise current state and next action |
| `aos maintain inspect RUN` | Full run plan, diff, attempts, gates, logs, evidence, and budget view |
| `aos maintain inspect --plan PLAN` | Full immutable plan, policy, impact, risk, gate, and budget view before execution |
| `aos maintain diff RUN` | Exact worktree and semantic inventory diff |
| `aos maintain accept RUN` | Record maintainer acceptance of the current candidate edit |
| `aos maintain commit RUN` | Commit the accepted tree using reviewed text and maintainer Git identity |
| `aos maintain evidence RUN` | Generate and verify the final local dossier |
| `aos maintain prepare-pr RUN` | Render title/body/checklist without network mutation |
| `aos maintain publish-pr RUN` | Explicitly push the branch and create/update its PR |
| `aos maintain abandon RUN` | Mark the run abandoned without deleting its evidence or worktree |
| `aos maintain clean RUN` | Remove a completed/abandoned worktree after confirmation |
| `aos maintain ui [RUN]` | Open the optional read-only full-screen cockpit when terminal capabilities permit |

All commands produce one typed result. Human, plain, and stable `--json` output
render that result; mutually exclusive `--jsonl` renders typed events and one
mandatory terminal result event for long-running consumers. Human explanation
and progress go to stderr while requested data and primary values go to stdout.
Machine modes never prompt or emit terminal controls. Exit codes distinguish
no-change, pending human action, test failure, upstream unknown, quarantine,
stale plan, infrastructure failure, and invalid invocation.

The CLI extends the existing AOS `Printer`, `indicatif`, `console`, color, and
progress-mode conventions with a maintenance-specific typed renderer. It
centralizes terminal capability detection, removes ambient `atty` checks in
favor of `std::io::IsTerminal`, and never derives durable state from display
output. `--screen-reader` selects ASCII, no-color, non-animated output. An
operation-specific prompt binds the exact plan/tree/head digest; there is no
global approval flag.

High-level commands compose these operations rather than implement alternate
semantics. A maintainer can always stop after a stage and run the lower-level
command directly.

## Repository resolution

Every command resolves and records:

- canonical repository root;
- remote owner/name and expected canonical remote;
- current branch, HEAD, and worktree state;
- repository commit/tree or dirty-content identity associated with the
  inventory, plus its digest;
- configured target/platform context;
- AOS CLI and policy identity.

Read-only commands can run from a dirty checkout but report which source commit
and exact working-tree content they observed. The CLI wraps pure Nix inventory
bytes in a repository envelope containing commit, tree, dirty-state/content
digest, target set, inventory digest, and local-clone identity. Planning a write
requires an envelope for a clean committed base. Execution never labels dirty
bytes as `HEAD` or absorbs unrelated local changes into a run.

The coordinator executable and dependency closure are frozen in the plan. It
always operates on the candidate checkout through an explicit root and never
replaces itself with `pkgs.aos` built from candidate source. An update to Rust,
OpenSSL, Git, Nix, or `pkgs.aos` tests the candidate tool as an artifact while
the base controller remains the journal authority. Resume under another
controller requires explicit run-schema compatibility and records the new tool
identity before effects continue.

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
        patch.diff
        files.json
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

State directories are mode `0700` or stricter. Files are written through
directory-relative no-symlink opens, bounded, validated, flushed, atomically
renamed, and followed by parent-directory synchronization before a transition
is considered durable. The append-only journal is authoritative; indexes and
reports are rebuildable projections. Logs and caches have explicit retention
and never contain authentication values.

The repository key binds both canonical remote identity and the local Git common
directory identity/path. Two clones of the same remote therefore cannot share
locks or worktrees accidentally. Moving a clone requires an explicit state
adoption operation that verifies the Git object database, base commits,
worktrees, and run records before rewriting the local binding.

Each attempt retains its canonical textual patch, before/after file manifest,
and the content needed to reconstruct new text files from the retained base and
parent attempts. Binary generated outputs are forbidden from automatic attempts
unless a later typed format defines equivalent retention. Cleanup cannot prune
an attempt still referenced by retained evidence.

## Journal and locking

Every state-changing command acquires a local repository/run lock with a
generation/fencing value. Campaign creation atomically locks every ordered unit
before mutating any of them, so two runs cannot overlap a unit or worktree. A
killed process leaves an intent record and temporary output; resume determines
whether the effect committed exactly, can be repeated idempotently, or requires
human reconciliation.

Each journal record includes:

- schema and monotonically increasing sequence;
- previous-record digest;
- run, attempt, operation, and actor class;
- expected input/base/head/tree/plan digests;
- result/output digests and structured disposition;
- wall-clock observation for explanation, never ordering authority.

The local hash chain and durable index detect accidental corruption, unexpected
truncation relative to the recorded tip, reordering, duplication, and unknown
entries. They do not claim cryptographic immutability against the maintainer
account that owns the state directory. `inspect` explains the last verified
boundary. Before replaying any remote effect, resume reconciles the observed
remote head/PR with the last durable intent/result.

## Worktree model

`run` creates an isolated Git worktree at the plan's exact base under the local
state root unless `--worktree` selects another empty path. Branches follow the
repository rule:

```text
dplecki/upgrade-<campaign-slug>-<target-summary>
```

A one-unit campaign uses its unit ID and target version as those fields. Names
are normalized to bounded lowercase kebab-case and gain a short plan digest for
multi-unit campaigns or on collision. Before every mutation, the tool checks
the expected Git HEAD and tree. It never force-resets, force-pushes, or
overwrites unrecorded human changes.

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

The commit uses the maintainer's reviewed Git author, committer, and signing
policy through a sanitized Git configuration and an empty hooks path. If the
maintainer relies on a local hook, they run it as a separate explicit review
step before acceptance; candidate source never executes in a credentialed hook.
The tool adds no AI attribution, generated-by text, vendor/model name, agent
session link, or automatic DCO sign-off.

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
   diff, local contributor-identity preconditions, and PR text policy;
3. displays the remote, branch, base, commits, title, and body;
4. obtains explicit confirmation;
5. invokes a one-shot publisher with an empty hooks path, sanitized Git
   configuration, exact remote/refspec, expected remote head, and the
   maintainer's explicitly selected authentication source;
6. creates or updates only the matching PR;
7. records public identifiers and the remote head, but never credentials.

Authentication is loaded only for this final command and is not inherited by
discovery, source builds, tests, agent tools, or Git hooks. A maintainer
credential may itself have wider repository authority; the local safety claim
is that no untrusted process can use it and the publisher exposes only exact
branch/PR operations. Protected-branch rules remain the independent backstop.
A publishing failure leaves the tested local branch intact and is safely
retryable against the expected remote head.

Local evidence records contributor authorization as `pending-remote`.
`publish-pr` does not turn a local identity check into an authorization claim.
A later explicit foreground status observation may record the repository's
exact-head authorization/check/review result as `merge-eligible-observed`.

The generated PR body contains campaign and unit/component current/target
identities, upstream evidence, source/artifact changes, impact/risk,
deterministic and agent repair summary, exact final head, gates, warnings, and
local evidence digest. It does not claim that RFC-0017 publication has
occurred.

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
