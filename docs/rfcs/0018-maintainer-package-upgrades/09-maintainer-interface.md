# Maintainer interface and experience

## Product standard

`aos maintain` is a maintainer workbench, not a thin wrapper around logs. It
must make a long, partially agent-assisted update feel controlled and legible:

- the current object, state, risk, and next action are visible at every pause;
- completed work becomes stable scrollback rather than disappearing with a
  spinner;
- every prompt names the exact immutable object and effect being authorized;
- interruption is expected, checkpointed, and followed by an exact resume
  command;
- semantic package changes appear before raw patches and command output;
- rich terminal, plain terminal, JSON, and JSONL views describe the same state;
- color, symbols, cursor motion, and screen position never carry information
  alone.

The default interface is a polished line-oriented CLI. It is complete on its
own, works well over SSH, preserves scrollback, and degrades predictably in a
narrow or non-interactive terminal. An explicit `aos maintain ui` command may
open a read-only full-screen cockpit for navigating many updates and long runs.
No action requires that cockpit, and it is not the initial implementation
dependency.

The durable campaign is the product object. A conversation, progress bar,
terminal buffer, renderer, or model task list is only a view of that object and
never becomes workflow authority.

## One presentation model

The pure `aos-maintain` crate defines presentation-neutral types alongside its
workflow types. Durable workflow transitions and transient display progress are
different contracts:

```text
JournalEvent
  journal sequence, previous/record digest, run/attempt, intent or result,
  bound object digests, durable payload

ProgressEvent
  invocation sequence, operation identity, counter/message, bounded payload

MaintenanceView
  durable state plus active progress, title, sections, task tree, diagnostics,
  available actions

MaintainCommandResult
  schema, command, disposition, primary values, warnings, next actions

Diagnostic
  stable code, severity, summary, detail, source span, remediation

NextAction
  label, argv, reason, prerequisites, effect class, bound context
```

The controller appends `JournalEvent` only for effect intent/result, state
transition, decision, and other durable facts. Transfer ticks, spinners,
heartbeats, and intermediate counters are bounded `ProgressEvent` values and
never enter the hash-chained journal. A reducer builds the current view from
journaled state plus the active invocation's ephemeral progress; renderers do
not infer state by parsing subprocess logs.

```text
durable transition --> JournalEvent --> journal/evidence --> view reducer
active operation  --> ProgressEvent ----------------------> view reducer
subprocess bytes  --> bounded sanitized log metadata ----> evidence/detail
                                                           |
                                                           v
                                                  human / JSONL renderer
```

Every dispatched maintenance command returns exactly one
`MaintainCommandResult` to a single process-boundary renderer. That is
important because the existing general-purpose `Printer` allows commands to
print incremental JSON fragments. Maintenance code must never call incremental
`Printer::json` or `Printer::error`; it returns typed diagnostics and completion
instead. A successful subprocess exit is an observation, not a workflow result;
only the state reducer produces the command disposition.

PR 3 replaces the exiting Clap path with a non-exiting parse/dispatch boundary
for recognized maintenance invocations and introduces `CommandCompletion` for
their result and exit code. Root help/version and errors raised before the
`maintain` family or its output mode can be recognized retain Clap's ordinary
text contract and are not falsely described as maintenance-result JSON.

## Rendering modes

### Rich inline mode

Rich inline mode is the default when the human presentation stream is an
interactive terminal: stderr for activity/diagnostics and stdout for a
requested static report or diff. It uses restrained color, Unicode symbols,
adaptive columns, elapsed time, and `indicatif::MultiProgress`. At most one
overall progress bar and a small, bounded number of active child bars redraw. A
completed step becomes one stable line and releases its bar.

Concurrent warnings, diagnostics, and action cards print through the progress
coordinator so they cannot corrupt the display. Indeterminate spinners are used
only when no meaningful unit exists; a spinner always has a stage name and
elapsed time.

### Plain mode

Plain mode writes newline-delimited milestones without cursor movement. It is
selected when the active human presentation stream is non-TTY and by
`--progress plain`. Long operations emit a stage transition immediately and
then bounded heartbeats using the existing AOS interval/proportional policy.
Repeated log lines and rapidly changing counters are coalesced.

At narrow widths, records replace columns:

```text
bazel-7 current=7.6.2 candidate=7.6.3 discovery=UPDATE-AVAILABLE
bazel-8 current=8.4.2 candidate=8.4.3 run=MATERIALIZING elapsed=2m14s
qemu current=10.0.0 candidate=10.1.0 discovery=QUARANTINED reason=policy-major
```

### Screen-reader mode

`--screen-reader` is an explicit stable mode. It implies
`--progress plain --color never`, uses ASCII rather than decorative glyphs,
disables animation and the full-screen cockpit, expands abbreviated status
labels, and keeps information in reading order. `TERM=dumb` selects the same
terminal capabilities unless the maintainer explicitly chooses another
supported output mode.

This is stronger than color suppression. A screen reader should encounter the
campaign summary, current state, failure, and next commands in that order,
without walking through a visual grid or hearing every progress redraw.

### JSON and JSONL

The existing global `--json` flag means one complete, versioned JSON object on
stdout and no live human progress. Maintenance adds mutually exclusive
`--jsonl` for a versioned stream whose envelopes contain a durable
`JournalEvent`, transient `ProgressEvent`, diagnostic, or final result. Each
envelope has an invocation-local `stream_sequence`; a durable event additionally
has its run-global `journal_sequence` and record digest. Resuming a run starts a
new stream sequence without colliding with the journal sequence.

On normal or handled termination while stdout remains writable, JSONL ends with
a `result` event carrying the same disposition and next actions as the
one-document result. SIGKILL, power loss, abort, panic before recovery, or a
closed stdout can make that impossible. EOF without a final result is
indeterminate; consumers reconcile durable truth with
`aos maintain status RUN --json`. Output-delivery failure never changes a
persisted run into success or failure.

Machine modes never prompt, page, open an editor, emit terminal control
sequences, or fall back to `/dev/tty`. Durations are integer milliseconds.
Timestamps, run IDs, digests, enum values, and argument arrays are typed rather
than embedded in prose. Unknown fields follow the schema's stated compatibility
rules; event envelopes bind the plan, run, attempt, tree, and head when those
objects exist.

An illustrative final result is:

```json
{
  "schema_version": "aos.maintain.cli/v1",
  "command": "run",
  "disposition": "action-required",
  "exit_code": 11,
  "run_id": "01K4D9HMR09Q6S37FX9PWGCM8A",
  "data": {
    "unit": "bazel-8",
    "run_state": "blocked-human",
    "operation": "repair"
  },
  "warnings": [],
  "next_actions": [
    {
      "argv": ["aos", "maintain", "repair", "01K4D9HMR09Q6S37FX9PWGCM8A"],
      "reason": "patch no longer applies"
    }
  ]
}
```

### Stream ownership

Human explanation and progress go to stderr. Machine documents, requested
diff/report content, and primary values such as an exact run ID, artifact path,
or PR URL go to stdout. `--quiet` suppresses human progress and commentary but
retains requested primary output and errors. Broken-pipe handling is clean and
does not turn a successfully persisted run into a failed or falsely completed
one.

The terminal capability snapshot is computed once from stdin/stdout/stderr TTY
state, width, `TERM`, `NO_COLOR`, explicit color/progress/screen-reader flags,
and Unicode support. It is injectable in tests. Code must not let separate
libraries make conflicting TTY or color decisions.

`--jsonl` and `--screen-reader` are family-global Clap arguments accepted within
the `maintain` subtree; the existing `--json`, `--quiet`, `--progress`, and
`--color` remain root-global. Their combinations are deterministic:

| Selection | Result |
| --- | --- |
| `--json` with `--jsonl` | Invalid invocation; the formats are mutually exclusive. |
| Either machine format | Forces progress off, color off, and prompting/paging/editing off; an explicitly forced non-off progress mode is invalid. |
| `--screen-reader` | Implies plain progress, no color, ASCII, and no cockpit; explicit `--progress off` may suppress progress, while `--progress tty` or `--color always` is invalid. |
| `TERM=dumb` in auto modes | Selects ASCII, no cursor control, and no color; explicitly forced TTY progress is invalid. |
| `NO_COLOR` with `--color auto` | Disables color; explicit `--color always` remains the explicit override outside screen-reader or dumb-terminal mode. |
| `--quiet` with a machine format | Machine format wins; quiet is redundant and changes no document fields. |

### Untrusted terminal text

Every human renderer passes untrusted scalar text through one escaping layer
before layout or styling. It visibly escapes C0/C1 controls, ESC/CSI/OSC
sequences, embedded line breaks, and bidirectional formatting controls; strips
nothing silently; and computes width from the escaped representation. Package
metadata, upstream release names, URLs, source excerpts, subprocess output, and
agent text cannot create status lines, links, terminal titles, or cursor motion.

Bounded pre-render bytes, after credential scrubbing and retention policy, may
be retained only in the protected evidence/log store. Log views are sanitized
even when showing a retained file; there is no "raw to terminal" flag.
JSON/JSONL use their normal structural escaping and do not embed ANSI
decoration. Miette receives already sanitized labels and source content rather
than becoming the sanitizer.

## Information design

### Separate state axes

The interface never compresses discovery, durable workflow state, gate outcome,
and command disposition into one status enum:

| Axis | Canonical values | Purpose |
| --- | --- | --- |
| `DiscoveryDecision` | `current`, `update-available`, `unknown`, `quarantined` | What the bound fresh discovery evidence proves for a unit/stream. |
| `RunState` | Every normal and side/terminal value in the [run state machine](04-execution-and-agent-loop.md#run-state-machine) | The run's last durable transition, including `quick-gated`, `candidate-accepted`, `committed`, `final-gated`, `ready-for-pr`, `pr-published`, `superseded`, `rejected`, and `abandoned`. |
| `TaskStatus` | `pending`, `running`, `completed` | Ephemeral execution status for a controller-owned operation in the active task DAG. |
| `GateOutcome` | `success`, `failure`, `action-required`, `cancelled` | The result of one planned logical gate. |
| `CommandDisposition` | `success`, `operation-failed`, `invalid-invocation`, `infrastructure-unavailable`, `no-change`, `action-required`, `upstream-unknown`, `quarantined`, `stale`, `interrupted` | What the requested CLI operation did and how its caller should proceed. |
| `DiagnosticSeverity` | `warning`, `error` | Supplemental information that does not replace any state above. |

The UI carries every `RunState` value without collapsing it to generic
`RUNNING` or `READY`:

```text
observed | selected | planned | worktree-ready | materializing | policy-valid
quick-gated | repairing | candidate-accepted | committed | final-gated
ready-for-pr | pr-published | awaiting-remote-authorization
merge-eligible-observed | merged-observed | release-handoff
no-change | superseded | blocked-human | quarantined | rejected | abandoned
failed
```

Human views label the axis when ambiguity is possible: `DISCOVERY UNKNOWN`,
`RUN quick-gated`, `GATE failure`, or `ACTION REQUIRED`. Uppercase display
words and optional symbols/colors are renderings of exact schema values, never
additional states. A `blocked-human` run can therefore produce an
`action-required` command disposition without renaming its durable run state.

Color, symbol, and position never replace the label. `UNKNOWN` is not softened
into success, a warning is not a gate outcome, and an action-required
disposition is not presented as an ordinary command failure.

### Responsive hierarchy

The layout uses display-cell width rather than byte or character count:

- at 120 columns and above, reports show their full decision-oriented columns;
- from 80 through 119, secondary identity and timing fields move into details;
- below 80, each important item becomes a stacked card or plain record;
- unbounded values such as paths, URLs, and error messages never determine
  table width and remain available in `inspect`, `diff`, or JSON;
- exact IDs remain selectable and copyable; only explicitly accepted ID inputs
  may use an unambiguous prefix.

The first screen answers, in order: what changed, why it was selected, what is
happening, what failed or needs review, and what command advances it. Provider
payloads, raw subprocess output, full patches, and evidence internals remain
one deliberate expansion away.

### Reports are an inbox

Running `aos maintain` with no subcommand is a read-only home view over the
latest cached inventory projection and observations. It performs neither Nix
evaluation nor network refresh, so it remains usable when those tools are
unavailable. The heading always shows the inventory's exact base/dirty-content
identity, observation retrieval time/age, and remaining freshness under policy.
Stale required evidence renders `DISCOVERY UNKNOWN`, never `CURRENT`, while a
stale former candidate may remain visible as non-selectable context. If no cache
exists, the home view prints exact `inventory` and `scan` commands.

```text
AOS maintenance
Inventory  91c2f63a53d93a8f630dfac0e35ce4db890d98fe
Observed   2026-09-03T15:00:00Z · age 3h · valid for 21h

Updates  18 available   3 unknown   2 quarantined   4 active runs

UNIT       CURRENT   CANDIDATE   STREAM     RISK     DISCOVERY / RUN
bazel-7    7.6.2     7.6.3       >=7,<8     normal   UPDATE-AVAILABLE
bazel-8    8.4.2     8.4.3       >=8,<9     high     UPDATE-AVAILABLE / MATERIALIZING
openssl    3.5.1     3.5.2 stale  3.5 LTS     high     UNKNOWN / BLOCKED-HUMAN

next: aos maintain report --outdated
      aos maintain status --active
```

Default ordering is actionable state, risk, then unit identity. Filters are
composable, stable, and reflected in report headings. A family view keeps
concurrent major streams adjacent without implying that one supersedes the
others.

### Semantic diff precedes text diff

`aos maintain diff RUN` first renders the declared meaning of the change:

```text
bazel-8 · plan 01K4D9H1ER9R2AJZ2WQ6K2YQVA
Candidate tree sha256:8d8e20c8fabe53287736f793d9be77cd79ddba77b81e844cb05ea0759cf278f1

Component bazel
  identity       8.4.2 -> 8.4.3
  source hash    sha256-A... -> sha256-B...
  assurance      origin-integrity

Derived inputs
  MODULE.bazel.lock   regenerated by bazel-lock/v1

Impact
  1 member · 34 reverse dependencies · 4 targets · risk HIGH

Policy
  authored fields  3/3 allowed
  derived paths    1/1 allowed
  feature/dependency/license changes  none
```

The default `diff` output is the human semantic report only. `--semantic`
selects that same report explicitly; `--patch` writes only valid unified patch
bytes to stdout; and `--json` returns separate structured semantic fields plus
the patch digest. These selectors are mutually exclusive, and the command never
prompts to choose a renderer. A semantic summary can never hide an out-of-scope
textual delta; the policy verifier must have classified every changed path
first.

## Command ergonomics

The commands in the architecture chapter are grouped in `--help` under
`Discover`, `Update`, `Inspect`, and `Handoff`. Common selectors have the same
spelling everywhere. Unit, family, component, plan, run, gate, and attempt are
not called generically "package" or "job" when their distinction matters.

Interactive selection is a convenience over explicit arguments:

- omitting a run ID may open a searchable choice only when stdin and stderr
  are TTYs and the choice is unambiguous in scope;
- a non-interactive invocation receives a typed error and exact candidate
  commands instead of a guessed "latest" run;
- every selectable path has an equivalent flag-driven invocation;
- shell completions cover enum values and safely discoverable local IDs;
- `--help` includes the effect class and a short example for state-changing
  commands.

`aos maintain status` is concise; `status RUN` shows the current task tree;
`inspect RUN` owns full history, attempts, logs, budgets, and evidence. Logs are
stage-addressable (`inspect RUN --log GATE`) and follow a bounded tail by
default. Full retained logs require an explicit flag or artifact path.

Every paused or final result ends with one to three exact next commands. The
list is computed from legal workflow transitions, not copied into error strings.
On failure it includes the most useful inspection command before a retry.

`NextAction.argv` stores an argument vector, not a shell string. It carries
every nondefault `--repo`, `--state-dir`, and other non-secret selector required
to find the same repository and durable object from another directory. Human
output renders that vector with one tested POSIX-shell quoting routine; JSON
retains the original string array. Credentials and credential-source values are
never printed as next-command arguments.

### Selector and output contract

The first parser implementation locks these forms rather than relying on
examples to invent flags:

| Form | Selection and output |
| --- | --- |
| `maintain status [RUN]` | Without a run, lists local projected state; with an exact ID or interactive-only unambiguous prefix, prints that run. |
| `maintain status --active` | Mutually exclusive with `RUN`; lists nonterminal runs only. |
| `maintain inspect RUN` | Full bounded local history/evidence view. |
| `maintain inspect --plan PLAN` | Mutually exclusive with `RUN`; prints the immutable pre-execution plan. |
| `maintain inspect RUN --failure` | Focuses the latest failed/action-required operation while retaining run identity and next actions. |
| `maintain inspect RUN --log GATE` | Prints a bounded sanitized tail for the named planned gate. |
| `maintain inspect RUN --log-file GATE` | Prints only the retained log path; mutually exclusive with `--log` and valid only when policy retained the file. |
| `maintain diff RUN` / `--semantic` | Prints only the semantic human view. |
| `maintain diff RUN --patch` | Prints only unified patch bytes; no heading, prompt, color, or progress reaches stdout. |
| `maintain run UNIT --until STAGE` | `STAGE` is one of `worktree-ready`, `materialized`, `policy-valid`, or `quick-gated`; later boundaries require explicit accept/commit/test commands. |
| `maintain ui [RUN]` | Opens the optional local navigator; it does not accept a non-TTY or machine renderer. |

`--repo PATH` and `--state-dir PATH` are family-global context selectors.
Defaults are repository discovery from the current directory and the documented
repository-bound XDG state root. `--offline` belongs to `scan`; concurrency and
agent-profile flags belong only to commands that use them. Help groups these
separately from output selection and prints the enum values.

## Key interaction flows

### Plan preview

Planning is repository- and upstream-read-only: its only write is the immutable
plan record under local maintenance state. It cannot create a worktree, edit
the checkout, perform discovery or source network I/O, run hooks, or obtain
publication credentials. It consumes a recorded discovery snapshot. The
preview binds every fact that execution will rely on:

```text
Plan 01K4D9H1ER9R2AJZ2WQ6K2YQVA · bazel-8
  Digest       sha256:7f4c2ad97d5a1a0732c74df1e573681b475145191df4f810d8372f403973911d
  Change       8.4.2 -> 8.4.3
  Source       GitHub release v8.4.3
  Requires     origin-integrity
  Writes       3 declared fields · 1 generated input
  Impact       1 member · 34 reverse dependencies · 4 targets
  Risk         HIGH · patch stack and wide reverse closure
  Gates        27 planned · KVM available
  Budget       2 repair attempts · 45 min · 8 GiB

next: aos maintain run --plan 01K4D9H1ER9R2AJZ2WQ6K2YQVA
      aos maintain inspect --plan 01K4D9H1ER9R2AJZ2WQ6K2YQVA
```

In a TTY, `run UNIT` may create this preview and offer `run`, `details`, or
`quit`; it has no approval default. Choosing `run` records the exact full plan
digest. In a non-interactive terminal, implicit planning stops with
`ACTION REQUIRED`; execution requires
`run --plan FULL_ID --confirm-plan SHA256`, so a newly changed plan cannot
inherit an earlier approval and a plan ID is never mistaken for its digest.

### Live run

```text
bazel-8 · attempt 2 · run 01K4D9HMR09Q6S37FX9PWGCM8A · head 7c91e42

[COMPLETED] Resolve upstream                 1.2s
[COMPLETED] Materialize declared inputs     48.1s
[COMPLETED] Apply semantic source edit       0.4s
[COMPLETED] Evaluate inventory               3.8s
[RUNNING  ] Quick gates                     02:14
            package bazel-8                 [=========>------] 6/10
            reverse dependencies            [====>-----------] 3/12
[PENDING  ] Final gates

Budget  18m/45m · 3.1/8 GiB · repairs 1/2
Ctrl-C checkpoints and stops
```

Only active children redraw. Completed steps are stable. Agent work appears as
ordinary controller-owned stages such as `inspect failure`, `request patch`,
`verify patch`, and `await expanded-scope decision`; the model's prose or task
list cannot overwrite controller state.

### Action-required card

```text
ACTION REQUIRED  AOS-MAINT-241
Patch no longer applies: patches/use-aos-toolchain.patch

Run      01K4D9HMR09Q6S37FX9PWGCM8A
Run state blocked-human
Operation repair / bazel-8
Kept     worktree, patch, failed command log, completed gate evidence
Invalid  final gates have not run

next: aos maintain inspect 01K4D9HMR09Q6S37FX9PWGCM8A --failure
      aos maintain repair 01K4D9HMR09Q6S37FX9PWGCM8A
      aos maintain abandon 01K4D9HMR09Q6S37FX9PWGCM8A
```

Diagnostics use stable AOS-owned codes. When a package declaration is the
cause, rich output may include a source span and help text; plain and machine
forms retain the same code and remediation.

### Resume reconciliation

`resume` never silently adopts a tree, chooses a new upstream version, or
replans. It first prints a reconciliation receipt:

```text
Resume 01K4D9HMR09Q6S37FX9PWGCM8A
  Receipt       sha256:d4671c24403d195fb43c876f803b3437659283503dd170b0f40fbdaabea49d8c
  Plan          01K4D9H1ER9R2AJZ2WQ6K2YQVA unchanged
  Base          91c2f63a53d93a8f630dfac0e35ce4db890d98fe unchanged
  Candidate     7c91e42be523a0b1ef47c87c73da9e0caf829274 unchanged
  Worktree      clean at expected tree
  Last durable  quick-gate-started #184
  Recovery      interrupted child absent; gate will restart

Continue from quick gates? [c] continue  [d] details  [q] quit
```

Any mismatch becomes a separate explicit action: adopt a verified human tree,
restore a retained attempt, rebase into a new plan, or abandon. There is no
generic "continue anyway."

### Candidate and final receipts

After deterministic materialization and quick gates, the tool stops in the
actual `quick-gated` run state. No commit-specific final gate is claimed:

```text
ACTION REQUIRED · RUN quick-gated
bazel-8 8.4.2 -> 8.4.3

Run       01K4D9HMR09Q6S37FX9PWGCM8A
Tree      sha256:0a7d259c85ded334f43fc3be65a7e796c073f492567a32e81a49ae00971dcc5b
Quick     11 success · 0 failure · exact candidate tree
Final     not run; requires accepted and committed candidate

next: aos maintain diff 01K4D9HMR09Q6S37FX9PWGCM8A
      aos maintain accept 01K4D9HMR09Q6S37FX9PWGCM8A
```

After acceptance, commit, and complete commit-bound final gates, the distinct
receipt reflects the `ready-for-pr` state:

```text
READY FOR PR · RUN ready-for-pr
bazel-8 8.4.2 -> 8.4.3

Run       01K4D9HMR09Q6S37FX9PWGCM8A
Head      7c91e42be523a0b1ef47c87c73da9e0caf829274
Tree      sha256:0a7d259c85ded334f43fc3be65a7e796c073f492567a32e81a49ae00971dcc5b
Gates     27 success · 0 failure · exact committed head
Evidence  /home/maintainer/.local/state/aos/maintain/.../final-evidence.json
Elapsed   31m 08s

next: aos maintain prepare-pr 01K4D9HMR09Q6S37FX9PWGCM8A
      aos maintain publish-pr 01K4D9HMR09Q6S37FX9PWGCM8A
```

Receipts name the exact object and workflow state that passed. They never
collapse `unknown`, a missing target/KVM capability, or a stale head into
success.

### Publication preview

Before a remote mutation, `publish-pr` leaves the alternate screen if active
and shows an ordinary scrollback-preserving effect card:

```text
Publish pull request
  Run          01K4D9HMR09Q6S37FX9PWGCM8A
  Tested head  7c91e42be523a0b1ef47c87c73da9e0caf829274
  Remote       github.com/andyl-technologies/aos
  Ref          refs/heads/dplecki/upgrade-bazel-8
  Base         main @ 91c2f63a53d93a8f630dfac0e35ce4db890d98fe
  PR content   sha256:3ec522e9b26cb445ddf1a46725701095ab8fc661099b9e8a3ff16beb6112c49d
  Operation    create pull request against main
  Recovery     branch/PR may be closed, but pushed objects, audit records,
               notifications, and review history may persist

[p] publish exact head  [d] review title/body/diff  [q] quit
```

The approval binds the displayed head, ref, remote, base, title/body digest,
and operation. A stale value invalidates it. There is no global `--yes`,
"always allow," or post-effect confirmation.

## Approval rules

The following transitions require an explicit maintainer action: begin an
implicitly created plan; accept an expanded scope/risk plan; adopt human
worktree changes; accept the exact candidate tree; commit that tree; publish
the exact head; and clean retained state that cannot be reconstructed.

A confirmation view includes:

1. the plan/tree/head digest and full affected scope;
2. external and local effects;
3. irreversibility, available recovery actions, and retained recovery data;
4. the reason approval is needed;
5. evidence invalidated by proceeding;
6. safe alternatives and the quit path.

Prompts run only when stdin and stderr are interactive and human rendering is
active. EOF, unreadable input, an unknown response, or an empty response fails
closed. Enter and Escape never approve. Risky transitions use an explicit
letter or typed phrase; automation uses operation-specific, digest-bound
arguments where policy permits it. Commit and publication are interactive-only
in v1. Broad approval flags and approvals that survive a changed
plan/tree/head are forbidden.

| Transition | Interactive form | Permitted non-interactive form |
| --- | --- | --- |
| Execute immutable plan | `run --plan PLAN`, then confirm the displayed digest | `run --plan PLAN --confirm-plan PLAN_DIGEST` |
| Resume after reconciliation | `resume RUN`, then confirm the displayed receipt | `resume RUN --confirm-recovery RECEIPT_DIGEST` |
| Accept candidate tree | `accept RUN`, then confirm the displayed tree | `accept RUN --confirm-tree TREE_DIGEST` |
| Adopt human work | `accept RUN --adopt-worktree`, then confirm new semantic/tree digest | Same command plus `--confirm-tree TREE_DIGEST` |
| Accept expanded scope | Execute the new immutable plan generation | `run --plan NEW_PLAN --confirm-plan NEW_PLAN_DIGEST` |
| Commit exact tree/message | `commit RUN`, with an exact preview and explicit prompt | Not supported in v1. |
| Publish exact head/PR | `publish-pr RUN`, with an exact effect preview and explicit prompt | Not supported in v1. |
| Clean reconstructible state | `clean RUN`, then confirm the deletion manifest | `clean RUN --confirm-clean MANIFEST_DIGEST` when policy marks every target reconstructible. |

The confirmation flags are accepted only by their named command, never stored
as standing policy, and are rejected if any bound value or precondition differs.
Machine-mode `next_actions` includes the required full IDs, context selectors,
and digest argument when non-interactive continuation is permitted. Otherwise
it marks the action `interactive_required` without suggesting an unusable flag.

## Interruption and terminal lifecycle

The first Ctrl-C requests graceful cancellation. The controller stops
scheduling new work, terminates and reaps the complete active worker tree,
flushes bounded logs, appends the interruption and recovery transition, then
prints the exact resume command. While cleanup runs, the UI says what it is
waiting for and how long it has waited.

A second Ctrl-C requests forceful local teardown. If durable reconciliation
cannot prove the result, the command returns `INTERRUPTED` with an unknown
worker/effect state, never success. The next invocation must reconcile it.

All cursor/raw-mode behavior uses one tested RAII terminal guard. Panic, error,
signal, and normal exit restore cursor visibility, raw mode, alternate screen,
and progress suspension in a defined order. Full-screen actions return to the
normal screen before showing approval or invoking an editor/pager.

## Optional full-screen cockpit

`aos maintain ui [RUN]` is a read-only navigator over the same typed projections
used by `status`, `report`, and `inspect`. It is useful when comparing many
streams or following a long task graph:

```text
+ Updates (18) | Runs (4) ---------------- AOS maintenance -- base 91c2f63 +
| FILTER /bazel                                                               |
| bazel-7   UPDATE-AVAILABLE 7.6.2 -> 7.6.3 | bazel-8 · RUN materializing     |
| bazel-8   MATERIALIZING   8.4.2 -> 8.4.3 | attempt 2                        |
| bazel-9   CURRENT    9.0.0           | [COMPLETED] source/materialize/edit  |
|                                        | [RUNNING  ] quick gates 9/22        |
|                                        | [PENDING  ] final gates             |
|                                        +--------------------------------------|
|                                        | Failure/log/evidence preview         |
+ / search  Enter inspect  d diff  l logs  n next command  ? help  q quit ----+
```

The task graph, selection, filters, and detail panes are views, not a second
state machine. No key mutates state or dispatches another command. The cockpit
can display the exact next command; the maintainer exits and runs it through the
ordinary typed command and confirmation path. Resize is lossless. Search and
navigation have visible focus; all keys appear in help; mouse input is optional.

The cockpit requires stdin and stdout TTYs and refuses `--screen-reader`, JSON,
or JSONL modes with an exact equivalent command suggestion. Ratatui's test
backend snapshots the buffer at supported widths, but complete plain/JSON
functionality remains mandatory.

## Rust implementation choices

AOS already owns the essential stack. The implementation should strengthen it
behind AOS-specific interfaces rather than allow third-party widgets to define
the product contract.

| Concern | Choice | Reason |
| --- | --- | --- |
| Parsing/help/completions | Existing `clap` derives | One discoverable command tree and shell completion path already exist. |
| Styling/width | Existing `console` behind `Printer` | Keeps color and display-width policy centralized. |
| Progress | Existing `indicatif::MultiProgress` | Supports bounded nested activity and safe stable-line printing; evaluate the 0.17-to-0.18 upgrade separately with rendering tests. |
| Terminal detection | `std::io::IsTerminal` plus an injected capability snapshot | Replaces [`atty`, which is unmaintained](https://rustsec.org/advisories/RUSTSEC-2024-0375.html), and prevents inconsistent ambient checks. |
| Diagnostics | AOS `Diagnostic` rendered through `miette` where source spans help | AOS codes/schema remain authoritative; use miette's narratable/ASCII theme in accessible output. |
| Prompts | Small AOS `Prompter` interface | Exact effect/digest semantics remain testable. Add `dialoguer` with minimal features only if fuzzy selection materially improves the real workflow. |
| Tables/cards | AOS view model rendered with `console` display width | Avoids fixed-width format strings and a second terminal backend; spike a table crate only if fixtures prove the need. |
| Full-screen view | Workspace-pinned `ratatui` and `crossterm` | Reuses the `aos doc` stack and allows `TestBackend` snapshots without making the view mandatory. |
| CLI contract tests | `trycmd` as a development dependency | Exercises help, stdin, exit status, stdout/stderr, and filesystem fixtures as one user-facing contract. |

`cliclack` and JavaScript's Clack prompts are useful visual references for
intro/outro cards, grouped tasks, and concise prompts, but would duplicate
AOS's existing output stack. Ink demonstrates the value of componentized,
state-derived terminal views, not a runtime choice for this Rust CLI. The newer
`cli-ui` crate replaces rather than complements `clap`, so it is not adopted.
`tracing` remains implementation diagnostics; tracing spans are not converted
implicitly into user progress or durable workflow events.

`anstream` is a credible general output layer, but running it beside `console`
would create two color/capability policies. `comfy-table` is likewise deferred:
the semantic table/card model is useful, while its terminal backend and width
choices should not determine AOS state or force a Crossterm upgrade. AOS also
does not adopt `tracing-indicatif`; presentation stages are explicit events,
not an accidental projection of tracing span topology.

Relevant upstream references are the
[`indicatif::MultiProgress` API](https://docs.rs/indicatif/latest/indicatif/struct.MultiProgress.html),
[`dialoguer` prompt library](https://docs.rs/dialoguer/latest/dialoguer/),
[`miette` diagnostic renderer](https://docs.rs/miette/latest/miette/),
[`ratatui::backend::TestBackend`](https://docs.rs/ratatui/latest/ratatui/backend/struct.TestBackend.html),
[`trycmd` CLI fixture runner](https://docs.rs/trycmd/latest/trycmd/),
[`std::io::IsTerminal`](https://doc.rust-lang.org/std/io/trait.IsTerminal.html),
[`cliclack`](https://docs.rs/cliclack/latest/cliclack/),
[anstream](https://docs.rs/anstream/latest/anstream/),
[comfy-table](https://docs.rs/comfy-table/latest/comfy_table/),
[Clack](https://bomb.sh/docs/clack/packages/prompts/), and
[Ink](https://github.com/vadimdemedes/ink).

## Exit dispositions

Maintenance results use typed dispositions and preserve AOS's established
general exit meanings:

| Code | Disposition |
| --- | --- |
| `0` | The requested operation completed successfully. |
| `1` | A package gate, build, test, or candidate operation failed. |
| `2` | Invocation or input is invalid. |
| `3` | Required local infrastructure or tooling is unavailable. |
| `10` | Complete discovery found no selectable change. |
| `11` | A specific human action or host capability is required. |
| `12` | Required upstream evidence is unknown or incomplete. |
| `13` | The unit/candidate/run is quarantined. |
| `14` | The immutable plan or candidate head is stale. |
| `130` | The foreground operation was interrupted and is resumable or requires reconciliation. |

These are `MaintainDisposition` values, not synthetic string errors. Human and
machine renderers receive the same disposition. A command that reports data
about a quarantined run may still succeed; the disposition describes the
requested operation rather than blindly mirroring the stored object's state.

Command families apply them consistently:

| Command class | Exit rule |
| --- | --- |
| `inventory`, `status`, `inspect`, `diff`, `report`, `evidence`, `prepare-pr` | Exit `0` when the requested local query/render succeeds, including an empty report or an object whose stored state is failed/quarantined. Object states remain in result data. Invalid input and unavailable required local tooling use `2`/`3`. |
| `inventory --check` | Exit `0` for a valid complete inventory, `1` for a completed check with policy/schema findings, `2` for invalid invocation, and `3` when evaluation tooling is unavailable. |
| `scan` | After invocation/tool errors, aggregate required unit results by precedence: any quarantine `13`; otherwise any required unknown/incomplete evidence `12`; otherwise no selectable changes `10`; otherwise `0`. The result always contains counts for every category, so a higher-precedence code does not hide mixed results. |
| `plan` | Exit `0` when a plan is created, `10` for proven no-change, `12` for insufficient upstream evidence, `13` for quarantine, and `14` when the selected snapshot/base/policy is stale. |
| `run`, `resume`, `test`, `repair`, `accept`, `commit`, `publish-pr` | Exit for the requested transition: `0` completed; `1` executed but its candidate/gate failed; `3` required local infrastructure unavailable; `11` decision/capability required; `12` upstream proof incomplete; `13` quarantined; `14` bound object stale; `130` handled interruption. |
| `observe-pr` | Exit `0` when the exact-head remote observation is fetched and recorded, even when required checks/reviews remain pending or failed; those states are result data. Authentication/transport unavailability uses `3`, and a mismatched expected head uses `14`. |
| `ui` | Exit `0` on an ordinary quit, `2` for an incompatible terminal/output selection, and `3` when required local state cannot be read. |
| `abandon`, `clean` | Exit `0` only after the requested local transition completes; refusal/action requirement uses `11`, and invalid or unavailable context uses `2`/`3`. |

Validation of arguments precedes domain aggregation. A command that fails
before it can classify its requested objects returns `2` or `3`, not a guessed
domain state. `scan`'s quarantine-before-unknown precedence is solely an exit
choice; both remain equally visible and fail-closed in its report.

## Verification

Presentation is tested as a compatibility surface, not judged only by manual
inspection:

- pure view-model snapshots at widths 40, 79, 80, 119, 120, and 160;
- Unicode/color, ASCII/no-color, screen-reader, and plain fixtures;
- `trycmd` fixtures for help, simple stdin cases, stdout/stderr ownership, and
  exact stable command output;
- direct built-binary subprocess tests for exit dispositions, one-document
  JSON, JSONL truncation, non-TTY prompts, EOF, broken pipes, and exact next
  commands;
- semantic JSON assertions and backward-compatibility fixtures for final
  results and JSONL events, including the terminal event on every handled,
  writable-output path and missing-terminal-event reconciliation;
- fake clocks, IDs, providers, process results, and terminal capabilities so
  golden output contains no unstable wildcard regions;
- process-group signal/kill/restart tests proving cleanup, journaling, and
  resume receipts;
- Ratatui `TestBackend` snapshots and a dedicated pseudo-terminal lifecycle
  harness if the cockpit is implemented;
- secret canaries, hostile control characters, OSC-8/ANSI injection, very long
  untrusted values, wide/combining Unicode, and terminal resize cases;
- output-volume budgets for progress, warnings, repeated failures, and logs.

Golden fixtures normalize temporary roots and elapsed values at the typed data
boundary. They are never updated automatically in validation. Reviewers see UI
changes in the same pull request as the semantic change that caused them.

The M0 usability check is a real maintainer rehearsal: from a cached report,
the maintainer can identify one update, understand and start its plan, follow
its work, inspect a failure, interrupt/resume it, and find the candidate diff
without reading implementation logs or guessing a command. M2 repeats the
exercise for a concurrent-major family and a multi-component unit; M3 adds a
bounded repair and expanded-scope decision; M4 adds exact-head publication.
