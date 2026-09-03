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
workflow types:

```text
MaintenanceEvent
  sequence, time, run/attempt identity, kind, bound object digests, payload

MaintenanceView
  title, summary fields, sections, task tree, diagnostics, available actions

MaintainCommandResult
  schema, command, disposition, primary values, warnings, next actions

Diagnostic
  stable code, severity, summary, detail, source span, remediation

NextAction
  label, argv, reason, prerequisites, effect class
```

The controller emits state-transition events. A reducer builds the current
view from journaled state; renderers do not infer state by parsing subprocess
logs. The journal/evidence sink, bounded command-log sink, and active human or
machine renderer receive the same typed events:

```text
controller event
  +-- durable journal and evidence
  +-- bounded, sanitized command log
  `-- human / JSONL presentation
```

Every command returns exactly one `MaintainCommandResult` to the process
boundary. That is important because the existing general-purpose `Printer`
allows commands to print incremental JSON fragments. Maintenance commands must
instead render one final JSON document or one explicitly selected JSONL event
stream. A successful subprocess exit is an observation, not a workflow result;
only the state reducer produces the command disposition.

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
selected for non-TTY stderr and by `--progress plain`. Long operations emit a
stage transition immediately and then bounded heartbeats using the existing
AOS interval/proportional policy. Repeated log lines and rapidly changing
counters are coalesced.

At narrow widths, records replace columns:

```text
UPDATE bazel-7 7.6.2 -> 7.6.3 READY
UPDATE bazel-8 8.4.2 -> 8.4.3 RUNNING stage=quick-gates elapsed=2m14s
UPDATE qemu 10.0.0 -> 10.1.0 BLOCKED reason=policy-major
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
`--jsonl` for a versioned stream of `MaintenanceEvent` objects. A JSONL stream
always ends with a `result` event carrying the same disposition and next
actions as the one-document result, including after a handled interruption or
failure.

Machine modes never prompt, page, open an editor, emit terminal control
sequences, or fall back to `/dev/tty`. Durations are integer milliseconds.
Timestamps, run IDs, digests, enum values, and argument arrays are typed rather
than embedded in prose. Unknown fields follow the schema's stated compatibility
rules; event sequence numbers are monotonic within one invocation and bind the
run and attempt when those objects exist.

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
    "stage": "repair"
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

## Information design

### Status vocabulary

All views use the same textual states:

| State | Meaning |
| --- | --- |
| `CURRENT` | Complete evidence proves there is no in-policy update. |
| `UPDATE` | A selectable candidate exists but has no plan. |
| `PLANNED` | An immutable plan exists and has not begun. |
| `RUNNING` | The foreground command is advancing the run. |
| `ACTION REQUIRED` | A named human decision or host capability is required. |
| `READY` | The exact candidate tree is ready for its next explicit handoff. |
| `PASS` / `WARN` / `FAIL` | A completed check's typed outcome. |
| `UNKNOWN` | Evidence is insufficient to make the requested claim. |
| `QUARANTINED` | Policy forbids automatic advancement pending review. |
| `INTERRUPTED` | Work stopped with a recorded recovery state. |

Rich mode may prefix these with distinct symbols and colors, but the word is
always present. `UNKNOWN` is never visually softened into success, and
`ACTION REQUIRED` is not presented as an ordinary command failure.

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
current inventory and cached observations. It performs no refresh. If no cache
exists, it prints the exact `aos maintain scan` command.

```text
AOS maintenance                                      base 91c2f63

Updates  18 ready   3 unknown   2 quarantined   4 active runs

UNIT       CURRENT   CANDIDATE   STREAM     RISK     STATE
bazel-7    7.6.2     7.6.3       >=7,<8     normal   UPDATE
bazel-8    8.4.2     8.4.3       >=8,<9     high     RUNNING
openssl    3.5.1     3.5.2       3.5 LTS     high     ACTION REQUIRED

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

The command then offers or prints the unified patch. `--semantic`, `--patch`,
and `--json` select deterministic views without changing the candidate. A
semantic summary can never hide an out-of-scope textual delta; the policy
verifier must have classified every changed path first.

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
`ACTION REQUIRED`; execution requires `run --plan FULL_ID`, so a newly changed
plan cannot inherit an earlier approval.

### Live run

```text
bazel-8 · attempt 2 · run 01K4D9HMR09Q6S37FX9PWGCM8A · head 7c91e42

[PASS] Resolve upstream                 1.2s
[PASS] Materialize declared inputs     48.1s
[PASS] Apply semantic source edit       0.4s
[PASS] Evaluate inventory               3.8s
[RUN ] Quick gates                     02:14
       package bazel-8                 [=========>------] 6/10
       reverse dependencies            [====>-----------] 3/12
[WAIT] Final gates

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
Stage    quick-gates / bazel-8
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

### Completion receipt

```text
READY  bazel-8 8.4.2 -> 8.4.3

Run       01K4D9HMR09Q6S37FX9PWGCM8A
Tree      sha256:0a7d259c85ded334f43fc3be65a7e796c073f492567a32e81a49ae00971dcc5b
Gates     27 PASS on commit 7c91e42be523a0b1ef47c87c73da9e0caf829274
Evidence  ~/.local/state/aos/maintain/.../final-evidence.json
Elapsed   31m 08s

next: aos maintain diff 01K4D9HMR09Q6S37FX9PWGCM8A
      aos maintain accept 01K4D9HMR09Q6S37FX9PWGCM8A
```

Receipts name the exact object that passed. They never collapse `UNKNOWN`, a
missing target/KVM capability, or a stale head into success.

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
  Reversible   branch/PR may be closed; no force push or merge

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
3. reversibility and retained recovery data;
4. the reason approval is needed;
5. evidence invalidated by proceeding;
6. safe alternatives and the quit path.

Prompts run only when stdin and stderr are interactive and human rendering is
active. EOF, unreadable input, an unknown response, or an empty response fails
closed. Enter and Escape never approve. Risky transitions use an explicit
letter or typed phrase; automation uses operation-specific, digest-bound
arguments where policy permits it. Initial publication may remain interactive
only. Broad approval flags and approvals that survive a changed plan/tree/head
are forbidden.

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
| bazel-7   UPDATE     7.6.2 -> 7.6.3 | bazel-8 · RUNNING · attempt 2        |
| bazel-8   RUNNING    8.4.2 -> 8.4.3 |                                      |
| bazel-9   CURRENT    9.0.0           | [PASS] source/materialize/edit       |
|                                        | [RUN ] quick gates 9/22             |
|                                        | [WAIT] final gates                  |
|                                        +--------------------------------------|
|                                        | Failure/log/evidence preview         |
+ / search  Enter inspect  d diff  l logs  r resume  ? help  q quit ----------+
```

The task graph, selection, filters, and detail panes are views, not a second
state machine. A key that requests a mutation exits or suspends the cockpit,
routes through the ordinary typed command and confirmation path, and can then
reopen the view. Resize is lossless. Search and navigation have visible focus;
all keys appear in help; mouse input is optional.

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

## Verification

Presentation is tested as a compatibility surface, not judged only by manual
inspection:

- pure view-model snapshots at widths 40, 79, 80, 119, 120, and 160;
- Unicode/color, ASCII/no-color, screen-reader, and plain fixtures;
- `trycmd` fixtures for help, stdout/stderr ownership, exit dispositions,
  prompts, EOF, non-TTY use, broken pipes, and exact next commands;
- semantic JSON assertions and backward-compatibility fixtures for final
  results and JSONL events, including the mandatory final event;
- fake clocks, IDs, providers, process results, and terminal capabilities so
  golden output contains no unstable wildcard regions;
- signal/kill/restart tests proving cleanup, journaling, and resume receipts;
- Ratatui `TestBackend` snapshots and one pseudo-terminal lifecycle smoke test
  if the cockpit is implemented;
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
