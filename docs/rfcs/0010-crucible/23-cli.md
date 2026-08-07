# 23 — The `crucible` CLI

This file specifies the **`crucible` command-line interface**: the operator's
front door to a Crucible run. Where the session (20) is the control-plane actor
and the API (21) is the programmatic surface over it, the CLI is the thin,
human-facing wrapper that turns a shell invocation into a sequence of session
commands (20 §4) — locally in-process, or remotely against a daemon (21).

The CLI exists so that the most common operator workflows — run a scenario,
prove it is deterministic, save a point, resume or fork from it, replay a
failure bit-identically, and drive exploration — are one command each, with
copy-pasteable reproduction built in. It is **not** a second control plane: it
holds no run state of its own, implements no scheduling, no fork logic, and no
determinism mechanism. Every subcommand maps to operations the session (20) and
API (21) already define; the CLI's only added value is ergonomics, discovery,
and the determinism-first defaults that make reproduction free
([G-6]). Requirement IDs here use the prefix `CLI`.

Forward and cross references: the session control plane is
[`20-session-control-plane.md`](20-session-control-plane.md); the programmatic
API the CLI wraps is `21-api.md`; advanced features (state-space search,
coverage-guided fuzzing) the `search`/`fuzz` subcommands drive are
`22-advanced-features.md`; the `ScenarioDef`, `ScenarioFamily`, and the
reproduction artifact are [`06-spatial-graph.md`](06-spatial-graph.md); the
temporal graph (checkpoints/savepoints) is
[`07-temporal-graph.md`](07-temporal-graph.md); the event log and its formats
are [`19-observability-event-log.md`](19-observability-event-log.md); the
divergence-bisection and fingerprint machinery `verify` leans on is
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md); the
patched QEMU and plugin discovery is `26-packaging-aos-integration.md`,
[`11-qemu-patches.md`](11-qemu-patches.md), and
[`12-qemu-plugin.md`](12-qemu-plugin.md); the gates this file's requirements
reference are catalogued in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1.

The canonical gates this file's requirements reference are `gate:e2e-determinism`
(reproduce-from-artifact, bit-identical across machine profiles),
`gate:replay-oracle` (replay/fork/resume reduce to the same state by hash), and
`gate:control-responsive` (remote/local control operations acknowledged within
a bounded number of quanta) — all defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1.1.

---

## 1. What the CLI is, and what it is not

The CLI is a **thin wrapper over the session (20) and the API (21)**. It does
exactly three things and nothing more:

1. **Parse** an operator's intent (a subcommand + flags) into a session command
   set (20 §4) or an API call sequence (21).
2. **Route** that intent to a backend: an *in-process* session (the
   `SimulationBackend` of 20 §10 — real QEMU for fidelity, or the `SimDouble`
   of 24 §3 for fast local checks), or a *remote* daemon over the API (21).
3. **Render** the result — the event-log stream (19), the run outcome (20 §2),
   the fingerprint/verdict, and, on any failure, a copy-pasteable reproduction
   command and a self-contained reproduction artifact (06 §7.1, 24 §12).

What the CLI is **not**: it is not a place where scheduling, forking, checkpoint
materialization, or any determinism mechanism lives. Those belong to the session
(20), the temporal graph (07), and the scheduler (08). If a behavior the CLI
exposes is not already an operation of the session command set (20 §4) or the
API (21), it is a layering defect, not a CLI feature.

- **[CLI-1]** The `crucible` CLI MUST be a thin wrapper over the session control
  plane (20 §4) and the API (21): every subcommand MUST decompose into session
  commands or API calls, and the CLI MUST NOT implement scheduling, fork/resume
  logic, checkpoint materialization, or any determinism mechanism of its own. A
  CLI behavior with no corresponding session/API operation is a layering defect.
  *Gate:* `gate:control-responsive`. *Spec:* §1; cross-ref 20 §4, 21.

- **[CLI-2]** The CLI MUST hold no canonical run state. Any state it needs
  between invocations (the last run's artifact, a savepoint handle, a daemon
  address) MUST be either a content-addressed reference into the store
  ([INV-6], 06, 07) or a connection handle to a daemon (21); the CLI MUST NOT be
  a second source of truth for a run. *Gate:* `gate:replay-oracle`. *Spec:* §1.

---

## 2. Top-level shape and global flags

The binary is `crucible`. Its top-level shape is a small set of subcommands plus
a global flag block. The global flags configure determinism inputs, backend
selection, plugin/QEMU discovery, and output rendering, and apply to every
subcommand that runs or talks to a session.

```text
  crucible [GLOBAL FLAGS] <SUBCOMMAND> [SUBCOMMAND FLAGS] [ARGS]

  SUBCOMMANDS
    run        Run a scenario to completion (local or via a daemon).
    verify     Prove determinism: run N times, diff fingerprints + causal logs.
    selftest   Run the determinism gates against a built-in scenario corpus.
    save       Run to a savepoint and export it as a resumable checkpoint.
    resume     Resume a run from a checkpoint or savepoint.
    fork       Fork a run from a savepoint with a new seed or decision override.
    replay     Replay a reproduction artifact, bit-identically.
    search     Drive state-space search over the schedule space (22).
    fuzz       Coverage-guided fuzzing over a scenario family (22).
    triage     Cluster, dedup, and minimize discovered failures (34).
    debug      Open the time-travel debugger at a coordinate (36).
    serve      Run the daemon hosting the API (21).
    completions  Generate shell completions.

  GLOBAL FLAGS (apply to run/verify/save/resume/fork/replay/search/fuzz/serve)
    --seed <u64|hex>        Root entropy (06 §5.3). Overrides CRUCIBLE_SEED.
    --backend <auto|qemu>          Local production backend (20 §10). Default: auto.
    --daemon <addr>         Talk to a daemon (21) instead of running in-process.
    --qemu <path>           Patched QEMU system binary (26). Else discovered.
    --plugin <path>         crucible-qemu-plugin cdylib (12, 26). Else discovered.
    --store <path>          Content-addressed store root (06, 07). Else default.
    --format <jsonl|json|table|markdown>    Trace/report render format. Default: jsonl.
    --trace <path>          Write the event-log stream here. Default: stdout.
    --artifact-dir <path>   Where failure artifacts are written. Default: ./.crucible.
    -v, --verbose           Increase log verbosity (repeatable: -vv).
    -q, --quiet             Suppress non-essential output.
```

The global flags are deliberately small and orthogonal: determinism inputs
(`--seed`), backend/transport selection (`--backend`, `--daemon`), hermetic
discovery (`--qemu`, `--plugin`, `--store`), and rendering (`--format`,
`--trace`, `--artifact-dir`, `-v`/`-q`). Everything else is per-subcommand.

- **[CLI-3]** The CLI MUST expose exactly the subcommand set `run`, `verify`,
  `selftest`, `save`, `resume`, `fork`, `replay`, `search`, `fuzz`, `triage`,
  `debug`, `serve`, and `completions`. Each subcommand MUST map to a defined
  session/API operation (§3–§16) or, for `triage`/`debug`, a thin driver over the
  triage engine (34) / debugger (36), and MUST NOT introduce a control-plane
  capability absent from 20/21/34/36.
  *Gate:* `gate:control-responsive`. *Spec:* §2; cross-ref 20 §4, 21, 22, 34, 36.

- **[CLI-4]** The global flags `--seed`, `--backend`, `--daemon`, `--qemu`,
  `--plugin`, `--store`, `--format`, `--trace`, `--artifact-dir`, and
  `-v`/`-q` MUST apply uniformly across the run-capable subcommands, with the
  same meaning everywhere. A subcommand MUST NOT redefine a global flag's
  meaning. *Spec:* §2.

- **[CLI-5]** When `--daemon <addr>` is given, the subcommand MUST execute
  against the remote daemon over the API (21) and MUST behave identically — same
  outputs, same exit codes, same artifacts — to a local run, except that node
  fidelity is whatever the daemon's backend provides. When `--daemon` is absent,
  the subcommand MUST run in-process against the local `SimulationBackend`
  selected by `--backend` (20 §10). *Gate:* `gate:control-responsive`. *Spec:*
  §2, §3; cross-ref 20 §10, 21.

### 2.1 Clap-derive doc discipline (this is user-facing surface)

The CLI is implemented with a derive-based argument parser, where the doc
comment on each subcommand container and each flag field becomes the `--help`
text. Per the repository's documentation standard, those comments are treated as
**user-facing CLI surface**, not internal rustdoc: the surrounding module is
documented with `//!`, the derive *containers* carry no `///` (that text would
leak into `--help`), and every flag/field doc is short, imperative, accurate,
and edited as a deliberate UI change. The `--help` text below for each
subcommand is the normative help copy.

- **[CLI-6]** Flag and subcommand help text MUST be authored as user-facing CLI
  copy: short, imperative, and accurate. Derive-container doc comments MUST NOT
  carry overview prose (it would surface in `--help`); the module overview lives
  in the module `//!` header instead. A change to a flag's help text MUST be
  treated as a user-facing CLI change (it is the rendered `--help`), and the
  help text MUST stay in sync with the flag's actual behavior. *Spec:* §2.1.

---

## 3. Backend selection and the local/remote split

Every run-capable subcommand resolves to *one session* (20) over *one backend*.
The resolution rule is uniform:

```text
  --daemon <addr> set?  ──yes──►  remote: open API client (21), submit to daemon,
       │                          stream the event log + state back; exit on outcome.
       no
       ▼
  --backend resolves a local SimulationBackend (20 §10):
    qemu    real patched QEMU (10, 26)   — full fidelity; needs QEMU + plugin (§5)
    auto    qemu if QEMU + plugin discover (§5), otherwise fail clearly
```

The `SimDouble` remains available to test targets compiled with the explicit
`test-double` Cargo feature. It is not part of a production binary's CLI surface
and production `auto` never degrades to it.

- **[CLI-7]** `--backend auto` (the default) MUST select the real QEMU backend
  when a patched QEMU and the plugin are discoverable (§5), announce that
  choice unless `-q`, and fail clearly (§5, exit 4) otherwise.
  `--backend qemu` has the same fail-closed discovery behavior. Production
  builds MUST NOT expose `--backend double`; test targets MAY expose it only
  through the explicit `test-double` Cargo feature. *Gate:*
  `gate:control-responsive`. *Spec:* §3, §5; cross-ref 20 §10, 24 §3.

- **[CLI-8]** A local run and a `--daemon` run of the same subcommand with the
  same flags MUST produce the same canonical event log (19) and the same outcome
  for a given backend fidelity, and MUST emit byte-identical reproduction
  artifacts (06 §7.1, 24 §12). The CLI MUST NOT make the remote path observably
  different from the local path beyond connection errors and backend fidelity.
  *Gate:* `gate:e2e-determinism`. *Spec:* §3; cross-ref 21.

---

## 4. Determinism ergonomics: the seed, the artifact, the repro command

This is the load-bearing section: the CLI's defaults are what make
"reproduce-then-explore" ([G-6]) the path of least resistance instead of an
afterthought. Three rules govern every run-capable subcommand.

**Rule 1 — the seed is always known and always printed.** The root entropy
(06 §5.3) comes from `--seed`, else the `CRUCIBLE_SEED` environment variable,
else a freshly *generated* seed. In all three cases the resolved seed is printed
at the start of the run, so a developer who ran without a seed can still
reproduce the exact run. A generated seed is drawn once, from a host entropy
source, *before* the run begins and then frozen into the `ScenarioDef`'s
identity (06 §5.3) — host entropy seeds the run's *identity*, never its
*execution* ([INV-1]).

```text
  $ crucible run cluster.scn
  crucible: seed not set; generated seed = 0x9f86d081884c7d65 (set CRUCIBLE_SEED to pin)
  crucible: backend = qemu (patched QEMU + plugin discovered)
  ... event log ...
  crucible: PASSED in 42.000s virtual time (1.2s wall), 3 nodes, 0 violations
```

**Rule 2 — a failure prints a copy-pasteable reproduction command and writes a
self-contained artifact.** When a run ends `Failed`, `Crashed`, or `Timeout`
(20 §2), the CLI writes the reproduction artifact `(seed, ScenarioDef,
Schedule)` (06 §7.1, 24 §12) to `--artifact-dir` and prints the exact `crucible
replay` command that re-runs it bit-identically. The developer copies one line
and reproduces the failure on any machine ([HARN-28]).

```text
  crucible: FAILED — property "no_split_brain" violated at virtual_time=12.4s, node=db-1
  crucible: wrote reproduction artifact ./.crucible/repro-2c26b4.crucible (4.1 KiB)
  crucible: reproduce with:
      crucible replay ./.crucible/repro-2c26b4.crucible
  crucible: debug at the failure with:
      crucible debug ./.crucible/repro-2c26b4.crucible --at-failure
  crucible: bisect against a passing run with:
      crucible verify cluster.scn --seed 0x9f86d081884c7d65 --runs 2
```

**Rule 3 — trace/event-log output has three formats.** For canonical event-log
rendering, the `--format` flag selects `jsonl` (one canonical event-log entry per
line, the default and the stream format), `json` (a single array, for tooling
that wants one document), or `table` (a human-readable column view: virtual time,
node, kind, summary). All three render the *same* canonical event log (19); the
observational/canonical distinction is by schema (19), so `--format` never
changes which entries appear, only how they are printed. `markdown` is reserved
for the offline `triage` report renderer (§16, 34 §34.5.2) and is not a
canonical event-log format.

- **[CLI-9]** The root seed MUST be resolved as `--seed`, else `CRUCIBLE_SEED`,
  else a freshly generated seed; and the resolved seed MUST be printed at run
  start (unless `-q`) so any run is reproducible. A generated seed MUST be drawn
  once before the run from a host entropy source and frozen into the
  `ScenarioDef` identity (06 §5.3); host entropy MUST seed only the run's
  identity, never its execution ([INV-1]). *Gate:* `gate:e2e-determinism`.
  *Spec:* §4; cross-ref 06 §5.3.

- **[CLI-10]** On any non-passing outcome (`Failed`, `Crashed`, `Timeout`;
  20 §2), the CLI MUST write a self-contained reproduction artifact `(seed,
  ScenarioDef, Schedule)` (06 §7.1, 24 §12) to `--artifact-dir` and MUST print a
  copy-pasteable `crucible replay <artifact>` command that reproduces the run
  bit-identically. The failure footer MUST additionally print a copy-pasteable
  `crucible debug <artifact> --at-failure` command (§16) that opens the
  time-travel debugger positioned at the violation. The printed commands and the
  artifact together MUST be sufficient to reproduce and debug with no other input
  ([HARN-27]). *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`. *Spec:* §4,
  §16; cross-ref 06 §7.1, 24 §12.

- **[CLI-11]** `--format` MUST support `jsonl` (one canonical event-log entry
  per line; the default and the streaming format), `json` (a single array), and
  `table` (a human-readable virtual-time / node / kind / summary view), all
  rendering the *same* canonical event log (19). `--format` MUST NOT change which
  entries are emitted — the canonical/observational split is by schema (19), not
  by format — only how they are rendered. The `jsonl` form MUST be a stream:
  entries are emitted as they are produced (via the session's event bus, 20 §9),
  not buffered to the end. `markdown` is a triage report format, not an event-log
  trace format. *Spec:* §4; cross-ref 19, 20 §9.

- **[CLI-12]** The CLI MUST NOT read host wall-clock on any path that feeds a
  run's canonical `State` ([INV-9]). Wall-clock MAY appear only in
  observational, render-only output (e.g. the "1.2s wall" summary line), behind
  output that cannot influence the canonical event log or the artifact. *Gate:*
  `gate:harness-lint`. *Spec:* §4; routes [INV-9].

---

## 5. Plugin and QEMU discovery (hermetic, fail-clear)

A QEMU-backed run needs two artifacts: the **patched QEMU system binary** (10,
11, 26) and the **`crucible-qemu-plugin` cdylib** (12, 26). The CLI discovers
both **hermetically** — from the AOS-built package set, not by groping `$PATH`
for whatever QEMU the host happens to have — and fails with a clear, actionable
message if either is absent. A run that silently used a wrong (unpatched, or
host) QEMU would violate patch-dependent determinism and the inertness contract
([INV-7]); discovery therefore prefers the pinned AOS build and records its
build identity into the artifact ([HARN-28]).

Discovery order for each of QEMU and plugin:

```text
  1. explicit flag        --qemu <path> / --plugin <path>
  2. environment          CRUCIBLE_QEMU / CRUCIBLE_PLUGIN
  3. AOS package set      the hermetic, content-addressed AOS QEMU package (26),
                          which co-locates the patched binary and the matching plugin
  4. (no host $PATH fallback for QEMU; the host's QEMU is never used)
```

The AOS-package step is the hermetic default and the one CI uses: the patched
QEMU and the plugin are built from source together (26), so their versions
match by construction and the build identity is content-addressed. The CLI MUST
verify the discovered QEMU is the patched build (it carries a sim-capability
marker per 11/26) and that the plugin's ABI version matches the host's
([HARN-32]); a mismatch fails rather than runs.

- **[CLI-13]** A QEMU-backed run MUST locate both the patched QEMU system binary
  (10, 11, 26) and the matching `crucible-qemu-plugin` cdylib (12, 26)
  hermetically, in the order: explicit `--qemu`/`--plugin`, then
  `CRUCIBLE_QEMU`/`CRUCIBLE_PLUGIN`, then the AOS-built package set (26). The
  host's `$PATH` QEMU MUST NOT be used as a fallback; an unpinned host QEMU is
  never a valid backend. *Gate:* `gate:e2e-determinism`. *Spec:* §5; cross-ref
  26, 11.

- **[CLI-14]** If a QEMU-backed run cannot discover a patched QEMU or the plugin,
  or if the discovered QEMU is not the patched build or the plugin's ABI version
  does not match the host ([HARN-32]), the CLI MUST fail with a clear, actionable
  message (which artifact is missing or mismatched, the discovery order tried,
  and how to supply it) and exit code 4 — never silently fall back to an
  unpatched or host QEMU, and never run with a mismatched plugin. *Gate:*
  `gate:e2e-determinism`. *Spec:* §5; cross-ref 26, [HARN-32], [INV-7].

- **[CLI-15]** The CLI MUST record the discovered AOS QEMU build identity and the
  plugin ABI version into every run's reproduction artifact (24 §12), so a later
  `replay` that would silently use a different binary fails loudly rather than
  reproducing something else ([HARN-28]). *Gate:* `gate:e2e-determinism`,
  `gate:replay-oracle`. *Spec:* §5; cross-ref 24 §12, [HARN-28].

---

## 6. `run` — run a scenario to completion

**Purpose.** Run one pinned `ScenarioDef` (06) to a terminal outcome (20 §2) and
report. The workhorse subcommand.

```text
  crucible run <SCENARIO> [FLAGS]

  ARGS
    <SCENARIO>   Scenario file (the canonical TOML form, 06 §6.1) or its content hash.

  FLAGS (subcommand-local; global flags from §2 also apply)
    --until <quiescence|virtual-time|property|stopped>   Terminal condition. Default: quiescence.
    --max-virtual-time <dur>   Stop with Timeout past this virtual time (20 §2).
    --max-quanta <n>           Stop with Timeout at this scheduler-quantum boundary.
    --interactive              Pause at genesis and drive the session interactively.
    --save-on <fail|always|never>   Materialize a savepoint at the outcome. Default: never.
    --watch                    Stream the live status line (20 §9) alongside the trace.
```

`run` constructs a local or remote session (§3), issues `start` then `continue`
(20 §4), streams the event log in `--format` (§4), and exits on the terminal
outcome. When `--max-quanta` is present, the CLI advances one paused quantum at
a time so the terminal coordinate cannot overshoot the requested bound.
`--interactive` instead leaves the session `Paused(Instantiated)` and
reads control commands (continue/pause/step/inject/heal/fork/save/query, 20 §4)
from stdin — the CLI face of the session command set, with each command
acknowledged within a bounded quantum count ([SESS-3], `gate:control-responsive`).
State queries render their returned lifecycle state. An accepted `stop`
preserves the joined actor's exact terminal snapshot across lifecycle registry
cleanup and returns it in the command response; the CLI uses that snapshot for
final outcome, configuration, savepoint, frontier, quanta, event-log draining,
and watch evidence, then stops reading stdin without requiring EOF.

**Exit codes.** `0` = `Passed`; `1` = `Failed` (property violation); `2` =
`Timeout`; `3` = `Crashed` / backend error; `4` = discovery/configuration error
(§5); `5` = invalid scenario (06 §9 build/validation error); `64` = usage error.

- **[CLI-16]** `crucible run <scenario>` MUST construct a session (local or
  remote, §3), issue `start` then `continue` (20 §4), stream the canonical event
  log in `--format` (§4), and exit on the terminal outcome (20 §2) with the exit
  code mapping `0=Passed`, `1=Failed`, `2=Timeout`, `3=Crashed/backend`,
  `4=discovery/config`, `5=invalid-scenario`, `64=usage`. `--interactive` MUST
  leave the session paused at genesis and accept the session command set
  (20 §4) from stdin, each acknowledged within a bounded number of quanta
  ([SESS-3]). On a non-passing outcome it MUST honor §4's artifact + repro-command
  rule ([CLI-10]). *Gate:* `gate:control-responsive`, `gate:e2e-determinism`.
  *Spec:* §6; cross-ref 20 §2, §4.

---

## 7. `verify` — prove determinism by repetition + diff

**Purpose.** The determinism workhorse: run the same `(ScenarioDef, seed)` `N`
times and assert every run produces byte-identical fingerprint streams (24 §4)
and byte-identical *canonical* causal logs (19); on any difference, localize the
first divergence with bisection (24 §5). This is the CLI face of
`gate:adversarial-determinism` / `gate:single-vm-fingerprint` for a developer's
own scenario.

```text
  crucible verify <SCENARIO> [FLAGS]

  FLAGS
    --runs <n>            Number of runs to compare. Default: 2.
    --adversarial         Run under the hostile host-condition matrix (24 §7).
    --bisect              On divergence, run divergence-bisection (24 §5) and print the report.
    --compare <a> <b>     Diff two existing reproduction artifacts instead of running.
```

`verify` runs `N` independent reductions (each its own session, §3), compares
their canonical logs and fingerprint streams pairwise, and — if any pair differs
— invokes the divergence-bisection tool (24 §5) to report the *first* differing
decision/instruction and node, with a both-sides state dump. `--adversarial`
runs them under randomized host scheduling, wall-clock jitter, and varied core
counts (24 §7) so the comparison actively *tries* to break determinism.
`--compare` consumes the identities recorded by its two artifacts and MUST NOT
draw or report a fresh run seed.

**Exit codes.** `0` = all runs byte-identical (deterministic); `1` = divergence
detected (the bisection report is printed and an artifact for each side is
written, §4); `4` = discovery/config error; `64` = usage error.

- **[CLI-17]** `crucible verify <scenario> --runs N` MUST execute `N` independent
  reductions of the same `(ScenarioDef, seed)`, compare their canonical event
  logs (19) and execution-fingerprint streams (24 §4) for byte-identity, and
  exit `0` iff all are identical and `1` on any divergence. On divergence it MUST
  run divergence-bisection (24 §5) to report the first differing
  decision/instruction and node and write a reproduction artifact for each side
  (§4). `--adversarial` MUST apply the hostile-condition matrix (24 §7). *Gate:*
  `gate:e2e-determinism`, `gate:divergence-bisect`. *Spec:* §7; cross-ref 24 §4,
  §5, §7.

---

## 8. `selftest` — run the gates against a built-in corpus

**Purpose.** Run Crucible's own determinism gates (24 §1) against a built-in
scenario corpus, so an operator can confirm a Crucible build (and its discovered
QEMU/plugin) is healthy without authoring a scenario. This is the operator's
"is my install correct?" check.

```text
  crucible selftest [FLAGS]

  FLAGS
    --gates <list>   Gate subset to run.
    --with-qemu      Execute the QEMU-backed gates (required in production).
    --corpus <path>  Test-double-only manifest of built-in fixture names.
```

`selftest` runs the named gates from the canonical catalog (24 §1.1) against the
packaged backend. The production binary defaults to the real-QEMU gates
(`gate:single-vm-fingerprint`, `gate:any-guest`, `gate:qemu-inert`) and requires
`--with-qemu` as an explicit acknowledgement that it will boot guests. A build
with the non-production `test-double` Cargo feature instead defaults to the
fast, double-backed corpus gates
(`gate:layer0-determinism`, `gate:content-address`, `gate:layer1-injection`,
`gate:replay-oracle`, `gate:scheduler-liveness`, `gate:control-responsive`) and
may add the real-QEMU gates with `--with-qemu`. In that feature build,
`--corpus <path>` is a line-oriented manifest of built-in fixture names
(`happy-path.scn`, `partition-recovery.scn`, `crash-restart.scn`). Every
real-QEMU row boots the hermetic patched-QEMU/plugin pair and reports the
resolved identity, terminal icount, and execution fingerprint. It reports a
per-gate pass/fail table and exits non-zero on any failure.

**Exit codes.** `0` = all selected gates green; `1` = one or more gates failed
(the table names which); `4` = discovery/config error (e.g. `--with-qemu` with no
QEMU); `64` = usage error.

- **[CLI-18]** `crucible selftest` MUST run a selected subset of the canonical
  gate catalog (24 §1.1) against a built-in scenario corpus and report a per-gate
  pass/fail table. The production binary MUST contain only real-QEMU runners,
  default to the QEMU-backed subset, and execute them only under `--with-qemu`.
  A `test-double` feature build MAY expose the fast corpus runners. It MUST exit
  `0` iff every selected gate is green and `1` otherwise, naming each failing
  gate. *Gate:* `gate:control-responsive`, `gate:replay-oracle`. *Spec:* §8;
  cross-ref 24 §1.1, §3.3.

---

## 9. `save` — run to a savepoint and export it

**Purpose.** Run to a chosen point and materialize a **savepoint**: a fat
checkpoint (07 §3) keyed by `config.id()` (05), validated by the replay oracle
(07 §6, [INV-2]), and exported as a resumable, content-addressed handle. Save is
just `create_savepoint` (20 §4) at a chosen stop point.

```text
  crucible save <SCENARIO> [FLAGS]

  FLAGS
    --at <virtual-time|quiescence|property|marker>   Where to stop and save. Required.
    --label <name>     Human label for the savepoint (07).
    --max-virtual-time <dur>   Coordinate for --at virtual-time.
    --property <assertion>     Assertion selector for --at property.
    --marker <name>    Guest marker selector for --at marker.
    --out <path>       Write the exported savepoint handle here. Default: --artifact-dir.
```

`save` runs the session to the `--at` stop point (using the §10 step modes /
breakpoints of 20 §4.3/§6 internally), issues `create_savepoint` (20 §4), and
exports the resulting handle. Because a savepoint is a checkpoint in the temporal
graph (07), it is CoW-shared with its ancestors and validated `fat == thin` by
the oracle (07 §6) on export — a save that fails the oracle fails the command.
For `--at virtual-time`, the controller advances one acknowledged scheduler
quantum at a time. It tolerates bounded zero-time boot quanta, rejects sustained
stagnation or an overshooting boundary, and exports only when the observed
frontier equals the requested coordinate exactly.

**Exit codes.** `0` = savepoint materialized, oracle-validated, and exported;
`1` = the run hit a non-savepoint terminal outcome before `--at` (the outcome is
reported); `3` = oracle violation on materialization (07 §6) or backend error;
`4` = discovery/config; `64` = usage.

- **[CLI-19]** `crucible save <scenario> --at <point>` MUST run the session to the
  stop point (via 20 §4.3 step modes / §6 breakpoints), issue `create_savepoint`
  (20 §4) to materialize a fat checkpoint keyed by `config.id()` (07 §3/§4),
  validate it `fat == thin` with the replay oracle (07 §6, [INV-2]), and export a
  content-addressed, resumable savepoint handle. An oracle violation MUST fail
  the command (exit 3), never export an unvalidated savepoint. *Gate:*
  `gate:replay-oracle`, `gate:content-address`. *Spec:* §9; cross-ref 20 §4, 07
  §3/§4/§6.

---

## 10. `resume` — resume from a checkpoint or savepoint

**Purpose.** Continue a run from a savepoint or any checkpoint (07). Resume is
`instantiate` of the recorded configuration (05 §5) — *not* a special "restored"
mode; a resumed session is an ordinary session at the recorded checkpoint
configuration ([SESS-18]). A deterministic runtime-only
frontier may still have an empty decision schedule and therefore retain genesis
configuration identity; its fat checkpoint material and virtual-time coordinate
distinguish the resumed runtime boundary from the zero-time baked genesis.

```text
  crucible resume <SAVEPOINT> [FLAGS]

  ARGS
    <SAVEPOINT>   A savepoint handle / checkpoint content hash (07).

  FLAGS
    --until <...>   Terminal condition, as in `run` (§6).
    --interactive   Drive the resumed session interactively (as in `run`).
    --watch         Stream the live status line (20 §9).
```

The resumed-session interactive protocol uses the same agent-readable response
shape as `run`: an accepted `query` is immediately followed by
`interactive-query\tstate=<state>` rather than discarding the observed state.

`resume` opens (or connects to) a session, `instantiate`s the savepoint's
configuration (05 §5 — `loadvm` of its fat snapshot, or replay-from-nearest-fat-
ancestor if thin, 07 §4), then `continue`s. The resumed configuration MUST
reduce to the same state the savepoint records, verified by the replay oracle
([INV-2]); a resume whose materialization disagrees with the thin derivation
fails rather than running a wrong state.

**Exit codes.** Same outcome→code mapping as `run` (§6); additionally `5` if the
savepoint is malformed or its referenced components cannot be resolved from the
store, and `3` on an oracle disagreement at materialization (07 §6).

- **[CLI-20]** `crucible resume <savepoint>` MUST `instantiate` the savepoint's
  recorded configuration (05 §5) — `loadvm` of its fat snapshot, or
  replay-from-nearest-fat-ancestor if thin (07 §4) — then `continue` (20 §4),
  with the same outcome→exit-code mapping as `run` (§6). A resumed session MUST
  be an ordinary session loaded from its recorded checkpoint configuration and
  runtime boundary, with no bespoke "restored" code path ([SESS-18]); the materialized state MUST reduce
  to the savepoint's recorded state, verified by the replay oracle ([INV-2]), or
  the resume MUST fail (exit 3) rather than run a wrong state. *Gate:*
  `gate:replay-oracle`. *Spec:* §10; cross-ref 05 §5, 07 §4, [SESS-18].

---

## 11. `fork` — fork from a savepoint with a new seed or decision override

**Purpose.** Branch the temporal graph: take a savepoint (or any checkpoint) and
run a *different* future from it — a new seed, or an explicit override of one or
more decisions (05 §3) at or after the fork point. Fork is `instantiate` of a
*prefix* configuration that then appends different decisions (05 §6, [SESS-19]),
sharing the parent's checkpoints CoW (07 §5).

```text
  crucible fork <SAVEPOINT> [FLAGS]

  ARGS
    <SAVEPOINT>   The fork point: a savepoint handle / checkpoint hash (07).

  FLAGS
    --seed <u64|hex>          New root seed for the forked future (06 §5.3).
    --override <decision=value>  Override a decision at/after the fork point (05 §3). Repeatable.
    --until <...>             Terminal condition, as in `run` (§6).
    --label <name>           Label the forked branch.
    --interactive            Drive the forked session interactively.
```

`fork` opens a session, `instantiate`s the *prefix* configuration up to the fork
point (05 §6), and produces an **independent child session** with its own
mailbox and lifecycle ([SESS-19]); mutating the child does not affect the parent
(CoW sharing is copy-on-*write*, 07 §5). With `--seed` the child draws all
post-fork decisions from a new seed; with `--override` it pins specific decisions
and draws the rest as before. Either way the child is a fully concrete run whose
artifact (06 §7.1) reproduces it without reference to the parent ([SPAT-27]).

**Exit codes.** Same outcome→code mapping as `run` (§6); `5` if the fork point is
malformed/unresolvable; `64` on conflicting `--seed`/`--override` usage.

- **[CLI-21]** `crucible fork <savepoint>` MUST `instantiate` the prefix
  configuration up to the fork point (05 §6) and produce an independent child
  session (its own mailbox/lifecycle, CoW-sharing the parent's checkpoints,
  [SESS-19]) that appends different decisions — `--seed` re-seeds all post-fork
  decisions (06 §5.3), `--override <decision=value>` pins specific decisions
  (05 §3) and draws the rest as before. The child MUST be a fully concrete run
  whose reproduction artifact (06 §7.1) reproduces it with no reference to the
  parent ([SPAT-27]); mutating the child MUST NOT affect the parent. *Gate:*
  `gate:replay-oracle`, `gate:content-address`. *Spec:* §11; cross-ref 05 §6, 07
  §5, [SESS-19].

---

## 12. `replay` — replay a reproduction artifact, bit-identically

**Purpose.** Re-run a reproduction artifact `(seed, ScenarioDef, Schedule)`
(06 §7.1, 24 §12) and produce a **bit-identical** canonical event log and
fingerprint stream — the concrete form of [G-6], and the command the CLI prints
on every failure (§4). This is the `gate:replay-oracle` / [HARN-28] contract made
operator-facing.

```text
  crucible replay <ARTIFACT> [FLAGS]

  ARGS
    <ARTIFACT>   A reproduction artifact (06 §7.1) or its content hash.

  FLAGS
    --check <original-log>   Assert the replayed canonical log is byte-identical to this one.
    --to <savepoint>        Validate a target savepoint handle or checkpoint hash.
    --bisect <other-artifact>    Bisect this artifact against another (24 §5).
```

`replay` reads the artifact, resolves its content-addressed components from the
store (06 §7.1), verifies the pinned engine/ABI/QEMU identities match the host
([HARN-28]) — failing loudly on any mismatch rather than reproducing something
else — then `reduce`s `(ScenarioDef, Schedule)` to the recorded state ([INV-1]).
With `--check`, it asserts the replayed canonical log equals the supplied
original byte-for-byte and exits non-zero on any difference, feeding the diff to
bisection (24 §5). With `--bisect <other-artifact>`, it compares two replayable
artifacts with matching replay inputs and exits non-zero when the canonical log
or fingerprint stream diverges.

**Exit codes.** `0` = replayed successfully (and, with `--check`, byte-identical);
`1` = `--check` mismatch or `--bisect` divergence (the divergence is bisected
and reported, §4); `3` = pinned-identity mismatch (engine/ABI/QEMU; [HARN-28])
or backend error; `5` = malformed/unresolvable artifact; `4` =
discovery/config; `64` = usage.

- **[CLI-22]** `crucible replay <artifact>` MUST resolve the artifact's
  content-addressed components (06 §7.1), verify the pinned engine/ABI/QEMU
  identities match the host and **fail loudly** (exit 3) on any mismatch rather
  than reproduce a different binary ([HARN-28]), then `reduce(ScenarioDef,
  Schedule)` (05, [INV-1]) as a mandatory preflight. A production replay MUST
  then launch fresh guests through the pinned QEMU/plugin pair and reproduce the
  terminal configuration, terminal outcome, canonical event stream, and
  all-node fingerprint stream exactly. It MUST fail closed when the live recipe
  or evidence is absent; model-only success is not a production replay.
  Operator-facing summaries of streamed events retain the original event
  sequence, scheduler coordinate, source, causal class, and a bounded
  kind-specific diagnostic field set. Fault and assertion identities therefore
  remain visible while byte payloads are length-only and redacted. These
  summaries are deterministic evidence projections; they do not replace the
  exact canonical event frames used by replay.
  `--check <original-log>` MUST assert byte-identity to the
  supplied log and exit `1` on any difference, reporting the bisected first
  divergence (24 §5). Replay MUST be machine-independent: the same artifact on a
  different host profile MUST reproduce byte-identically ([HARN-28]). *Gate:*
  `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:* §12; cross-ref 06 §7.1,
  24 §5, §12, [HARN-28].

---

## 13. `search` / `fuzz` — drive exploration (22)

**Purpose.** Drive systematic exploration of the schedule/scenario space: `search`
expands the temporal graph by enumerating decisions at frontier checkpoints
(22, state-space search); `fuzz` samples a `ScenarioFamily` (06 §7) under
coverage guidance (22). Both are *drivers* over the same fork/replay/oracle
primitives the other subcommands use; the exploration policy lives in 22, not in
the CLI.

```text
  crucible search <SCENARIO> [FLAGS]
    --strategy <bfs|dfs|guided>   Frontier expansion strategy (22).
    --max-depth <n>               Decision-depth bound.
    --max-states <n>              Budget on materialized states.
    --on-violation <stop|collect> Stop at the first finding, or collect within budget.
    --findings-out <path>         Override the signed findings-ledger path.
    --schedule-named-truths <path> Load schedule-named assertion truth data.

  crucible fuzz <FAMILY> [FLAGS]
    --family <path|hash>          A ScenarioFamily (06 §7) to sample.
    --runs <n>                    Number of family instances to run.
    --coverage <basic-block>      Coverage signal guiding sampling (22).
    --corpus <path>               Seed/regression corpus directory.
    --on-violation <stop|collect> Stop at the first finding, or collect within budget.
    --findings-out <path>         Override the signed findings-ledger path.
```

`search` and `fuzz` walk the space, run each pinned `ScenarioDef` (06 §7,
[SPAT-27]) as `run` would, and — on every materialized fat checkpoint —
opportunistically run the replay oracle (24 §6, [HARN-13]) so the invariant is
exercised on real explored states. Each discovered counterexample reduces to a
self-contained reproduction artifact (06 §7.1), is entered in a signed findings
ledger (§34.7), and is reported with the §4 repro command, so a fuzz-found
failure is reproduced exactly like a hand-run one. `--on-violation` defaults to
`stop`; `collect` retains every distinct property violation or concrete
execution timeout encountered within the supplied campaign budget. Repeated
discovery of the same reproduction artifact and identical evidence is
deduplicated; conflicting evidence for that artifact is an artifact error.

**Exit codes.** `0` = exploration completed within budget with no finding, or a
`collect` campaign exhausted its campaign budget without retaining a finding;
`1` = at least one property counterexample found (artifacts written, §4); `2` =
at least one concrete execution timeout, or `stop`-mode campaign budget
exhaustion without a property finding; `3` = oracle violation during search (a
data-model defect; 24 §6); `4` = discovery/config; `64` = usage.

- **[CLI-23]** `crucible search` and `crucible fuzz` MUST drive the exploration
  policies of `22-advanced-features.md` over the same fork/replay/oracle
  primitives the other subcommands use, pinning exactly one concrete
  `ScenarioDef` per run ([SPAT-27]) and opportunistically exercising the replay
  oracle on materialized checkpoints (24 §6, [HARN-13]). The CLI MUST NOT
  implement exploration policy itself; it MUST delegate to 22. Each discovered
  counterexample MUST reduce to a self-contained reproduction artifact (06 §7.1)
  and be reported with the §4 repro command. An in-search oracle violation MUST
  exit `3`. *Gate:* `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:* §13;
  cross-ref 22, 06 §7, 24 §6.

---

## 14. `serve` — host the daemon and the API (21)

**Purpose.** Run the long-lived **daemon** that hosts the API (21): it owns one
or more sessions (20), accepts API clients (including remote `crucible --daemon`
invocations, §3), and streams event logs and state transitions over the API's
broadcast surface (20 §9, 21). `serve` is the server half of the local/remote
split (§3).

```text
  crucible serve [FLAGS]

  FLAGS
    --listen <addr>      Address to bind the API (21) on. Required.
    --store <path>       Content-addressed store root (06, 07). Global flag (§2).
    --max-sessions <n>   Concurrency cap on live sessions.
    --read-only          Accept only read-only API calls (query/watch); no mutate.
```

`serve` binds the API transport (21) and runs an accept loop, constructing a
session actor (20 §1) per submitted scenario and routing API calls to its command
set (20 §4). Because the session is an actor with lock-free observation (20 §9),
many clients can `watch` a run's event log and status without entering the
stepping path or blocking each other; control commands are acknowledged within a
bounded quantum count ([SESS-3], `gate:control-responsive`). The daemon holds no
determinism mechanism the in-process path lacks — it is the *same* sessions,
reached over the API instead of in-process ([CLI-8]).

**Exit codes.** `0` = clean shutdown (signal); `3` = bind/backend error; `4` =
discovery/config; `64` = usage. While running, the process stays up until a
shutdown signal.

- **[CLI-24]** `crucible serve --listen <addr>` MUST run the daemon that hosts the
  API (21): bind the API transport, construct a session actor (20 §1) per
  submitted scenario, route API calls to the session command set (20 §4), and
  stream event logs / state transitions over the API broadcast surface (20 §9).
  Many clients MUST be able to `watch`/`query` a run lock-free without blocking
  the stepping path (20 §9), and control commands MUST be acknowledged within a
  bounded number of quanta ([SESS-3]). The daemon MUST host the *same* sessions
  the in-process path runs — no determinism mechanism unique to the daemon
  ([CLI-8]). `--read-only` MUST reject all state-mutating API calls. *Gate:*
  `gate:control-responsive`. *Spec:* §14; cross-ref 21, 20 §1, §4, §9.

---

## 16. `triage` — cluster, dedup, and minimize discovered failures

**Purpose.** Turn a pile of discovered failures (the counterexamples a `search`
or `fuzz` campaign emits, §13) into a deduplicated, minimized, reportable set.
`triage` is a **thin driver over the triage engine of
[`34-failure-triage.md`](34-failure-triage.md)**: it clusters failures by
signature, picks a representative per cluster, minimizes each representative to a
smaller still-failing artifact, and emits reports. It holds no triage policy of
its own ([CLI-1]); the clustering/minimization policy lives in 34.

```text
  crucible triage <FINDINGS> [FLAGS]

  ARGS
    <FINDINGS>   A findings directory / corpus of reproduction artifacts (06 §7.1, 34).

  FLAGS (subcommand-local; global flags from §2 also apply)
    --policy <coarse|default|fine|exact>     Signature policy to apply (34). Default: default.
    --minimize <none|representative|all>     Representative minimization mode (34). Default: representative.
    --report <dir>                           Write the triage report here. Default: --artifact-dir.
    --recompute-signatures    Recompute failure signatures rather than reuse cached ones (34).
    --compare <other-triage-result>          Diff against a prior triage result (34).

  GLOBAL FLAGS USED BY TRIAGE
    --store <path>                          Content-addressed store root for ledgers/results.
    --artifact-dir <path>                   Default report directory.
    --format <jsonl|json|table|markdown>    Report render format (34 §34.5.2). Default: jsonl.
```

`triage` reads the findings, computes a failure signature per artifact and
clusters by it (34), elects a representative per cluster, optionally minimizes
each representative (34) — each minimized result remaining a self-contained
reproduction artifact (06 §7.1) that reproduces bit-identically ([CLI-22]) — and
emits a per-cluster report. Because every representative is an ordinary artifact,
each is replayable (§12) and debuggable (§16's sibling, §17) exactly like a
hand-found failure.

**Exit codes.** `0` = triage completed (report written); `1` = at least one
cluster's minimization failed its signature-preservation assertion or
`--recompute-signatures` found a mismatch; `4` = discovery/config;
`5` = malformed/unresolvable findings ledger or artifact; `64` = usage.

- **[CLI-26]** `crucible triage <findings>` MUST be a thin driver over the
  triage engine of [`34-failure-triage.md`](34-failure-triage.md): it MUST
  cluster the findings by failure signature, elect a representative per cluster,
  optionally minimize each representative (`--minimize`) to a smaller artifact
  that still reproduces the failure bit-identically (06 §7.1, [CLI-22]), and emit
  a per-cluster report (`--report`, `--format`). `--policy` MUST select the
  clustering/signature policy (34); `--recompute-signatures` MUST recompute rather
  than reuse cached signatures; `--compare <other>` MUST diff against a prior
  triage report. The CLI MUST NOT implement clustering or minimization policy
  itself — it MUST delegate to 34 ([CLI-1]). Every cluster representative MUST be
  an ordinary reproduction artifact, replayable (§12) and debuggable (§17).
  *Gate:* `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:* §16; cross-ref 34,
  13, 06 §7.1.

---

## 17. `debug` — open the time-travel debugger at a coordinate

**Purpose.** Open the **gdb-protocol time-travel debugger** at a chosen
coordinate of a run. `debug` is a **thin wrapper over the debugger of
[`36-time-travel-debugging.md`](36-time-travel-debugging.md)** and the session's
read-only debugging command set (20 §4.4): it instantiates the run from an
artifact, savepoint, or a live `--session`, positions it at the requested
coordinate (restore-nearest-checkpoint + deterministic replay, [SESS-33]), opens
QEMU's gdbstub as an out-of-band channel ([SESS-32]), and accepts interactive
reverse verbs. It introduces no determinism mechanism of its own ([CLI-1]).

```text
  crucible debug <ARTIFACT|SAVEPOINT> [FLAGS]
  crucible debug --session <id:epoch:seed> [FLAGS]

  ARGS
    <ARTIFACT|SAVEPOINT>   A reproduction artifact (06 §7.1) or savepoint handle (07).

  FLAGS (subcommand-local; global flags from §2 also apply)
    --session <id:epoch:seed> Attach to a live daemon session (21) instead of an artifact;
                              seed is exactly 64 lowercase hexadecimal digits.
    --at <virtual-time|icount>   Open at this coordinate (20 §4.4 DebugCoordinate).
    --at-event <seq>          Open at this event-log sequence position (19).
    --at-failure              Open at the run's first property violation (the failure footer's verb, §4).
    --at-checkpoint <id>      Open at this checkpoint id (07).
    --node <id>               Which node's gdbstub to open. Default: the failing node.
    --gdb-listen <addr>       Address QEMU's gdbstub listens on. Default: a local port.
    --read-only               Read-only debugging (the default): no mutation, fully canonical.
    --allow-mutate            Authorize an explicit `fork-debug`; never forks implicitly.
    --checkpoint-stride <n>   Checkpoint density for reverse stepping (replay-suffix bound, 36).
```

`debug` instantiates the run, issues `goto` to the requested coordinate
(`--at`/`--at-event`/`--at-failure`/`--at-checkpoint`; default `--at-failure` for
a failing artifact), opens the gdbstub on `--node` at `--gdb-listen`
([SESS-33], [SESS-32]), and then reads interactive verbs — `attach-gdb`,
`fork-debug`, `goto`, `reverse-step`, `reverse-continue`, `exec`, `pty`, `ssh` — mapping each to the session's
read-only debugging command (20 §4.4). It is **read-only by default**
([SESS-33]): the run stays fully canonical and the gdbstub is observation-only.
`--allow-mutate` authorizes the explicit `fork-debug` verb; it does not fork by
itself. Continuing or mutating is rejected until `fork-debug` has created a
**clearly-marked whole-world NON-CANONICAL debug branch** (excluded from the replay
oracle, not artifact-reproducible, [SESS-33]); the CLI MUST label this prominently.
Guest `exec`, `pty`, and `ssh` additionally require the authenticated role's
closed `shell` capability and the exclusive controller lease. Arguments are sent
as argv values without host-shell parsing. PTY and SSH bytes use the public,
bounded guest-introspection protocol; they never expose a host shell.
`--checkpoint-stride` tunes checkpoint density so reverse stepping stays cheap
(bounded replay suffix, 36, [HARN-9]).

The current production executor implements these operations for a live daemon
session. A local artifact, savepoint, or daemonless session target fails clearly
with exit `4` before launching the generic QEMU admission probe; it MUST NOT emit
a plan-only success or claim that `goto`, reverse execution, GDB attachment, or
guest introspection occurred. Malformed artifact decoding retains exit `5`
precedence. Local instantiate/replay remains part of open T-DBG-9/T-DBG-10 work.

**Exit codes.** `0` = clean debugger exit; `3` = pinned-identity mismatch
([HARN-28]); `4` = backend capability, discovery, configuration, or an
unimplemented local executor (e.g. a backend without `open_gdbstub`, [SESS-32]);
`5` = malformed/unresolvable
artifact/savepoint; `64` = usage error (e.g. conflicting `--at*` flags).

- **[CLI-27]** `crucible debug <artifact|savepoint|--session>` MUST be a thin
  wrapper over the debugger of [`36-time-travel-debugging.md`](36-time-travel-debugging.md)
  and the session read-only debugging command set (20 §4.4): it MUST instantiate
  the run, position it at the coordinate selected by `--at` / `--at-event` /
  `--at-failure` / `--at-checkpoint` via restore-nearest-checkpoint + deterministic
  replay ([SESS-33]), open the gdbstub on `--node` at `--gdb-listen` ([SESS-32]),
  and accept the interactive verbs `attach-gdb`/`fork-debug`/`goto`/`reverse-step`/
  `reverse-continue`/`exec`/`pty`/`ssh`. It MUST be **read-only by default** (`--read-only`,
  canonical); `--allow-mutate` MUST only authorize an explicit `fork-debug`, and
  mutation/free run control MUST be rejected before that verb creates a clearly-marked
  whole-world NON-CANONICAL debug branch (excluded from the replay oracle, not
  artifact-reproducible, [SESS-33]). The CLI MUST label it as such.
  `--checkpoint-stride` MUST tune reverse-step
  cost (bounded replay suffix, 36). The CLI MUST NOT implement any debugging or
  time-travel mechanism of its own ([CLI-1]); a backend without `open_gdbstub`
  ([SESS-32]) MUST fail clearly (exit 4), never fake a stub. *Gate:*
  `gate:replay-oracle`, `gate:control-responsive`. *Spec:* §17; cross-ref 36,
  20 §4.4, [SESS-33], [SESS-32].

---

## 15. Exit codes and machine-readable output (summary)

The exit-code mapping is uniform across run-capable subcommands, so a script can
branch on the verdict without parsing output:

```text
  code   meaning
  ────   ───────────────────────────────────────────────────────────────────
   0     success / Passed / deterministic / all gates green / clean shutdown
   1     Failed (property violation) / verify divergence / replay --check mismatch /
         replay --bisect divergence / counterexample found
   2     Timeout (virtual-time or quantum budget reached, 20 §2)
   3     Crashed / replay-oracle violation / pinned-identity mismatch
   4     backend capability / discovery / configuration error (QEMU/plugin/store/daemon; §5)
   5     invalid scenario or malformed/unresolvable artifact (06 §9)
   64    usage error (bad flags / args; conventional EX_USAGE)
```

- **[CLI-25]** The exit-code mapping in §15 MUST be uniform across the
  run-capable subcommands: `0` success, `1` failure/divergence/counterexample,
  `2` timeout, `3` crash/oracle/identity-mismatch, `4`
  backend-capability/discovery/config, `5` invalid scenario/artifact, `64` usage. A script MUST be
  able to branch on a run's verdict by exit code without parsing stdout, and
  `--format json`/`jsonl` MUST be sufficient for fully machine-readable output of
  the event log and the final outcome. *Spec:* §15; cross-ref 20 §2, §4.

---

## Cross-file assumptions this file relies on

- The session command set `start/continue/pause/step/stop/inject_fault/
  heal_fault/set+remove breakpoint/create_savepoint/fork/query` (20 §4) is the
  CLI's only control vocabulary; the CLI adds no command outside it ([CLI-1]).
- The reproduction artifact is the self-contained `(seed, ScenarioDef, Schedule)`
  bundle (06 §7.1, 24 §12); this file owns the `replay` flow and the
  failure-time repro-command ergonomics (§4, §12).
- `start ≡ resume ≡ fork` is one `instantiate` (05 §5/§6, [SESS-11], [SESS-18]):
  `run`/`resume`/`fork` are CLI faces of that one operation, not three code paths
  (§6, §10, §11).
- Backend selection (real QEMU / `SimDouble`) is the `SimulationBackend` of
  20 §10; the CLI selects but does not define it (§3).
- Plugin/QEMU discovery is hermetic against the AOS package set (26), never the
  host `$PATH` (§5); the AOS QEMU build identity and plugin ABI version are
  pinned into the artifact ([HARN-28]).
- Exploration policy lives in `22-advanced-features.md`; `search`/`fuzz` are
  drivers, not policy (§13).

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md). The copies below are
> the tasks whose primary area is this file ([PLAN-3]); they are kept in
> sync with the master plan's order/digest by the doc lint
> ([`28-engineering-standards.md`](28-engineering-standards.md)).

- [x] **T-CLI-1** Implement the `crucible` binary skeleton: the closed subcommand
  set (run/verify/selftest/save/resume/fork/replay/search/fuzz/triage/debug/serve/completions)
  and the global flag block (§2), with derive-based parsing whose help text is
  authored as user-facing CLI copy (no container overview docs). — satisfies
  [CLI-3], [CLI-4], [CLI-6]; spec §2, §2.1.
  Completed by `checks.crucible.phase5.cliSkeleton`: the `crucible` binary now
  uses derive-based Clap parsing for the closed subcommand surface (`run`,
  `verify`, `selftest`, `save`, `resume`, `fork`, `replay`, `search`, `fuzz`,
  `triage`, `debug`, `serve`, `completions`) and the shared global flag block
  (`--seed`, `--backend`, `--daemon`, `--qemu`, `--plugin`, `--store`,
  `--format`, `--trace`, `--artifact-dir`, `-v/--verbose`, `-q/--quiet`). The
  focused parser tests assert the closed command set, global flag parsing, and
  unknown-command rejection; command execution and thin session/API dispatch
  remain T-CLI-2 and later CLI tasks.
- [x] **T-CLI-2** Implement the thin-wrapper layering: every subcommand decomposes
  into session commands (20 §4) / API calls (21); add a lint/test that the CLI
  holds no canonical run state and adds no control capability absent from 20/21. —
  satisfies [CLI-1], [CLI-2]; spec §1.
  Completed by `checks.crucible.phase5.cliThinWrapper`: the CLI now builds a
  `CliThinWrapperPlan` for every closed subcommand before dispatch, executes that
  plan through an operation recorder, and rejects a plan that owns canonical run
  state, implements scheduler/checkpoint/fork logic, or advertises any control
  capability outside `SessionCommandKind::ALL` and the actual `ControlClient`
  method set. The focused tests cover all subcommand plans, recorder-emitted
  session/API operations including a remote `--daemon` route, and negative cases
  for CLI-owned state, scheduler logic, checkpoint materialization, fork logic,
  and invented control capabilities. Production resume, fork, save, and search
  paths delegate validation-DAG operations to `crucible_session::validation`;
  parent-prefix derivation, fat checkpoint materialization, and baked-genesis DAG
  registration are session-owned APIs. The gate scans the production command
  modules and rejects direct checkpoint materialization in addition to checking
  the plan model.
- [x] **T-CLI-3** Implement backend selection and the local/remote split
  (`--backend auto|qemu` in production, test-feature-only `double`, `--daemon`),
  with the announced `auto` choice and
  local/remote output+exit-code equivalence. — satisfies [CLI-5], [CLI-7],
  [CLI-8]; spec §3.
  Completed by `checks.crucible.phase5.cliBackendSelection`: the CLI builds
  and executes a `BackendSelectionPlan` for every backend-routed subcommand,
  routes `--daemon` invocations to a fakeable remote API command runner without
  selecting a local backend, resolves local `--backend auto` through the
  hermetic discovery contract and fails closed when no production backend is
  available. The in-process double is compiled only for tests or an explicit
  `test-double` feature build and is absent from the packaged binary's parser
  and help. Explicit `--backend qemu` fails with exit code 4 when hermetic
  discovery cannot produce a valid patched-QEMU/plugin pair. The focused tests
  record local and remote
  command-runner invocations and compare stdout/stderr, exit code,
  canonical-log digest, and artifact digest projections. The selected QEMU path
  now boots the closure-owned patched QEMU, stock AOS kernel, raw fixture root,
  and production Rust plugin through the API boundary. It records the negotiated
  protocol/ABI, exact icount, execution fingerprint, boot-barrier proof, and
  orderly child exit alongside the session result; the remote route exercises
  the production HTTP/2 lifecycle session with the same output and exit contract.
- [x] **T-CLI-4** Implement determinism ergonomics: seed resolution
  (`--seed`/`CRUCIBLE_SEED`/generated) with always-printed seed, failure-time
  artifact + copy-pasteable repro command, and the three trace formats
  (jsonl/json/table) over the canonical log; assert no wall-clock feeds canonical
  State. — satisfies [CLI-9], [CLI-10], [CLI-11], [CLI-12]; spec §4.
  Completed by `checks.crucible.phase5.cliDeterminismErgonomics`: the CLI now
  builds and executes a `DeterminismErgonomicsPlan` before backend routing for
  commands that create a run identity, resolves the seed by explicit flag,
  `CRUCIBLE_SEED`, then pre-run OS entropy, and prints the resolved seed unless
  quiet; replay and resume are explicitly artifact/savepoint-owned seed modes.
  The resolved seed is threaded into the backend-routed canonical run-identity
  projection and into failure reproduction artifacts, so same-seed local/remote
  routes stay equivalent while different seeds change the canonical digest. The
  generic non-passing outcome path writes the self-contained artifact and emits
  shell-quoted `crucible replay <artifact>` plus
  `crucible debug <artifact> --at-failure` footer commands. Routed command
  output now renders or writes the canonical log through `jsonl`, `json`, and
  `table` over one canonical entry digest, emits `jsonl` entry by entry, rejects
  `markdown` for event-log traces, and propagates non-passing outcomes through
  the process exit-code path after writing artifacts. The gate scans the CLI plus
  canonical model/session sources for wall-clock APIs on canonical paths. This
  Generic failed local runs now serialize their exact compact scenario form,
  observed canonical entries, resolved seed and backend identity, and observed
  execution-fingerprint stream. An adversarial test decodes the emitted
  artifact and proves its scenario, event decision, and fingerprint came from
  the failed run rather than the gate-only mock fixture.
- [x] **T-CLI-5** Implement hermetic QEMU/plugin discovery
  (flag → env → AOS package set, no host `$PATH`), clear fail-with-exit-4 on
  absence/mismatch, and pinning the AOS QEMU build identity + plugin ABI version
  into the artifact. — satisfies [CLI-13], [CLI-14], [CLI-15]; spec §5.
  Completed by `checks.crucible.phase5.cliHermeticDiscovery`: the CLI now
  resolves QEMU and plugin candidates independently in flag, environment
  (`CRUCIBLE_QEMU`/`CRUCIBLE_PLUGIN`), then AOS package-set order, with the
  packaged CLI receiving compile-time AOS store-path hints for
  `qemu-crucible` and `crucible-qemu-plugin`. A complete candidate pair must
  have readable artifacts, a patched-QEMU sim-capability marker with plugins
  enabled and a build identity, and plugin build metadata whose ABI is derived
  from `crucible_shmem::ABI_VERSION` and whose QEMU build identity matches the
  selected QEMU marker. Explicit QEMU absence or any mismatched candidate pair
  fails with exit code 4 and a message listing the discovery order and stating
  that host `$PATH` QEMU is never used. Resolved QEMU backends carry the pinned
  QEMU build identity and plugin ABI into replay identity checks and failure
  reproduction artifacts. Before marker identities are admitted, the selected
  QEMU must be an executable 64-bit ELF that accepts an actual `--version`
  process query, and the plugin must be an ELF shared object exposing
  `qemu_plugin_install` and `qemu_plugin_version`. Adversarial tests prove text
  files carrying plausible marker strings cannot impersonate either artifact.
- [x] **T-CLI-6** Implement `run` (start→continue, stream, outcome→exit-code,
  `--interactive` over the session command set, `--until`/budgets). — satisfies
  [CLI-16]; spec §6.
  Completed under `checks.crucible.phase5.cliRunWorkflow`: `run` parses canonical
  scenario files and `blake3:` store references, validates malformed scenarios
  as exit 5, starts lifecycle-owned sessions through the API, drives local
  in-process-double and `--daemon` HTTP/2 RPC sessions through the same typed
  control-client workflow, streams non-empty scheduler event/state frames,
  derives terminal status from session `OutcomeKind`, enforces
  virtual-time budgets from live counters and exact paused boundaries for
  quantum budgets, emits user-visible `--watch` status, materializes real
  terminal savepoint handles for `--save-on`, persists their replayable closure
  and checkpoint index in the selected DAG store before advertising them, maps
  non-passing outcomes to reproduction artifacts and exit codes, and provides
  incremental stdin acknowledgements and state-query results for interactive
  commands. Accepted interactive stops carry the joined actor's terminal
  snapshot through the existing query-result envelope, allowing immediate
  registry cleanup without losing final evidence or waiting for another input
  line.
- [x] **T-CLI-7** Implement `verify` (N independent reductions, canonical-log +
  fingerprint byte-identity compare, `--adversarial`, on-divergence bisection). —
  satisfies [CLI-17]; spec §7.
  Completed by `checks.crucible.phase5.cliVerifyWorkflow`: the CLI plans and
  executes fresh local-double, local-QEMU, and remote-daemon verify reductions,
  compares canonical log bytes and execution-fingerprint streams, applies the
  hostile-profile matrix for `--adversarial`, localizes the first differing
  decision/sample/byte with a bisection report, emits both-side reproduction
  artifacts on divergence, supports `verify --compare <a> <b>`, maps
  deterministic/divergent outcomes to exit 0/1, and records the resolved
  QEMU/plugin build identity for local-QEMU verify runs. Every local-QEMU
  reduction independently boots the packaged live backend and the command fails
  if any observed plugin-install report differs; the fleet gate supplies the
  AOS kernel/root closure and exercises this path under TCG.
- [x] **T-CLI-8** Implement `selftest` (run a selected gate subset of the canonical
  catalog, production real-QEMU under `--with-qemu`, optional feature-gated test
  corpus, per-gate pass/fail table). — satisfies [CLI-18]; spec §8.
  Completed under `checks.crucible.phase5.cliSelftest`: the gate invokes the
  packaged production CLI against the unmodified stock Linux kernel with
  `crucible selftest --with-qemu`. The production binary selects the three
  real-QEMU gates by default, discovers the hermetic QEMU/plugin pair, and emits
  a PASS row with QEMU identity, terminal icount, and execution fingerprint for
  each independently booted guest. Discovery, live execution, or cross-run
  evidence divergence prevents a PASS. Supplemental `test-double`-feature tests
  cover the fast built-in corpus runners, `--gates <list>` validation, and
  file-backed corpus manifests; none of those runners are compiled into the
  packaged binary.
- [x] **T-CLI-9** Implement `save` (run to `--at`, create_savepoint, oracle-validate
  fat==thin, export a content-addressed handle; fail on oracle violation). —
  satisfies [CLI-19]; spec §9.
  Completed under `checks.crucible.phase5.cliSaveWorkflow`: the CLI parses
  `save <SCENARIO>` with the required `--at` stop selector plus
  `--label <name>`, `--max-virtual-time <dur>`, `--property <assertion>`,
  `--marker <name>`, and `--out <path>`, runs quiescence and virtual-time
  saves to paused session boundaries, issues a label-bearing
  `create_savepoint`, validates the returned materialized checkpoint with the
  replay oracle (`fat==thin`) before export, writes the validated
  `.crucible-savepoint` handle, parses property and marker selector syntax,
  validates property selector names against declared assertions, exercises
  local-double property saves through host assertion evaluation of
  scenario-declared properties, exercises marker saves through white-box
  scenario-declared guest marker sources, proves both selector classes with
  suspending breakpoints plus breakpoint-firing proof, rejects wrong-marker and
  no-source marker selectors, routes explicitly selected local-QEMU saves
  through the same create-savepoint/export/oracle workflow with resolved
  QEMU/plugin identity metadata, process-tests real-binary `save --backend qemu`
  JSONL output and handle export through marker-resolved QEMU/plugin identity,
  routes remote-daemon quiescence and virtual-time saves over the RPC control
  API with replay-oracle validation, advances virtual-time saves as individually
  acknowledged quanta so observer polling cannot hide a hung duration step,
  rejects sustained zero-time progress and coordinate overshoot, routes remote
  selector proof queries over RPC breakpoint-firing payloads, transfers arbitrary scenario selector sources
  to remote daemons as form-bearing inline `CreateSession` RPC payloads, derives
  remote guest-marker white-box policy from the transferred source form, and
  fails undeclared property selectors and marker selectors without a white-box
  source. The gate also runs a backend-executed patched-QEMU `snapshot-save`
  smoke over the same QMP savepoint primitive before marking `T-CLI-9` green.
- [x] **T-CLI-10** Implement `resume` (instantiate the savepoint's configuration
  and recorded runtime frontier, continue; ordinary session, no restored path;
  oracle-verified materialization). — satisfies [CLI-20]; spec §10.
  Completed under `checks.crucible.phase5.cliResumeWorkflow`: the CLI now
  parses `resume <SAVEPOINT>` with `--until`, `--max-virtual-time`,
  `--interactive`, and `--watch`, decodes `.crucible-savepoint` handles exported
  by `save`, validates their compact scenario and schedule evidence, loads bare
  `blake3:<hash>` checkpoint references from the local DAG-store checkpoint
  closure index, validates malformed handles as artifact errors, and executes
  handle- or store-backed local-double resume to quiescence, virtual-time,
  interactive command driving, or a declared property violation by rebuilding
  the temporal graph, validating
  property-stop breakpoint firing evidence when requested, stopping with a
  terminal savepoint, and replay-oracle-validating that terminal
  materialization. The same check also routes remote-daemon resume over
  `ResumeSession` RPC for handle-backed virtual-time runs and interactive
  command driving, instantiating the checkpoint through the session resume API,
  accepts runtime-only fat checkpoints whose decision schedule remains genesis
  while their frontier has advanced, thin-replays those checkpoints to the exact
  recorded frontier with bounded stagnation and overshoot rejection, rejects
  tampered zero-time baked-genesis material,
  streaming `--watch` status at observed remote boundaries, advancing the
  resumed actor, stopping with a terminal savepoint, and replay-oracle-validating
  that terminal materialization. Terminal remote interactive command sequences
  now query the stopped snapshot, validate the actor-materialized terminal
  savepoint, emit the same replay-oracle proof, and clean up the stopped remote
  session. Explicitly selected local-QEMU resumes now run the same resumed
  session workflow, invoke the `crucible-qemu` resume coordinator through an
  API-owned adapter backed by a `SimBackend`-seeded
  `QemuBackendRealizationExecutor`, and derive the emitted branch/runtime proof
  from that coordinator result. The API bridge now also accepts a caller-owned
  `QemuVmRealizationExecutor`, so the CLI/API boundary has an explicit hook for
  selecting the Linux real-node executor once launch artifacts are resolvable;
  `crucible-qemu` owns the typed realization coordinator with
  baked-genesis/source-ancestor evidence, the default savevm policy, and a
  `Backend`-backed realization executor that restores exact/baked snapshots
  through the QMP-backed backend boundary and replays suffixes through backend
  horizon advances, plus a Linux real-node realization executor that launches a
  policy-authorized restored `QemuNode`, replays through shared memory, samples
  live fingerprints and icounts, and keeps generic QMP snapshot/restore closed
  after node assembly.
  Stdout and the canonical log record
  `materialization=qemu-vm-realization`, `operation=resume`,
  `executor=model-checkpoint`, branch, replay count, runtime/configuration
  hashes, and resolved QEMU/plugin identity.
  Process-tests cover real-binary
  `resume --backend qemu` JSONL output, coordinator-derived branch/runtime
  fields from that model-checkpoint executor, and replay-oracle validation
  through marker-resolved QEMU/plugin identity. The selected local-QEMU path now
  requires a successful live packaged-QEMU/plugin boot before admitting the
  coordinator result. The gate also runs a direct patched-QEMU
  QMP `snapshot-load` smoke that proves the load job concludes and QEMU reports
  `running` after `cont`; exact restore is admitted only after the replay oracle
  validates the materialized configuration under the savevm policy.
- [x] **T-CLI-11** Implement `fork` (instantiate a prefix into an independent child
  session; `--seed` re-seed and `--override decision=value`; child artifact
  reproduces without the parent). — satisfies [CLI-21]; spec §11.
  Completed under `checks.crucible.phase5.cliForkWorkflow`: the CLI now
  parses `fork <SAVEPOINT>` with global `--seed`, repeatable `--override
  decision=value`, `--until`, `--max-virtual-time`, `--label`, `--interactive`,
  and `--watch`; resolves `.crucible-savepoint` handles and direct
  `blake3:<hash>` checkpoint references through the shared savepoint evidence
  loader, including local DAG-store checkpoint closure indexes; validates
  override pairs, virtual-time budgets, malformed handles, and
  conflicting explicit `--seed` plus `--override`; executes handle-backed
  and store-backed no-divergence local-double forks through an independent child
  session to quiescence, virtual-time, or interactive command boundaries; applies
  repeatable post-fork `--override` decisions through the session fork path;
  applies explicit post-fork `--seed` in the local double by deriving the child's
  post-fork decision stream from that seed while preserving the requested
  savepoint prefix, proving distinct explicit seeds produce distinct terminal
  child savepoints and exact virtual-time fork targets still pause at the
  requested boundary; writes a CLI-replayable child reproduction artifact whose
  embedded seed remains the scenario-form seed while CLI output reports the fork
  seed provenance, separate model artifact/replay-state evidence for the same
  child configuration, and terminal child savepoint replay-oracle validation;
  routes explicitly selected local-QEMU forks through the same child-session
  materialization with resolved QEMU/plugin identity provenance in stdout and
  the canonical log; and process-tests real-binary `fork --backend qemu` JSONL
  output and child artifact creation through marker-resolved QEMU/plugin
  identity. The selected QEMU backend now requires a successful independent
  packaged-QEMU/plugin boot before the child workflow begins; the
  backend-agnostic prefix, independently materialized child session, and
  standalone child artifact prove the child does not depend on the parent
  process. For the production QEMU backend, `--seed` now re-seeds the live
  scheduler, World-network, block, 9p, and plugin-served app-random streams at
  the exact saved configuration; the app-random plugin carries exact branch and
  relaunch cursors, and the patched-QEMU white-box gate proves the first
  post-branch guest request comes from cursor zero under the branch seed.
- [x] **T-CLI-12** Implement `replay` (resolve components, verify pinned
  engine/ABI/QEMU identities and fail loudly on mismatch, reduce to a bit-identical
  log, `--check` byte-identity with on-mismatch bisection, machine-independent). —
  satisfies [CLI-22]; spec §12.
  Completed under `checks.crucible.phase5.cliReplayCheck`: the CLI now
  accepts `replay --check <original-log>`, validates the artifact through the
  pinned identity path before store access,
  resolves missing content-addressed component payloads from the selected local
  DAG store,
  validates declared DAG-store references against inline payloads, reconstructs
  the replay canonical log, returns exit 1 on byte mismatch with deterministic
  first-difference byte localization, process-tests real-binary
  `replay --check` success/mismatch and `replay --to <SAVEPOINT>`
  target-validation JSONL output with replay records plus `final_outcome`, and
  supports artifact-to-artifact `--bisect <other-artifact>`
  by validating both artifacts, requiring matching
  replay inputs, localizing the first differing canonical-log/fingerprint
  coordinate, and returning the replay-check failure exit path on divergence.
  `replay --to <SAVEPOINT>` now accepts a savepoint handle or local DAG-store
  checkpoint hash; a v3 artifact also resolves its own terminal checkpoint
  hash from the embedded scenario, schedule, and live frontier. It validates
  the target through savepoint evidence and the pure
  replay oracle, proves the savepoint scenario identity matches the artifact,
  builds a payload-backed typed schedule-prefix proof from the target `Schedule`,
  rejects equal-length non-prefix artifacts with deterministic mismatch
  diagnostics, requires artifact decision payload bytes to resolve for the proved
  prefix, and still requires the savepoint schedule length to fit within the
  encoded artifact decision stream. It also materializes the target through the
  unified model temporal-graph replay operation, proving the realized runtime
  state, reduced state, single-VM fingerprint, and replay-oracle fat/thin
  checkpoints agree, and wires mock host-profile machine-independent replay into
  the replay gate by reproducing the same artifact across quiet single-core and
  loaded many-core profiles with identical canonical log, fingerprint, and
  artifact digest. Ordinary replay reconstructs canonical entries from embedded
  decisions and payload summaries, re-executes the pure
  `reduce(ScenarioDef, Schedule)` materialization, verifies all pinned
  identities before store access, and compares the reconstructed canonical
  bytes and fingerprint evidence through the bisection-capable check path used
  by production failure artifacts. Every newly captured failed-run artifact
  carries the session-observed terminal `Configuration` as that typed
  scenario/schedule model reproduction; a process-independent regression
  replays an actual failed-run artifact through the same reduction path.
  This task's original model-only completion is retained as the pure preflight;
  T-CLI-21 completes the production QEMU execution half of [CLI-22].
- [x] **T-CLI-13** Implement `search`/`fuzz` as drivers over the 22 exploration
  policies (pin one ScenarioDef per run, in-search oracle sampling, counterexamples
  to self-contained artifacts with repro commands; no policy in the CLI). —
  satisfies [CLI-23]; spec §13.
  Completed under `checks.crucible.phase5.cliSearchFuzzWorkflow`: the CLI
  now parses `search <SCENARIO>` with `--strategy`, `--max-depth`,
  `--max-states`, and `--on-violation`, validates the scenario through the same
  concrete `ScenarioDef` resolver used by `run`, maps strategy and budget to the
  phase-6 advanced search API, executes local `--backend double search` through
  `TemporalGraph::search_with_strategy_and_failure_oracle_bounded_depth_sampled`
  after deriving a prefix-safe scenario-assertion failure oracle from the same
  search budget, honors `--max-depth` as a bounded
  decision-depth search run,
  accepts explicit `--on-violation`, and reports deterministic `search-run`
  output with `failure_oracle=none` or `failure_oracle=scenario-assertions`,
  exhaustion metadata,
  1/1 replay-oracle sampling counts over fat search materializations,
  and the RFC §13 status mapping for discovered failures, stop-mode
  budget exhaustion, and collect-mode budgeted campaigns. Engine
  failures discovered by the local-double search path now attach replayable CLI
  reproduction artifacts, `search-run` counterexample metadata, and the standard
  replay/debug footer commands. The assertion oracle lowers concrete
  prefix-safe, schedule-derived fault-active safety/unreachability violations and
  now accepts `--schedule-named-truths <path>` to load explicit data-only oracle
  inputs for named host predicates keyed by search-reconstructed schedule facts.
  The CLI validates the truth file schema, scenario node references, and
  duplicate canonical truth entries, and records the source digest and payload in
  `search-run` provenance and replayable reproduction artifacts; it does not
  prove the authored predicate semantics are prefix-safe. The engine now also
  exposes a trusted retained-log provider path that can lower prefix-safe
  safety/unreachability failures over event-log-backed predicates such as
  time/timers, network/console/I/O/node/assertion-state observables, raw
  guest-address coverage, physical-address/register memory samples, guest
  markers, and schedule fault-active facts when the caller supplies the exact
  `RecordedAssertionLog` for each reached configuration; configuration-bound
  retained-log evidence bundles can pair those logs with host-resolution tables,
  and an explicit resolution context admits symbolic coverage and
  virtual/symbolic memory leaves only when their host resolutions are supplied;
  terminal quiescence evidence on those bundles admits retained
  after-quiescence violations over quiescent predicates and terminal
  `sometimes`/`eventually` violations plus expected-reachable failures over
  retained-log predicates, plus terminal `sometimes` and required `reachable`
  guest assertion marker failures, while event-backed guest marker failures are
  limited to `always` false and `unreachable` true records. The local-double CLI
  path now has a hidden retained-evidence fixture input that validates
  `crucible.search-retained-evidence.v1` TOML, currently accepts
  `guest-marker` retained events for white-box-enabled nodes, terminal quantum
  `evaluation-boundary` entries, and
  `terminal-quiescence` evidence on the root or an explicit configuration hash.
  It rejects blocked terminal quiescence
  until blocker evidence is modeled, uses this fixture to exercise retained
  `after-quiescence` and terminal `sometimes` failures through local-double
  `search`, feeds the resulting configuration-bound
  `SearchRetainedLogAssertionEvidence` into the trusted retained-log provider,
  and records the retained evidence source digest and payload in `search-run`
  provenance and replayable reproduction artifacts.
  The default CLI path intentionally excludes absence-based existential/liveness
  failures, time/timer predicates, quiescence predicates outside explicit
  local-double terminal retained evidence, observable-event predicates, and
  named host predicates unless explicit schedule-named truth data is supplied;
  guest-marker predicates also require the local-double retained-evidence fixture
  today. It also parses `fuzz <FAMILY>` / `fuzz --family
  <path|hash>` with `--runs`, `--coverage basic-block`, and `--corpus`, maps the
  campaign seed into
  `CoverageGuidedFuzzConfig`, loads file-backed `crucible.scenario-family.v1`
  families, executes local `--backend double fuzz` through
  `ScenarioFamily::fuzz_coverage_guided` or
  `ScenarioFamily::fuzz_coverage_guided_corpus`, persists retained corpus
  artifacts through `LocalDagStore`, loads stored family hashes as strict
  scenario-family TOML from the configured DAG store, and reports deterministic
  `fuzz-run` output with generated-mutant, admission, retained-entry, store-put,
  and replay-oracle validation counts. Missing/corrupt stored family objects and
  unsupported backend targets fail explicitly. Production-QEMU search queries
  the engine-owned live `SearchFrontier`, expands its decisions, and realizes
  every child prefix in a fresh packaged-QEMU session before replay-oracle
  admission to the graph. Production-QEMU fuzz executes both warm-up and guided
  campaign iterations in fresh packaged-QEMU sessions and feeds the plugin's
  non-empty basic-block coverage back into the engine policy. The gate
  process-executes the packaged production `search` and `fuzz` commands against
  the unmodified stock Linux kernel, requires live branch-realization and
  coverage-feedback records, and checks their JSONL `final_outcome` records.
  Its search and fuzz workloads reuse the already-certified guest-only
  raw-Ethernet initramfs from the live network gate. With shift 0, a
  3.999-billion-nanosecond conservative link window, and a
  12-billion-icount terminal horizon, one search root expansion observes a
  live loss frontier and replay-validates both child choices in fresh two-node
  QEMU sessions. The fuzz family excludes pre-boot faults so a real guest
  quantum commits plugin coverage before feedback is evaluated; none of these
  bounds or traffic sources modify the Linux kernel.
  Production-QEMU search and fuzz now classify terminal property violations and
  concrete execution timeouts as findings, honor `--on-violation stop|collect`,
  retain one replay artifact per selected finding, and emit a canonical signed
  v3 findings ledger automatically (or at `--findings-out`). The ledger binds
  each artifact to exact streamed event frames, coverage, typed evidence, and
  its discovery signature so `triage --recompute-signatures` can verify the
  discovery boundary offline. When one execution streams multiple violated
  assertion transitions, the primary property signature is selected by stable
  assertion id, virtual time, instruction count, and node ordering; the ledger
  still binds the complete retained frame set.
  Both routes append pinned QEMU/plugin execution proof and preserve the
  backend-independent self-contained counterexample and corpus evidence.
- [x] **T-CLI-14** Implement `serve` (bind the API, session-actor-per-scenario,
  lock-free watch/query for many clients, bounded-quantum control ack, same
  sessions as in-process, `--read-only`). — satisfies [CLI-24]; spec §14.
  Completed under `checks.crucible.phase5.cliServeReadOnly`,
  `checks.crucible.phase5.cliServeMaxSessions`,
  `checks.crucible.phase5.cliServeMultiClient`, and
  `checks.crucible.phase5.cliServeShutdown`: the CLI accepts and advertises
  `serve --read-only` and `serve --max-sessions <n>`, rejects invalid
  max-session caps before binding, runs the production HTTP/2 daemon with the
  same lifecycle/session actor path used by the in-process API, enforces
  read-only mode against state-mutating lifecycle/control/send calls, admits
  concurrent Watch and Query clients while Control drives the same session,
  propagates server shutdown to active Control/Watch streams, maps serve
  bind/backend failures to exit 3, and the process-level harness proves an
  external shutdown signal exits with code 0.
- [x] **T-CLI-15** Implement and test the uniform exit-code mapping (§15) across
  run-capable subcommands and full machine-readable `--format json`/`jsonl`
  output of the event log + final outcome. — satisfies [CLI-25]; spec §15.
  Completed by
  `checks.crucible.phase5.cliExitMachineReadable`: the
  backend-routed output path now appends a machine-readable final-outcome record
  to canonical `json`/`jsonl` traces, keeps human summary/footer lines out of
  machine-readable stdout, process-tests local-double `run`, `save`, `search`,
  `fuzz`, marker-resolved QEMU `save`, `resume`, and `fork`, `replay --check`
  success/mismatch, and `replay --to <SAVEPOINT>` JSONL output with parsed
  command-specific canonical events plus `final_outcome`, and regression-tests
  the RFC §15 exit-code mapping for success, failure/divergence, timeout,
  crash/backend/identity, discovery,
  invalid-artifact/scenario, and usage classes. Requirement [CLI-25] is
  satisfied: the uniform exit-code mapping and machine-readable `json`/`jsonl`
  event-log + final-outcome contract is exercised across every current
  run-capable command path, including the live-QEMU run/save/resume/fork/search/
  fuzz routes.
- [x] **T-CLI-16** Implement `completions` (generate shell completions) and the
  `--help`/`--version` surface, verifying help text matches the normative copy in
  §6–§14 and stays in sync with flag behavior. — satisfies [CLI-6]; spec §2.1.
  Completed by
  `checks.crucible.phase5.cliCompletionsHelp`: the CLI
  generates shell completions; renders exact binary/version output; snapshots
  normalized exact subcommand usage and flag help for every §6–§14 command;
  makes every normative positional, alternative, and conditional input
  Clap-required, including `serve --listen`; process-tests the real binary's
  top-level and §6–§14 `--help`, exact long/short `--version`, Bash, Elvish,
  Fish, PowerShell, and Zsh completion scripts, all missing required inputs,
  missing-shell usage failure, normative alternative/conflict failures, and
  hidden gate-only help exclusion; and rejects future flags whose behavior is
  not implemented yet.
  Requirement [CLI-6] is satisfied: the rendered help and parser behavior are
  now checked from the same Clap command definition.
- [x] **T-CLI-17** Implement `triage` as a thin driver over the triage engine (34):
  cluster findings by signature, elect + optionally minimize a representative per
  cluster (each a self-contained, replayable/debuggable artifact), emit a report
  (`--policy`/`--minimize`/`--report`/`--format`/`--recompute-signatures`/`--compare`),
  with no clustering/minimization policy in the CLI. — satisfies [CLI-26]; spec
  §16; cross-ref 34.
  Completed under `checks.crucible.phase5.cliTriageWorkflow`: the CLI parses and
  plans the thin `triage <FINDINGS>` driver, loads empty and signed
  engine-owned property findings ledgers and signed v3 property/timeout ledgers
  through the local DagStore, clusters by
  discovery-time signatures, elects/minimizes representatives through the triage
  engine, emits deterministic reports, stores findings/result artifacts,
  supports `--policy`, `--minimize`, `--report`, global `--format`,
  `--recompute-signatures`, and `--compare`, rejects live daemon routing,
  rejects CLI-local `finding.*` signature sidecars, and fails artifact-only
  ledgers instead of fabricating missing discovery-time signature evidence.
  Requested minimization records timeout representatives as the deterministic
  `not-applicable-timeout` no-op rather than attempting an assertion shrink.
- [x] **T-CLI-18** Implement `debug` as a thin wrapper over the debugger (36) and
  the session read-only debugging commands (20 §4.4): instantiate +
  restore-nearest-checkpoint-replay to the coordinate
  (`--at`/`--at-event`/`--at-failure`/`--at-checkpoint`), open the gdbstub
  (`--node`/`--gdb-listen`, [SESS-32]), interactive reverse verbs, read-only
  default with `--allow-mutate` authorizing an explicit `fork-debug` that creates a
  labelled whole-world NON-CANONICAL branch,
  `--checkpoint-stride`; print the `crucible debug <artifact> --at-failure` footer
  line on a non-passing run. — satisfies [CLI-27]; spec §17, §4; cross-ref 36,
  20 §4.4.
  Completed under `checks.crucible.phase6.debugCliSurface`:
  `crucible debug` is parsed as a thin session/debugger wrapper with coordinate
  selection, target-aware coordinate defaults, gdbstub proxy listen/node controls,
  reverse verbs routed through the debug reverse-step/goto path instead of
  unsupported forward session step modes, read-only default, explicit
  `--allow-mutate` non-canonical branch planning, checkpoint-stride latency tuning,
  and the at-failure footer shared with failure artifact emission. The completed
  remote surface exposes explicit `fork-debug`, authenticated stable GDB relay,
  actor-owned goto/reverse operations, and fork-gated guest exec/PTY/SSH without
  admitting mutation or free control before the explicit transition.
  The daemonless local route remains an open production-executor task and fails
  with exit `4` before a generic QEMU probe; it never emits a successful
  planned-only result or claims that a debugger verb executed.
- [x] **T-CLI-19** Validate a discovered QEMU plugin by reading its ELF dynamic
  symbol table, not by scanning the file for symbol-name bytes, so a file that
  merely contains the string cannot impersonate a plugin.
  — satisfies [CLI-13], [CLI-14]; spec §7.
  - Defect (audit 2026-07-28): `crucible-cli/src/cli/backend.rs` accepts any
    candidate whose bytes contain `qemu_plugin_install` / `qemu_plugin_version`
    anywhere — including a comment, a string literal, or `.strtab`. The CLI's own
    test fixture passes validation by writing exactly those byte sequences into a
    file that is not a plugin.
  - Plan: parse the ELF64 `.dynsym` / `.dynstr` sections already located by
    `validate_elf64_header`, require both symbols to be defined (not `SHN_UNDEF`)
    and globally visible, and reject on absence with the existing discovery-help
    error. Keep the byte scan only as a fast pre-filter, never as the decision.
  - Gate: `checks.crucible.phase5.cliBackendSelection` gains negative controls —
    an ELF with the names only in `.strtab`, an ELF with both symbols undefined,
    and a non-ELF file containing the names — each of which MUST be rejected.
  - Completed by the ELF64 section-table parser in
    `crates/crucible-cli/src/cli/backend.rs`. It resolves `.dynsym` through its
    linked string table, accepts only defined globally visible symbols, and the
    backend-selection gate executes all three specified negative controls.

- [x] **T-CLI-20** Make the backend-selection evidence falsifiable: derive the
  local/remote proof predicates from observed execution rather than from literals
  set on the same construction path, and remove the environment escape hatches
  that disable the live probe in the tests that certify it.
  — satisfies [CLI-5], [CLI-7]; spec §3.
  - Defect (audit 2026-07-28): `proves_t_cli_3` inspects only fields written as
    constants in the arm of `plan_backend_selection` that builds the plan, so it
    cannot return false and both of its guard sites are dead. Separately,
    `crucible-cli/tests/machine_readable.rs` sets
    `CRUCIBLE_TEST_SKIP_LIVE_QEMU_PROBE=1`, and the verify probe helper returns an
    empty vector under `#[cfg(test)]`, so the divergence check over probe reports
    iterates nothing — the tests that certify `--backend qemu` are the ones that
    switch it off.
  - Plan: (1) replace the literal-comparison predicate with an assertion over the
    executed backend's recorded identity (the discovered QEMU build id and plugin
    ABI actually used by the run); (2) delete the `#[cfg(test)]` empty-vector
    return and the skip variable, replacing them with an injected fake backend
    that still exercises the divergence comparison; (3) keep `--backend double`
    as the only sanctioned way to run without QEMU, so degradation is explicit
    ([CLI-7]).
  - Gate: `checks.crucible.phase5.cliBackendSelection` and
    `.cliVerifyWorkflow` MUST fail when two probe reports differ and when the
    recorded build identity does not match the discovered binary.
  - Completed by `checks.crucible.phase5.cliBackendSelection`: backend command
    runners now return observed route evidence separately from the selection
    plan, and dispatch validates that evidence only after the local or remote
    execution path returns. Live-QEMU selftest probes use an injected runner
    boundary whose production implementation always boots the packaged backend;
    identical reductions must produce identical probe evidence. The debug-only
    environment bypass and the `cfg(test)` empty-probe implementation were
    removed. Focused negative controls inject a mismatched QEMU build identity
    and divergent probe fingerprints, and both fail closed.

- [x] **T-CLI-21** Complete production artifact replay through fresh QEMU
  processes for every local-QEMU artifact producer (`run`, `verify`, `search`,
  `fuzz`, and `fork`). — satisfies [CLI-22]; spec §12.
  - The v3 artifact embeds one compact scenario, one typed model reproduction
    and replay-state proof, a v2 live-QEMU recipe, exact QEMU event bytes, and
    typed fingerprint evidence. `run`, `verify`, and `fuzz` retain the full
    execution-fingerprint stream; `search` and `fork` retain the terminal
    all-node snapshot and declare that narrower scope in the recipe.
  - Fork recipes distinguish an unchanged resume from reseed and contiguous
    prefix-override branches. The retained base owns every pre-branch decision;
    only strictly increasing post-branch fault/network choice indices may be
    forced during child execution. Fresh-QEMU replay reconstructs validated
    checkpoint evidence for that retained base and re-enters the resume
    lifecycle used by the fork producer; treating a fork artifact as a genesis
    run changes both boundary commands and their acknowledgement transcript.
    Search recipes also retain the exploration run-ceiling and quantum-budget
    values that bounded the finding.
  - Interactive artifact capture fails closed. A command name without its
    exact acknowledged decision/frontier coordinate is not a replay recipe.
    Non-interactive startup and initial controls are separate ordered,
    closed-set recipe fields; all resulting acknowledgements are compared with
    the fresh session.
  - The CLI rejects v2 in production and has no model-only fallback. It first
    runs the pure reduction preflight, then launches the pinned packaged
    QEMU/plugin pair and compares the terminal status/outcome/configuration,
    frontier/quanta/budget tuple, canonical event bytes, and declared-scope
    fingerprint bytes.
  - Ordinary replay and `--check` execute one fresh QEMU session;
    `--to <savepoint>` performs the same live replay before typed-prefix and
    replay-oracle target validation, including self-contained terminal hashes;
    `--bisect <other-artifact>` live-replays both sides before locating evidence
    divergence.
  - Completed by `checks.crucible.phase5.cliReplayCheck`. Its contract matrix
    admits exactly `run`, `verify`, `search`, `fuzz`, and `fork`, exercises the
    search/fork scope and lifecycle rules plus unchanged-fork resume, and rejects
    unknown producers, duplicate/pre-branch choices, incompatible scope,
    missing fork recipes, and unknown controls. The process half creates a
    real two-VM packaged-QEMU timeout artifact and proves ordinary, `--check`,
    `--to`, and both-sided `--bisect` live replay.
