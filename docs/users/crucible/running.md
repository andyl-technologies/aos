# Running Crucible

This page covers the local packaged-QEMU path. See [Daemon operation](daemon.md)
before using `--daemon`.

## Global options

Global options may appear before or after the subcommand, but placing them
before it makes examples easier to scan.

| Option | Purpose |
|---|---|
| `--seed <u64|hex>` | Set root entropy and override `CRUCIBLE_SEED`. |
| `--backend <auto|qemu>` | Select the local production backend. Default: `auto`. |
| `--daemon <addr>` | Route supported operations to an HTTP/2 daemon. |
| `--qemu <path>` | Select a patched QEMU binary explicitly. |
| `--plugin <path>` | Select the matching Crucible QEMU plugin explicitly. |
| `--store <path>` | Select the local content-addressed DAG store. |
| `--format <jsonl|json|table|markdown>` | Override terminal-aware trace or report rendering. |
| `--trace <path>` | Also write the canonical event log to a file. |
| `--artifact-dir <path>` | Select the failure/savepoint artifact directory. Default: `./.crucible`. |
| `-v`, `-vv` | Reserved for diagnostic verbosity. |
| `-q`, `--quiet` | Suppress non-essential standard output. |

`markdown` is valid for triage reports, not canonical event-log traces.

## Backend discovery

For both QEMU and the plugin, discovery order is:

1. `--qemu` or `--plugin`;
2. `CRUCIBLE_QEMU` or `CRUCIBLE_PLUGIN`;
3. compile-time paths from the AOS package closure.

Crucible does not search the host `PATH` for QEMU. It checks that QEMU is the
patched build, reads the installed build marker, reads the plugin's ELF marker,
and verifies build identity and shared-memory ABI compatibility before running.

`--backend auto` does not mean "use anything available." In a production build
it resolves to the validated QEMU backend or fails with status `4`.

## Seed resolution

Run-capable commands resolve their seed in this order:

1. `--seed`;
2. `CRUCIBLE_SEED`;
3. one seed generated from host entropy before execution begins.

The resolved seed is then fixed as run identity. Host entropy is not consulted
again to make canonical execution decisions.

Pin seeds in CI and in any command transcript intended for reproduction:

```sh
./result/bin/crucible \
  --seed 0x9f86d081884c7d65 \
  run scenario.toml
```

## Terminal conditions and budgets

`run`, `resume`, and `fork` accept these terminal conditions:

- `quiescence` — stop when the scheduler becomes quiescent; this is the default.
- `virtual-time` — stop at the required `--max-virtual-time` budget.
- `property` — stop on a property verdict.
- `stopped` — stop only on an explicit stopped state.

Virtual-time budgets accept a positive integer followed by one of:

```text
ticks  tick  ns  us  ms  s
```

No suffix means ticks. Fractional durations are not accepted.

`run` also accepts `--max-quanta <n>` as an independent scheduler-work bound;
`resume` and `fork` do not currently expose that flag:

```sh
./result/bin/crucible \
  run scenario.toml \
  --until virtual-time \
  --max-virtual-time 30s \
  --max-quanta 10000
```

Budget exhaustion is a timeout, not a property failure. A bounded run stops at
exactly the requested scheduler-quantum boundary unless it reaches another
terminal condition first; observer polling does not add extra quanta.

Ordinary local QEMU lifecycle operations admit up to 40 billion retired
instructions per node and allow 300 wall-clock seconds for each node step.
`--max-quanta` is the run-level scheduler and control-plane bound; it does not
raise the per-node instruction ceiling. Live search uses separate, tighter
exploration bounds.

`run --save-on <fail|always|never>` controls terminal checkpoint
materialization. The default is `never`. `fail` materializes only a non-passing
outcome; `always` materializes every outcome. The resulting checkpoint reference
is reported only after its replayable closure and lookup index are stored in the
DAG store. The `run-store` output row records their content hashes and store
path. Use the dedicated `save` command when you need an exported
`.crucible-savepoint` handle at a chosen boundary.

## Output formats

Without `--format`, Crucible selects `table` when standard output is a terminal
and `jsonl` when output is redirected or piped. JSONL emits one canonical event
entry per line and ends with a `final_outcome` entry. `json` emits the same
entries as one document. `table` emits human-oriented summaries.

An explicit `--format` always wins. Use one in scripts whose output contract
must not depend on their execution environment.

`--trace` does not select a separate diagnostic trace. It writes the same
canonical event-log rendering selected by `--format`:

```sh
./result/bin/crucible \
  --format jsonl \
  --trace run.jsonl \
  --quiet \
  run scenario.toml
```

With `--quiet`, the trace file is still written. For automation, prefer JSONL
plus exit codes instead of scraping table output.

## Artifacts and store layout

If `--store` is absent, the local DAG store defaults to:

```text
<artifact-dir>/store
```

The default artifact directory is `./.crucible`. Non-passing executions write
reproduction artifacts named approximately:

```text
repro-<failure-kind>-<digest>.crucible
```

Savepoints use:

```text
savepoint-<label>-<digest>.crucible-savepoint
```

Keep a savepoint handle with the DAG store that produced it. A self-contained
failure artifact embeds its critical reproduction material, but a store-backed
component or direct checkpoint hash still requires the corresponding store.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Passed, deterministic, gates green, or clean shutdown. |
| `1` | Property failure, divergence, replay mismatch, counterexample, or triage failure. |
| `2` | Virtual-time or scheduler-quantum timeout. |
| `3` | Crash, daemon/server failure, replay-oracle violation, or build-identity mismatch. |
| `4` | Backend discovery or configuration failure. |
| `5` | Invalid/unresolvable scenario, artifact, store object, or local I/O input. |
| `64` | Command-line usage error. |

The final machine-readable outcome includes both status and exit code. Scripts
should branch on the process status and retain the JSONL output for diagnosis.

## Self-test

The production self-test runner currently supports these live-QEMU gates:

```text
gate:single-vm-fingerprint
gate:any-guest
gate:qemu-inert
```

Run the default live subset with:

```sh
./result/bin/crucible selftest
```

To select gates explicitly, pass a comma-separated list:

```sh
./result/bin/crucible \
  selftest \
  --gates gate:single-vm-fingerprint,gate:qemu-inert
```

Other gates are exercised by repository checks; they are not all runnable from
the packaged production CLI.

## Shell completions

Generate completions for Bash, Elvish, Fish, PowerShell, or Zsh:

```sh
./result/bin/crucible completions zsh > _crucible
```

Install the generated file through the shell's normal completion mechanism.
Generation is offline and does not require backend discovery.
