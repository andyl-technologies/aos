# Crucible Reference

This page is the exhaustive reference for the shipped `crucible` command-line
interface and canonical scenario TOML. Use the task-oriented guides for worked
procedures and this page to look up exact option names, accepted values, defaults,
required fields, and nested `kind` tables.

The Rust types and Clap declarations are the implementation source of truth.
Unknown TOML fields and unknown closed-vocabulary values are rejected. Generate a
scenario through the Rust builder and `to_canonical_toml` whenever possible; its
content-addressed IDs are computed values, not labels to invent by hand. See the
[scenario authoring guide](scenarios.md) and the
[Nginx/Curl tutorial](quickstart.md).

Direct implementation references:

- [Clap command and option declarations](../../../crates/crucible-cli/src/main.rs)
- [Canonical TOML schema and conversions](../../../crates/crucible/src/model/toml.rs)
- [Fault types and parameter validation](../../../crates/crucible/src/model/topology_faults.rs)
- [Properties and predicate types](../../../crates/crucible/src/model/plan_properties.rs)

## Value conventions

| Notation or value | Meaning |
| --- | --- |
| `<path>` | Host path. Relative paths are resolved from the command's working directory. |
| `<hash>` | Content address in `blake3:<64 lowercase hexadecimal digits>` form. |
| `<path-or-hash>` | A local file/path or an object resolvable from `--store`. |
| `<dur>` | Positive integer followed by no suffix, `tick`, `ticks`, `ns`, `us`, `ms`, or `s`. No suffix means ticks; one tick is one nanosecond. |
| `*_nanos` | Unsigned integer duration in virtual nanoseconds. |
| `*_ticks` | Unsigned integer virtual-time or scheduler coordinate. |
| `*_basis_points` | Integer probability or factor measured in basis points. Probabilities accept `0..=10000`, where 10,000 is 100%. |
| `loss_millionths` | Integer link probability in `0..=1000000`, where 1,000,000 is 100%. |
| `field?` in this page | Optional field. The question mark is documentation notation and is not part of the TOML key. |

## Command-line interface

### Global options

Global options may appear before or after the subcommand.

| Option | Accepted value and default | Purpose | Guide |
| --- | --- | --- | --- |
| `--seed <u64\|hex>` | Unsigned decimal, `0x` hexadecimal, or canonical seed text; otherwise `CRUCIBLE_SEED`, then scenario seed | Override the root entropy. | [Seed resolution](running.md#seed-resolution) |
| `--backend <auto\|qemu>` | `auto` (default), `qemu` | Select or discover the local backend. Production builds expose QEMU only. | [Backend discovery](running.md#backend-discovery) |
| `--daemon <addr>` | Host/port or HTTP endpoint | Send a supported lifecycle operation to a daemon instead of running locally. | [Daemon operation](daemon.md) |
| `--qemu <path>` | Discovered when omitted | Override the packaged patched-QEMU executable. Must be paired with `--plugin`. | [Backend discovery](running.md#backend-discovery) |
| `--plugin <path>` | Discovered when omitted | Override the matching QEMU plugin. Must be paired with `--qemu`. | [Backend discovery](running.md#backend-discovery) |
| `--store <path>` | Command-specific default below `--artifact-dir` | Set the content-addressed store root. | [Artifacts and store](running.md#artifacts-and-store-layout) |
| `--format <jsonl\|json\|table\|markdown>` | Terminal: `table`; non-terminal: `jsonl` | Select report rendering. `jsonl` and `json` are stable machine formats. | [Output formats](running.md#output-formats) |
| `--trace <path>` | Standard output | Write the canonical event-log stream to a file. | [Output formats](running.md#output-formats) |
| `--artifact-dir <path>` | `./.crucible` | Set the failure-artifact and default savepoint/report directory. | [Artifacts and store](running.md#artifacts-and-store-layout) |
| `-v`, `--verbose` | Repeatable; default count `0` | Increase diagnostic verbosity. | [Running](running.md) |
| `-q`, `--quiet` | Boolean; default off | Suppress non-essential output. | [Running](running.md) |
| `-h`, `--help` | Built in | Print top-level or subcommand help. | This reference |
| `-V`, `--version` | Built in | Print the Crucible version. | This reference |

Backend values:

| Value | Meaning |
| --- | --- |
| `auto` | Discover and validate the packaged QEMU/plugin pair. |
| `qemu` | Require the local patched-QEMU production backend. |

Output-format values:

| Value | Meaning |
| --- | --- |
| `jsonl` | Newline-delimited canonical JSON records; preferred for streaming programs. |
| `json` | One JSON document. |
| `table` | Human-readable terminal table. |
| `markdown` | Markdown report, especially useful for retained triage output. |

### Commands

| Command | Purpose | Detailed guide |
| --- | --- | --- |
| `run` | Execute a scenario to a terminal condition. | [Running](running.md) |
| `verify` | Repeat a scenario and compare fingerprints and canonical logs, or compare artifacts. | [Reproduction](reproduction.md#verify-repeated-execution) |
| `selftest` | Run packaged determinism gates. | [Self-test](running.md#self-test) |
| `save` | Stop at a deterministic coordinate and export a savepoint. | [Savepoints](reproduction.md#savepoints) |
| `resume` | Continue from a savepoint or checkpoint. | [Resume](reproduction.md#resume) |
| `fork` | Continue from a savepoint with a new seed or decision override. | [Fork](reproduction.md#fork) |
| `replay` | Validate and reduce a recorded reproduction artifact. | [Replay](reproduction.md#replay) |
| `search` | Explore a bounded schedule space. | [State-space search](exploration.md#state-space-search) |
| `fuzz` | Sample a scenario family using basic-block coverage. | [Coverage-guided fuzzing](exploration.md#coverage-guided-fuzzing) |
| `triage` | Cluster, deduplicate, compare, and minimize findings. | [Findings and triage](exploration.md#findings-and-triage) |
| `debug` | Inspect a live daemon session at a coordinate; local artifact/savepoint execution currently fails closed. | [Debugging](debugging.md#debug-command) |
| `serve` | Run the remote lifecycle API. | [Daemon operation](daemon.md) |
| `completions` | Generate shell completion definitions. | [Shell completions](running.md#shell-completions) |

### `run`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `SCENARIO` | Required | Canonical scenario TOML path or content hash. |
| `--until <quiescence\|virtual-time\|property\|stopped>` | Default `quiescence` | Select the terminal condition; see [terminal values](#terminal-and-save-boundary-values). |
| `--max-virtual-time <dur>` | Required with `--until virtual-time` | Stop with timeout after this virtual-time budget. |
| `--max-quanta <n>` | Optional | Stop at an exact scheduler-quantum boundary unless another terminal condition occurs first. |
| `--interactive` | Off | Pause at genesis and read interactive commands from standard input. |
| `--save-on <fail\|always\|never>` | Default `never` | Materialize an outcome savepoint only on failure, for every outcome, or never. |
| `--watch` | Off | Collect live session-status updates alongside run evidence. |

`--save-on` values:

| Value | Meaning |
| --- | --- |
| `fail` | Save only a failing outcome. |
| `always` | Save passing, failing, and timeout outcomes. |
| `never` | Do not create an outcome savepoint. |

### `verify`

Exactly one of `SCENARIO` and `--compare` is required.

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `SCENARIO` | Alternative to `--compare` | Scenario path or content hash to execute repeatedly. |
| `--runs <n>` | Default `2` | Number of executions to compare. |
| `--adversarial` | Off | Run under the hostile host-condition matrix. |
| `--bisect` | Off | On divergence, run deterministic divergence bisection and print its report. |
| `--compare <a> <b>` | Alternative to `SCENARIO` | Compare two existing reproduction artifacts using their embedded identities, without executing a scenario or generating a seed. |

### `selftest`

| Option | Required/default | Meaning |
| --- | --- | --- |
| `--gates <list>` | All applicable gates | Run a comma-separated gate subset. |
| `--with-qemu` | Hidden production option; off | Include QEMU-backed gates. This is primarily a package/gate surface. |

Test-double builds also compile a test-only `--corpus <path>` fixture-manifest
option; it is not part of the shipped production interface.

### `save`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `SCENARIO` | Required | Scenario path or content hash. |
| `--at <virtual-time\|quiescence\|property\|marker>` | Required | Select the save boundary; see [boundary values](#terminal-and-save-boundary-values). |
| `--label <name>` | Optional | Add a human-readable savepoint label. |
| `--max-virtual-time <dur>` | Required with `--at virtual-time` | Exact virtual-time coordinate at which to save; stagnation and overshoot fail closed. |
| `--property <assertion>` | Required with `--at property` | Assertion ID whose violated phase supplies the boundary. |
| `--marker <name>` | Required with `--at marker` | Guest-marker ID whose observation supplies the boundary. |
| `--out <path>` | Default below `--artifact-dir` | Select the exported savepoint-handle path. |

Savepoint handle schema v3 records the selected property violation or guest
marker, its exact boundary proof, and a content-addressed canonical predicate
payload. The reader rejects mismatched selectors, predicates, terminal
conditions, frontiers, and undeclared property identities. The canonical trace
exposes the same proof as `save_boundary_proof`, with percent-encoded selector
values. Older v2 handles remain readable but lack selector provenance.

A property or marker miss returns exit 3 without a handle. An explicit
`--trace` is still honored and ends with `save_boundary_failure`, preserving the
partial control trail for diagnosis.

### `resume`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `SAVEPOINT` | Required | Savepoint-handle path or checkpoint content hash. |
| `--until <quiescence\|virtual-time\|property\|stopped>` | Default `quiescence` | Select the resumed terminal condition. |
| `--max-virtual-time <dur>` | Required with `--until virtual-time` | Stop with timeout after this virtual-time budget. |
| `--interactive` | Off | Drive the resumed session from standard input. |
| `--watch` | Off | Collect live session-status updates. |

### `fork`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `SAVEPOINT` | Required | Savepoint-handle path or checkpoint content hash. |
| `--override <decision=value>` | Repeatable; conflicts with global `--seed` | Pin a scheduler-recorded live World-network choice. The percent-encoded point starts with `live-world-network/`; the value uses the canonical loss/duplicate/corrupt choice vocabulary. |
| `--until <quiescence\|virtual-time\|property\|stopped>` | Default `quiescence` | Select the child branch's terminal condition. |
| `--max-virtual-time <dur>` | Required with `--until virtual-time` | Stop with timeout after this virtual-time budget. |
| `--label <name>` | Optional | Label the forked branch. |
| `--interactive` | Off | Drive the forked session from standard input. |
| `--watch` | Off | Collect live session-status updates. |

### `replay`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `ARTIFACT` | Required | v3 reproduction-artifact path; production replay requires the matching packaged QEMU/plugin identity. |
| `--check <original-log>` | Optional | After live replay succeeds, require byte-identical canonical JSONL output. |
| `--to <savepoint>` | Optional | Live-replay the artifact, then validate a target savepoint handle or checkpoint hash as its typed prefix. A v3 artifact can resolve its own terminal checkpoint hash without a separate store object. |
| `--bisect <other-artifact>` | Optional | Live-replay both artifacts, then locate their first evidence divergence. |

The v3 artifact's live recipe declares its fingerprint evidence scope. Run,
verify, and fuzz use the full execution stream; search and fork use one terminal
sample per VM node. Interactive control recipes are rejected until exact command
timing can be reproduced.

### `search`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `SCENARIO` | Required | Scenario path or content hash. |
| `--strategy <bfs\|dfs\|guided>` | Default `bfs` | Expand breadth-first, depth-first, or by coverage guidance. |
| `--max-depth <n>` | Optional | Bound decision depth. |
| `--max-states <n>` | Default `1` | Bound materialized states. Set this explicitly for useful campaigns. |
| `--on-violation <stop\|collect>` | Engine default `stop` when omitted | Stop at the first property/timeout finding or continue within the supplied budget. |
| `--findings-out <path>` | Content-addressed path below `--artifact-dir` | Override the signed findings-ledger output path. |
| `--schedule-named-truths <path>` | Optional | Load schedule-named assertion truth data. |
| `--retained-evidence <path>` | Hidden/internal | Load backend-retained assertion evidence for gate workflows. |

Search policy values:

| Option value | Meaning |
| --- | --- |
| `--strategy bfs` | Expand the shallowest frontier first. |
| `--strategy dfs` | Follow a frontier deeply before returning to siblings. |
| `--strategy guided` | Use coverage feedback to prioritize frontiers. |
| `--on-violation stop` | Stop after the first counterexample. |
| `--on-violation collect` | Continue exploring within the configured budget and retain every distinct property or timeout finding. |

### `fuzz`

Supply the family either positionally or with `--family`, never both.

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `FAMILY` | Alternative to `--family` | Built-in name, family TOML path, or content hash. |
| `--family <path\|hash>` | Alternative to `FAMILY` | Explicit named form of the family input. |
| `--runs <n>` | Default `1` | Number of concrete family instances to run. |
| `--coverage <basic-block>` | Default `basic-block` | Select the coverage feedback signal. |
| `--corpus <path>` | Optional | Seed and regression corpus directory. |
| `--on-violation <stop\|collect>` | Default `stop` | Stop at the first property/timeout finding or retain findings through the run budget. |
| `--findings-out <path>` | Content-addressed path below `--artifact-dir` | Override the signed findings-ledger output path. |

### `triage`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `FINDINGS` | Required | Signed findings ledger emitted by `search` or `fuzz`. |
| `--policy <coarse\|default\|fine\|exact>` | Default `default` | Select how much failure evidence participates in a cluster signature. Finer policies split more findings. |
| `--minimize <none\|representative\|all>` | Default `representative` | Skip minimization, minimize one deterministic representative per cluster, or minimize every selected representative. |
| `--report <dir>` | Default below `--artifact-dir` | Write per-cluster reports here. |
| `--recompute-signatures` | Off | Recompute signatures and fail if discovery-time bytes drift. |
| `--compare <other-triage-result>` | Optional | Compare against another content-addressed triage result. |

Triage policy values:

| Option value | Meaning |
| --- | --- |
| `--policy coarse` | Group aggressively using coarse evidence. |
| `--policy default` | Use the normal failure-signature policy. |
| `--policy fine` | Include more evidence and split more findings. |
| `--policy exact` | Require exact signature evidence. |
| `--minimize none` | Report representatives unchanged. |
| `--minimize representative` | Minimize the content-address-least representative per cluster. |
| `--minimize all` | Minimize every selected representative. |

### `debug`

Exactly one target is required: positional `ARTIFACT|SAVEPOINT` or `--session`.
The four coordinate selectors are mutually exclusive.

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `ARTIFACT\|SAVEPOINT` | Alternative to `--session` | Attach to a retained artifact or savepoint. |
| `--session <id:epoch:seed>` | Alternative to positional target | Attach to a running daemon session. The seed is exactly 64 lowercase hexadecimal digits. |
| `--at <coord>` | Optional coordinate | Open at a virtual-time or node-icount coordinate. |
| `--at-event <seq>` | Optional coordinate | Open at an event-log sequence. |
| `--at-failure` | Optional coordinate | Open at the recorded failure point. |
| `--at-checkpoint <hash>` | Optional coordinate | Open at a checkpoint content address. |
| `--node <id>` | Optional | Select the node whose gdbstub is attached. |
| `--gdb-listen <addr>` | Optional | Listen for mediated GDB-protocol clients here. |
| `--read-only` | Off; conflicts with `--allow-mutate` | Preserve the canonical run and prohibit mutation. |
| `--allow-mutate` | Off | Fork a non-canonical debug branch for mutation. |
| `--checkpoint-stride <n>` | Optional | Bound reverse-step replay distance with opportunistic checkpoints. |
| `--record-transcript <path>` | Off | Exclusively create a bounded branch-local guest-channel transcript. |
| `--guest-idle-timeout <dur>` | `30s` | Fail and clean up when a guest agent produces no response for this duration. |

Debugger verbs:

| Verb | Arguments | Meaning |
| --- | --- | --- |
| `attach-gdb` | None | Open the mediated gdbstub channel. |
| `fork-debug` | None | Create the explicit non-canonical whole-world branch required for guest introspection. |
| `goto` | `<coord>` | Move to another accepted debug coordinate. |
| `reverse-step` | `instruction`, `quantum`, `event`, `assertion`, or `timer` | Step backward by one deterministic grain. |
| `reverse-continue` | `<condition>` | Continue backward to a matching condition. |
| `exec` | `-- <argv...>` | Execute argv directly through the forked guest agent. |
| `pty` | `[--columns <n>] [--rows <n>] -- <argv...>` | Bridge a local terminal to a guest PTY. |
| `ssh` | None | Bridge bytes to the SSH server configured in the guest agent. |

### `serve`

| Option | Required/default | Meaning |
| --- | --- | --- |
| `--listen <addr>` | Required | Bind the cleartext HTTP/2 lifecycle API. |
| `--max-sessions <n>` | Optional; must be greater than zero | Cap concurrent live sessions. |
| `--read-only` | Off | Permit query/watch calls and reject mutations. |

### `completions`

`completions SHELL` writes a completion definition to standard output.

| `SHELL` | Output |
| --- | --- |
| `bash` | Bash `complete` definition. |
| `elvish` | Elvish argument completer. |
| `fish` | Fish `complete` definition. |
| `powershell` | PowerShell argument completer registration. |
| `zsh` | Zsh `_crucible` completion definition. |

### Terminal and save-boundary values

| Value | Used by | Meaning |
| --- | --- | --- |
| `quiescence` | `run --until`, `resume --until`, `fork --until`, `save --at` | Stop when the scheduler has no immediately runnable work. This is the default terminal condition. |
| `virtual-time` | `--until`, `save --at` | Stop at the positive `--max-virtual-time` duration. |
| `property` | `--until`, `save --at` | Stop on a property verdict; `save` requires `--property` and selects that assertion's violated phase. |
| `stopped` | `--until` only | Stop only after an explicit stopped state. |
| `marker` | `save --at` only | Save after observing the named `--marker`. |

Interactive command keywords and current payload limitations are documented in
[Interactive control](debugging.md#interactive-run-control).

## Canonical scenario document

A scenario contains exactly four top-level tables. The `id` on each top-level
table is a validated content address generated from that canonical component;
changing its content requires regenerating that ID. Nested node, device, event,
and assertion IDs are scenario-local names instead.

| Table | Required fields | Contents |
| --- | --- | --- |
| `[scenario]` | `id`, `seed`, `app_random_draw_cap` | Scenario identity, deterministic seed material, and maximum guest application-random draws. |
| `[world]` | `id` | VM nodes, I/O device sub-nodes, and links. `node` and `link` arrays default empty. |
| `[plan]` | `id` | Exactly one plan representation: scheduled entries, fault plan, or event graph. |
| `[properties]` | `id` | Named assertions. `assertion` defaults empty. |

### `[scenario]` fields

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | content-address string | Hash of the complete scenario definition. Generated and validated. |
| `seed` | canonical seed string | Root deterministic seed, commonly a full `0x` byte string. |
| `app_random_draw_cap` | unsigned integer or decimal string | Maximum white-box application-random draws admitted by the scenario. Zero rejects all such draws. |

### `[[world.node]]` VM fields

VM rows are untagged: they do not carry `kind`.

| Field | Type/default | Meaning |
| --- | --- | --- |
| `id` | Required string | Unique scenario-local node name. |
| `arch` | `x86_64` (default) or `aarch64` | Guest architecture. |
| `memory_mib` | Default `512` | Guest memory in MiB. |
| `cmdline` | Default empty string | Additional kernel command line. |
| `smp_vcpus` | Required unsigned integer | Virtual CPU count. |
| `icount_shift` | Required unsigned integer | QEMU instruction-count shift. |
| `kernel` | Optional content address | Per-node kernel artifact. The production lifecycle may supply a configured artifact when absent. |
| `root_image` | Optional content address | Per-node root-image artifact. |
| `initrd` | Optional content address | Per-node initrd artifact. |
| `ready_point` | Required nested table | Deterministic snapshot point; see below. |
| `white_box` | Required `enabled` or `disabled` | Permit or prohibit the guest-host white-box channel. |

VM enum values:

| Field | Value | Meaning | Reference |
| --- | --- | --- | --- |
| `arch` | `x86_64` | Run an x86-64 guest. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `arch` | `aarch64` | Run an AArch64 guest. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `white_box` | `disabled` | Prohibit the optional guest-host observation/control channel. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `white_box` | `enabled` | Allow typed guest markers and application-random requests through the white-box doorbell. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |

`[world.node.ready_point]` kinds:

| `kind` | Required fields | Meaning | Reference |
| --- | --- | --- | --- |
| `fixed_icount` | `retired: u64` | Snapshot after exactly this many retired guest instructions. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `network_idle` | `window_nanos: u64` | Snapshot after the first network-idle window of this length. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `console_marker` | `marker: string` | Snapshot when the guest console emits the marker. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `agent_signal` | None | Snapshot when the optional in-guest agent signals readiness. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |

### `[[world.node]]` I/O device fields

I/O rows share the VM node array but carry a `kind`. Every field listed for the
selected kind is required.

| `kind` | Required fields | Meaning | Reference |
| --- | --- | --- | --- |
| `block` | `id`, `owner`, `shift_bits`, `artifact`, `artifact_length`, `read_base_ns`, `write_base_ns`, `flush_ns`, `get_length_ns`, `per_byte_ns` | Deterministic block sub-node backed by a content-addressed base image. `owner` is a VM ID; latency is the operation base plus the per-byte component. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `nine_p` | `id`, `owner`, `shift_bits`, `artifact`, `control_ns`, `data_ns`, `per_byte_ns` | Deterministic read-only 9p filesystem sub-node. `owner` is a VM ID; control/data bases and the per-byte term model completion latency. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |

For both kinds, `id` is the unique device name, `shift_bits` maps device work to
virtual time, and `artifact` is a content-addressed blob reference.

### `[[world.link]]` fields

| Field | Type | Meaning |
| --- | --- | --- |
| `endpoint_a`, `endpoint_b` | Required node IDs | The two distinct VM endpoints. Ordering is canonicalized. |
| `latency_nanos` | Required unsigned integer | One-way base latency. |
| `jitter_nanos` | Required unsigned integer | Maximum subtractive jitter. `latency_nanos - jitter_nanos` must remain above Crucible's minimum. |
| `loss_millionths` | Required integer `0..=1000000` | Baseline deterministic link-loss probability. |
| `bandwidth_bps` | Optional positive integer | Baseline bits-per-virtual-second cap. |

Taxonomy faults refer to a unique link by its link ID. For a simple unique pair,
the readable compatibility form is `<endpoint-a>--<endpoint-b>` using canonical
endpoint order. Prefer IDs emitted by a Rust scenario builder.

## Plans and events

### `[plan]` representations

The three row arrays are mutually exclusive. `kind` may be omitted only when the
populated row array makes the representation unambiguous.

| `kind` | Row array | Meaning | Reference |
| --- | --- | --- | --- |
| `entries` | `[[plan.entry]]` | Legacy membership-fault activation/heal schedule. An empty plan also resolves to this kind. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `fault_plan` | `[[plan.fault_entry]]` | Full taxonomy-fault schedule with finite, permanent, and heal entries. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `event_graph` | `[[plan.event]]` | Conditions trigger actions, including faults, timers, savepoints, forks, and terminal verdicts. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |

### `[[plan.entry]]` kinds

| `kind` | Required fields | Meaning |
| --- | --- | --- |
| `activate` | `at_ticks`, `tag`, `fault` | Activate a nested [membership fault](#membership-fault-kinds) at exact virtual time. |
| `heal` | `at_ticks`, `tag` | Remove the active fault with this tag at exact virtual time. |

### `[[plan.fault_entry]]` kinds

| `kind` | Required fields | Meaning |
| --- | --- | --- |
| `at` | `at_ticks`, `duration_nanos`, `tag`, `fault` | Activate a nested [taxonomy fault](#taxonomy-fault-kinds) and auto-heal after the duration. |
| `permanent_at` | `at_ticks`, `tag`, `fault` | Activate a taxonomy fault with no automatic heal. |
| `heal` | `at_ticks`, `tag` | Explicitly heal a previously declared tag. |

For example, this is the complete nesting for a finite 25% network-loss fault:

```toml
[plan]
id = "blake3:<generated-plan-hash>"
kind = "fault_plan"

[[plan.fault_entry]]
kind = "at"
at_ticks = 1000000000
duration_nanos = 5000000000
tag = "lossy-link"

[plan.fault_entry.fault]
kind = "network_loss"
link = "client--server"
rate_basis_points = 2500
```

Use the scenario builder to calculate the real `plan.id` after configuring the
fault. The placeholder above is explanatory and is not valid canonical input.

### `[[plan.event]]` fields

| Field | Type/default | Meaning |
| --- | --- | --- |
| `id` | Required string | Unique event ID. |
| `trigger` | Optional predicate table or DSL string | Condition that must become true. Omission creates an unconditional event. |
| `action` | Required action table | Operation performed when the trigger fires. |
| `policy` | `once` (default) or `repeatable` | Fire at most once, or fire again on later false-to-true transitions. |

### Event action kinds

`[plan.event.action]` is tagged by `kind`.

| `kind` | Required/optional fields | Meaning | Reference |
| --- | --- | --- | --- |
| `inject_fault` | `tag`, `fault` | Activate a nested [membership fault](#membership-fault-kinds). Use its `taxonomy` wrapper for a full taxonomy fault. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `heal_fault` | `tag` | Remove the active fault under `tag`. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `arm_timer` | `name`, `after_nanos` | Arm or replace a relative timer. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `cancel_timer` | `name` | Cancel the named timer. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `start_node` | `node` | Start a declared, currently stopped node. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `stop_node` | `node` | Stop a declared node without changing the static topology. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `create_savepoint` | `label?` | Materialize a savepoint at the firing boundary. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `fork` | `label?` | Fork a child execution at the firing boundary. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `pass` | None | Produce an explicit passing terminal verdict. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `fail` | `reason` | Produce an explicit failing terminal verdict. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `log` | `level`, `message` | Emit deterministic log text. `level` is `debug`, `info`, `warn`, or `error`. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `group` | `actions` array | Execute nested actions as one ordered group. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |

`log.level` values:

| Value | Meaning |
| --- | --- |
| `debug` | Diagnostic detail intended for developers. |
| `info` | Normal informational event. |
| `warn` | Non-terminal warning. |
| `error` | Error-level deterministic log event; this does not itself replace the `fail` action. |

### Membership fault kinds

Membership faults are used by legacy `plan.entry` rows and event
`inject_fault` actions.

| `kind` | Required fields | Meaning | Reference |
| --- | --- | --- | --- |
| `crash` | `node`, `restart` | Crash a VM and apply the selected [restart policy](#supporting-fault-values) when healed. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `partition` | `endpoint_a`, `endpoint_b`, `direction` | Suppress one or both directions of the declared link. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `isolate` | `node` | Remove all effective network connectivity for the VM. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `not_yet_joined` | `node` | Model a declared member that has not joined the active membership. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `taxonomy` | `fault` | Wrap one nested [taxonomy fault](#taxonomy-fault-kinds) for use in a membership-fault position. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |

An event action needs two nested fault tables when it injects a taxonomy fault:

```toml
[plan.event.action]
kind = "inject_fault"
tag = "lossy-link"

[plan.event.action.fault]
kind = "taxonomy"

[plan.event.action.fault.fault]
kind = "network_loss"
link = "client--server"
rate_basis_points = 2500
```

### Taxonomy fault kinds

Each `fault` in a `plan.fault_entry` is one of the following tagged tables.
Fields named `link`, `node`, or `device` must resolve to the corresponding
declared world object.

| `kind` | Required fields | Effect | Reference |
| --- | --- | --- | --- |
| `network_partition` | `link`, `direction` | Suppress the selected directed edge or both edges. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `network_loss` | `link`, `rate_basis_points` | Drop matching frames at the deterministic probability. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `network_reorder` | `link`, `window_nanos` | Shift delivery within the window so frames may pass one another. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `network_duplicate` | `link`, `rate_basis_points`, `gap_nanos` | Emit an additional identical frame after the modeled gap when the fault fires. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `network_corruption_bit_flip` | `link`, `rate_basis_points`, `max_bits` | Flip a seeded number of payload bits up to `max_bits`. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `network_corruption_field_mutation` | `link`, `rate_basis_points` | Mutate a parsed payload field to another seeded in-range value. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `network_corruption_truncation` | `link`, `rate_basis_points`, `max_bytes` | Shorten payload bytes by a seeded amount bounded by `max_bytes`. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `network_bandwidth` | `link`, `bits_per_second` | Add deterministic serialization delay for this bandwidth cap. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `network_latency_bump` | `link`, `extra_nanos` | Add fixed virtual latency to frame delivery. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `node_crash` | `node`, `restart` | Stop the VM and use the selected restart policy after healing. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `node_slow` | `node`, `factor_basis_points` | Stretch modeled progress by a factor of at least 10,000 basis points (1.0). | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `node_clock_skew` | `node`, `offset_nanos` | Apply a signed offset to guest-perceived wall-clock time without changing icount virtual time. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `block_latency` | `device`, `extra_nanos`, `jitter_nanos` | Delay block responses by the fixed addition plus seeded jitter. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `block_failure` | `device`, `rate_basis_points`, `mode` | Return an error-status response or drop the response at the configured rate. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `block_reorder` | `device`, `window_nanos` | Shift a block completion within the window. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `block_duplicate` | `device`, `rate_basis_points`, `gap_nanos` | Emit a duplicate block response after the modeled gap. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `block_corruption` | `device`, `rate_basis_points`, `bit_flips` | Flip the configured number of deterministic response bits. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `block_bandwidth` | `device`, `bits_per_second` | Add deterministic serialization delay for a block-device bandwidth cap. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `nine_p_latency` | `device`, `extra_nanos`, `jitter_nanos` | Delay 9p responses by the fixed addition plus seeded jitter. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `nine_p_failure` | `device`, `rate_basis_points`, `errno_code` | Return the configured positive POSIX errno at the deterministic rate; portable `EIO` is `5`. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `nine_p_reorder` | `device`, `window_nanos` | Shift a 9p completion within the window. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `nine_p_duplicate` | `device`, `rate_basis_points`, `gap_nanos` | Emit a duplicate 9p response after the modeled gap. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `nine_p_corruption` | `device`, `rate_basis_points`, `bit_flips` | Flip the configured number of deterministic response bits. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `nine_p_bandwidth` | `device`, `bits_per_second` | Add deterministic serialization delay for a 9p-device bandwidth cap. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |

### Supporting fault values

| Field | Accepted value | Meaning |
| --- | --- | --- |
| `direction` | `bidirectional` | Suppress endpoint A to B and endpoint B to A. |
| `direction` | `endpoint_a_to_endpoint_b` | Suppress only A to B. |
| `direction` | `endpoint_b_to_endpoint_a` | Suppress only B to A. |
| `restart` | `from_ready_point` | Relaunch from the baked genesis ready point after healing. |
| `restart` | `from_last_checkpoint` | Relaunch from the last pre-crash checkpoint. A checkpoint must exist. |
| `restart` | `stay_down` | Do not relaunch automatically; an explicit `start_node` is required. |
| block failure `mode` | `drop` | Never complete the response. |
| block failure `mode` | `error_status` | Complete with an error-status response. |

## Properties and predicates

### `[properties]` and assertions

| Location | Required fields | Meaning |
| --- | --- | --- |
| `[properties]` | `id` | Generated content address for the property bundle. |
| `[[properties.assertion]]` | `id`, `message`, `property` | Stable assertion name, user-facing failure message, and nested temporal property. |

### Property kinds

`[properties.assertion.property]` is tagged by `kind`. Supplying a field not
listed for that kind is an error.

| `kind` | Required fields | Meaning | Reference |
| --- | --- | --- | --- |
| `always` | `predicate` | Invariant: the predicate must hold at every relevant evaluation point. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `sometimes` | `predicate` | Liveness witness: the predicate must hold at least once. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `eventually` | `trigger`, `property`, `deadline_ticks` | After `trigger` holds, `property` must hold within this many virtual-time ticks from the trigger instant. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `after_quiescence` | `predicate` | Check the predicate once when the run quiesces or reaches its run limit. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `reachable` | `predicate`, `expectation` | Coverage-style reachability or unreachability expectation. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |

Reachability expectation tables:

| `kind` | Fields/default | Meaning |
| --- | --- | --- |
| `reachable` | `on_unreached: warn\|fail`, default `warn` | Expect at least one witness; warn or fail if none is observed. |
| `unreachable` | None | Fail if a witness is observed. |

### Predicate kinds

A predicate may be a DSL string or a structured table tagged by `kind`. The
same vocabulary is accepted for assertion predicates and event triggers.

| `kind` | Required/optional fields | True when | Reference |
| --- | --- | --- | --- |
| `at` | `at_ticks` | Virtual time equals the exact coordinate. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `after` | `duration_nanos`, `of` | The duration has elapsed since event ID `of` last fired. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `timer` | `name` | The named relative timer fires. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `network_match` | `predicate`, `link?` | A delivered frame, optionally restricted to a link ID, matches the nested frame predicate. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `console_match` | `node`, `regex` | The node's captured serial output matches the regex program. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `coverage_point` | `node`, `point` | The node executes the nested address or symbol code point. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `memory_predicate` | `node`, `place`, `cmp`, `value` | The sampled memory/register value satisfies the comparison. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `io_pattern` | `node`, `io_kind` | An I/O event of the selected kind is observed for the node. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `node_state` | `node`, `state` | The node has the selected lifecycle state. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `assertion_state` | `name`, `state` | The named assertion is satisfied or violated. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `quiescent` | None | The scheduler has settled with no immediately runnable work. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `fault_active` | `tag` | A fault with this tag is active. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `named` | `name`, `nodes?` | The named predicate DSL entry resolves in the current world/plan context. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `guest_marker` | `marker` | The white-box-enabled guest emits the named bare marker or declared assertion marker as applicable. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `all_of` | `predicates` array | Every nested predicate is true. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `any_of` | `predicates` array | At least one nested predicate is true. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `once` | `predicate` | The nested predicate has become true at least once. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |
| `not` | `predicate` | The nested predicate is false. | [TOML schema source](../../../crates/crucible/src/model/toml.rs) |

### Named predicate DSL strings

These strings may appear directly where a predicate is expected. Structured
`kind = "named"` form also accepts `name` plus an optional `nodes` array.

| DSL value | Expansion |
| --- | --- |
| `no_crashed_nodes` | `not(any_of(node_state(node, crashed) for every VM))` |
| `quiescent` | `quiescent` |
| `no_active_faults` | `not(any_of(fault_active(tag) for every declared tag))` |
| `node_alive:<node>` | `not(node_state(<node>, crashed))` |
| `node_crashed:<node>` | `once(node_state(<node>, crashed))` |

### Nested predicate value tables

Frame predicates used by `network_match`:

| `kind` | Required fields | Match |
| --- | --- | --- |
| `any` | None | Any delivered frame. |
| `exact` | `bytes_hex` | Complete frame bytes equal the hexadecimal sequence. |
| `contains` | `needle_hex` | Frame contains the hexadecimal byte sequence. |
| `prefix` | `prefix_hex` | Frame begins with the hexadecimal byte sequence. |

Code points used by `coverage_point`:

| `kind` | Required fields | Meaning |
| --- | --- | --- |
| `guest_address` | `address` | Exact guest virtual address. |
| `symbol` | `name` | Symbol resolved by the configured observation backend. |

Places used by `memory_predicate`:

| `kind` | Required fields | Meaning |
| --- | --- | --- |
| `physical_address` | `address`, `width` | Read a guest physical address. |
| `virtual_address` | `address`, `width` | Read a guest virtual address. |
| `symbol` | `name`, `width` | Read memory at a symbol. |
| `register` | `name`, `width` | Read a guest register. |

Memory widths:

| `width` | Read size |
| --- | ---: |
| `u8` | 8 bits |
| `u16` | 16 bits |
| `u32` | 32 bits |
| `u64` | 64 bits |

Unsigned memory comparisons:

| `cmp` | Operation |
| --- | --- |
| `eq` | Equal to `value`. |
| `ne` | Not equal to `value`. |
| `lt` | Less than `value`. |
| `le` | Less than or equal to `value`. |
| `gt` | Greater than `value`. |
| `ge` | Greater than or equal to `value`. |

`io_pattern.io_kind` values:

| Value | Matches |
| --- | --- |
| `any` | Any modeled I/O event. |
| `block_read` | Block read. |
| `block_write` | Block write. |
| `fsync` | Flush/fsync event. |
| `nine_p` | 9p filesystem event. |
| `network` | Network event. |

Node lifecycle states:

| `node_state.state` | Meaning |
| --- | --- |
| `started` | The declared node is running. |
| `crashed` | The node entered its modeled crash state. |
| `hung` | The node is running but no longer making modeled progress. |
| `exited` | The guest/runtime exited. |

Assertion phases:

| `assertion_state.state` | Meaning |
| --- | --- |
| `satisfied` | The named assertion reached its satisfied terminal phase. |
| `violated` | The named assertion reached its violated terminal phase. |

## Output, artifacts, and exit status

JSON and JSONL are stable programmatic formats. Tables and Markdown are
presentation formats. The event trace is distinct from diagnostic output; use
`--trace` and `--quiet` when a job needs a clean machine stream.

The content-addressed store contains scenario forms, schedules, checkpoints,
and related execution objects. A reproduction artifact records inputs and the
schedule needed to reproduce a result. A savepoint handle names a checkpoint
for `resume`, `fork`, and debugger attachment. Preserve every store object
referenced by exported handles and artifacts.

| Status | Class |
| ---: | --- |
| 0 | Success |
| 1 | Property failure, divergence, replay mismatch, counterexample, or triage failure |
| 2 | Virtual-time or scheduler-quantum timeout |
| 3 | Crash, daemon failure, replay-oracle failure, or build-identity mismatch |
| 4 | Backend failure |
| 5 | Invalid scenario, artifact, store object, or local I/O input |
| 64 | Command-line usage error |

Scripts should branch on the status class and consume JSON/JSONL output. Human
diagnostic wording may change. See [Troubleshooting](troubleshooting.md) for
cause-oriented guidance.
