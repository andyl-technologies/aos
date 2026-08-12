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
- [Signal-driven effect registry](../../../crates/crucible/src/model/fault_signal/effect_registry.rs)
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
| `--trusted-unauthenticated-daemon` | Required for cleartext daemon access | Explicitly acknowledge an unauthenticated endpoint on a trusted network. Conflicts with daemon mutual TLS. | [Daemon operation](daemon.md) |
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

Production QEMU execution also requires `CRUCIBLE_RUN_STATE_ROOT` to name a
writable, durable directory. Crucible creates content-addressed scenario and
monotonic run subdirectories beneath it. Each run records exact Linux process
identities (PID, start-time ticks, and executable), staged replacements, and
the lifecycle transaction phase. A second live owner is rejected; after an
interrupted owner disappears, Crucible verifies or contains every recorded
process before admitting a new run. Missing, malformed, or version-mismatched
recovery records fail closed.

Every QEMU child also receives a nonzero, monotonically increasing process
generation before the plugin accepts fault commands. Terminal lifecycle
authorization, durable supervision records, and restored fault state must all
name that exact generation. A request or checkpoint from an earlier child is
rejected rather than being applied to its replacement.

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

Self-test honors the global `--format`, `--trace`, and `--quiet` options. JSONL
uses `selftest_gate`, `selftest_scenario`, and terminal `final_outcome` records.

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
| `--findings-out <path>` | Content-addressed path below `--artifact-dir` | Write the signed findings ledger here, including an empty ledger when no finding is retained. |
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
| `--findings-out <path>` | Content-addressed path below `--artifact-dir` | Write the signed findings ledger here, including an empty ledger when no finding is retained. |

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
| `[plan]` | `id`, `fault_model`, `fault_signal_semantic_version` | Event graph plus the sole signal/binding fault representation. |
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

Bindings refer to a unique link by its canonical link ID. Generate target IDs
through a Rust scenario builder so they remain bound to the admitted World.

### `[[world.node_fault_capabilities]]` fields

Each VM that accepts node-level faults has one closed capability declaration.
The declaration is an admission contract, not a request for best-effort QEMU
behavior: the run fails before boot if the realized CPU type or canonical
register manifest differs. `register_schema` is the BLAKE3 content hash of the
complete encoded register manifest, represented in TOML as
`{ bytes = [32 decimal byte values] }`.

| Field | Required value | Meaning |
| --- | --- | --- |
| `id` | Unique string | Scenario-local capability declaration ID. |
| `node` | VM node ID | VM governed by this declaration. |
| `architecture` | `x86_64` or `aarch64` | Exact guest architecture ABI. It must agree with the VM's `arch`. |
| `cpu_model` | Printable QOM typename | Exact realized QEMU CPU type, including the architecture suffix reported by QEMU. |
| `register_schema` | Content hash table | BLAKE3 of the canonical public register-manifest bytes. |
| `registers` | Nonempty array | Exhaustive register rows described below, ordered canonically by `numeric_id`. |
| `address_spaces` | Nonempty array | Guest memory ranges which node faults may address. |
| `page_bytes` | Power-of-two integer | Guest page size used by memory-fault contracts. |
| `dram_geometry` | Table | Exact QEMU DRAM coordinate mapping described below. |
| `interrupts` | Array | Fully routed interrupt targets. May be empty. |
| `clock_sources` | Array | Guest-visible clock sources. May be empty. |
| `accelerators` | Array | Declared accelerator devices. May be empty; sensor devices are not accepted. |
| `ready_markers` | Canonically ordered unique string array | Exact guest event-marker names allowed to complete `require_ready`; an undeclared marker rejects the run before boot. May be empty. |
| `semantic_version` | `1` | Capability schema version. |

#### Register rows

Every guest-visible or implementation-private register in the pinned CPU model
appears in `[[world.node_fault_capabilities.registers]]`. A row with an all-zero
`writable_mask_hex` is reference-only: it must advertise neither `impulse` nor
`persistent`, has no model phases or side effects, and cannot be selected for a
mutation. A writable row advertises at least one mutation mode, has VMState
coverage, and lists every safe hook phase. The four masks partition every
in-range bit exactly once; padding bits above `width_bits` are zero. Mask bytes
use lowercase hexadecimal in least-significant-byte-first order.

| Field | Required value | Meaning |
| --- | --- | --- |
| `id` | Unique string | Stable selector ID for this register. |
| `name` | Canonical lowercase identifier | Exact name exported by QEMU. |
| `numeric_id` | Nonzero integer | Stable private-to-public manifest row ID. |
| `group` | Register-group value below | Architecture category used by coverage gates. |
| `width_bits` | `1..=65536` | Architectural value width. |
| `per_vcpu` | `true` | Values are independently selected by vCPU index. |
| `model_phases` | Ordered unique array | Writable rows use `before_instruction`, `after_instruction`, or both; reference-only rows use `[]`. |
| `side_effects` | Ordered unique array | Derived QEMU state recomputed by the architecture setter; reference-only rows use `[]`. |
| `impulse` | Boolean | Supports one exact mutation at a selected occurrence. |
| `persistent` | Boolean | Supports a rule applied at every selected register hook. |
| `vmstate` | Boolean | Register value and any advertised persistent rule survive save/restore. Required for writable rows. |
| `writable_mask_hex` | Exact-width lowercase hex | Bits the fault ABI may change. |
| `reserved_mask_hex` | Exact-width lowercase hex | Architecturally reserved bits, always preserved. |
| `ignored_mask_hex` | Exact-width lowercase hex | Bits whose architectural writes are ignored. |
| `read_only_mask_hex` | Exact-width lowercase hex | Readable or implementation-private bits that cannot be mutated. |

Register-group values are exhaustive:

| Value | Contents |
| --- | --- |
| `general_purpose` | Integer data and address registers. |
| `control_flow` | Program counters and explicit control-flow registers. |
| `flags` | Integer condition and status flags. |
| `segment` | Segment selectors, bases, limits, and attributes. |
| `control` | Translation and execution-control registers. |
| `system` | Other guest-visible architecture system registers. |
| `debug` | Guest-visible debug registers. |
| `floating_point` | Floating-point data, status, and control registers. |
| `vector` | SIMD, vector, and predicate registers. |
| `error` | Architecture-defined error status and syndrome registers. |

Register side-effect values are exhaustive:

| Value | Required architecture action |
| --- | --- |
| `tlb_flush` | Flush affected vCPU translations. |
| `translation_block_flush` | Invalidate affected translated code. |
| `flags_recompute` | Rebuild cached flags or execution state. |
| `interrupt_reevaluate` | Recompute interrupt masking and delivery. |
| `timer_rearm` | Recompute and arm derived timer deadlines. |
| `control_flow_synchronize` | Synchronize the next guest instruction location. |

#### Memory, interrupt, clock, and accelerator rows

| Nested location | Required fields | Meaning |
| --- | --- | --- |
| `[[world.node_fault_capabilities.address_spaces]]` | `id`, `start_address`, positive `length_bytes` | One non-wrapping guest address range. Address and length accept a TOML integer or canonical decimal/hex string. |
| `[world.node_fault_capabilities.dram_geometry]` | `channels=2`, `ranks=2`, `banks=16`, `interleave_bytes=64`, `semantic_version=1` | The only currently implemented GPA-to-DRAM mapping. |
| `[[world.node_fault_capabilities.interrupts]]` | All interrupt-row fields below | One exact source-to-controller route and its mutation contract. |
| `[[world.node_fault_capabilities.clock_sources]]` | `id`, `semantic_version=1`, `monotonic` | One registered guest clock and whether reads must remain monotonic. |
| `[[world.node_fault_capabilities.accelerators]]` | `id`, nonempty sorted `classes`, `semantic_version=1`, `capability_manifest` | One realized fault device and its exact content-addressed manifest; `classes` contains any supported combination of `gpu`, `tpu`, and `fpga`. |

`ready_markers` is part of the content-addressed QEMU launch contract. Each
entry names a decoded guest `event` marker, not an assertion, lifecycle,
coverage, or random-request marker. The host carries the exact set admitted by
the World through setup and node construction, and rejects a lifecycle or
watchdog action whose `ready_marker` is absent from the selected live node.

Interrupt rows are exhaustive realized-machine contracts. Every field is
required; there are no inferred controller defaults. A scenario is rejected
before boot if QEMU reports a different family, controller version, electrical
mode, route, priority, phase set, replacement range, drop transition, or
VMState coverage.

| Interrupt field | Required value | Meaning |
| --- | --- | --- |
| `id` | Unique string | Stable manifest-row identity. |
| `controller` | Controller object ID | Controller selected by a fault target. |
| `source` | Source object ID | Device, timer, or vCPU source selected by a fault target. |
| `controller_version` | Printable non-whitespace string | Exact realized QEMU controller implementation/version identity. |
| `family` | Interrupt-family value below | Architecture path whose hooks and state semantics are implemented. |
| `vector_start` | Family-valid integer | Inclusive first x86 vector or Arm INTID this source may produce after guest programming. |
| `vector_end` | Family-valid integer | Inclusive last runtime vector or INTID; must be at least `vector_start`. Each opportunity records the exact observed value. |
| `replacement_vector_start` | Family-valid integer | Inclusive first replacement accepted for this row. |
| `replacement_vector_end` | Family-valid integer | Inclusive last replacement accepted for this row; must be at least `replacement_vector_start`. |
| `trigger` | `edge` or `level` | Electrical pending-state behavior. Families fixed to edge reject `level`. |
| `polarity` | `active_high` or `active_low` | Active line level or edge direction. |
| `target_vcpus` | Sorted unique nonempty integer array | Complete closed route target set. |
| `model_phases` | Sorted unique nonempty phase array | Any subset of `raise`, `route`, and `interrupt_deliver` actually implemented for this row. |
| `priority` | Integer `0..=255` | Controller priority used by deterministic ordering. |
| `delivery_drop` | Drop-state value below | Exact controller transition when a selected delivery is dropped. |
| `vmstate` | `true` | The controller state and Crucible interrupt overlay survive save/restore. |

Interrupt-family values and valid vector domains are exhaustive:

| Family | Architecture | Valid vector/INTID | Required trigger |
| --- | --- | --- | --- |
| `x86_local_apic_fixed` | x86-64 | `16..=255` | `edge` or `level` |
| `x86_ipi` | x86-64 | `16..=255` | `edge` |
| `x86_io_apic` | x86-64 | `16..=255` | `edge` or `level` |
| `x86_pic` | x86-64 | `0..=255` | `edge` or `level` |
| `x86_msi` | x86-64 | `16..=255` | `edge` |
| `x86_msi_x` | x86-64 | `16..=255` | `edge` |
| `x86_nmi` | x86-64 | exactly `2` | `edge` |
| `x86_timer` | x86-64 | `16..=255` | `edge` or `level`, as realized |
| `arm_gic_sgi` | AArch64 | `0..=15` | `edge` |
| `arm_gic_ppi` | AArch64 | `16..=31` | `edge` or `level` |
| `arm_gic_spi` | AArch64 | `32..=1019` | `edge` or `level` |
| `arm_gic_lpi` | AArch64 | `8192..=16777215` | `edge` |
| `arm_timer` | AArch64 | `16..=31` | `edge` or `level`, as realized |

`delivery_drop` is constrained by `trigger` so that dropping cannot silently
change controller semantics:

| Value | Allowed trigger | Exact transition |
| --- | --- | --- |
| `consume_edge` | `edge` | Consume the selected pending edge without creating active guest exception state. |
| `repend_asserted_level` | `level` | Consume the sampled opportunity and re-pend according to the unchanged physical line assertion. |

SMI is intentionally absent: the current QEMU contract does not implement the
complete SMM state transition. Arm SError is configured as a typed
`cpu_exception`, not as an interrupt-manifest family.

## Plans, signals, bindings, and faults

There is one fault authoring and execution model. A plan combines an ordinary
event graph with signal programs and typed bindings. Static, finite, periodic,
stochastic, trace-replayed, and stateful behavior all use this same path; there
is no separate imperative activation API.

Implementation sources:

- [plan wire shape](../../../crates/crucible/src/model/toml.rs)
- [signal value, source, operator, and state schemas](../../../crates/crucible/src/model/fault_signal/mod.rs)
- [binding, selector, mapping, sampling, and search schemas](../../../crates/crucible/src/model/fault_signal/binding.rs)
- [closed effect registry](../../../crates/crucible/src/model/fault_signal/effect_registry.rs)
- [network effect parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs)
- [storage and 9p effect parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs)
- [node, CPU, memory, interrupt, clock, and accelerator parameters](../../../crates/crucible/src/model/fault_signal/node_effect.rs)
- [resource-limit registry](../../../crates/crucible/src/model/fault_signal/resource_limits.rs)

### Storage-array declarations

Every `[[world.fault_topology.storage_array]]` row is a complete logical-device
contract. All fields below are required; there are no inferred RAID defaults or
legacy fallbacks.

| Field | Accepted value | Meaning |
| --- | --- | --- |
| `id` | Unique object ID | Stable array identity used by `storage_array` targets. |
| `device` | Block storage-device ID | Guest-visible logical block node. It must not be a member. |
| `semantic_version` | `1` | Exact layout, parity, and rebuild semantics. |
| `layout` | `mirror`, `stripe`, `single_parity`, or `dual_parity` | Closed physical layout. Single parity requires at least three members; dual parity requires at least four. |
| `chunk_bytes` | Positive power of two | Data chunk and parity-stripe unit. |
| `read_quorum` | Positive integer no greater than member count | Minimum online member paths before reads are admitted. |
| `write_quorum` | Positive integer no greater than member count | Minimum online members before non-atomic writes are admitted. |
| `members` | Canonical nonempty member table | Each row has unique `id`, unique block `device`, and contiguous `ordinal` beginning at zero. |
| `paths` | Canonical path table | Each row has `id`, positive `queue_depth`, and a `path` policy reference. |
| `member_path_state` | `array_state` artifact ID | Complete baseline online state for every declared member and path. |
| `selection_policy` | `array_selection` artifact ID | Baseline mirror read selection: lowest healthy, stable hash, or least loaded. |
| `rebuild_service` | `rebuild` artifact ID | Baseline positive rebuild chunk, queue depth, and byte rate. |
| `consistency_policy` | `array_consistency` artifact ID | Baseline quorum, degraded-commit, or atomic-stripe behavior. |
| `failure_result` | Non-success block `typed_result` artifact ID | Exact result returned when no legal quorum exists. |
| `fault_domains` | Canonical fault-domain ID list | Shared-cause domains containing the array. |

The smallest member capacity, rounded down to `chunk_bytes`, must cover the
logical device after mirror/stripe/parity overhead. The baseline policy always
routes logical I/O through the declared members. An active
`storage.array_state` binding replaces all five baseline policy references as
one state transition; when it deactivates, the declaration baseline resumes.

### `[plan]` fields

| Field | Required/default | Meaning |
| --- | --- | --- |
| `id` | Required generated content address | Identity of the event graph and complete signal-driven fault layer. |
| `fault_model` | Required; only `signal_bindings_v2` | Selects the sole accepted fault schema. Earlier forms fail before typed lowering. |
| `fault_signal_semantic_version` | Required; only `2` | Locks signal/binding semantics for canonicalization and replay. |
| `signal` | Empty array by default | Closed signal-program rows described below. |
| `fault_binding` | Empty array by default | Typed bridges from signal outputs to effects. |
| `resource_limits` | All compiled defaults | Scenario-owned limits; every value must be positive and no greater than its compiled ceiling. |
| `event` | Empty array by default | Non-fault event-graph rows. |

### `[[plan.event]]` fields and actions

| Field | Required/default | Meaning |
| --- | --- | --- |
| `id` | Required string | Unique event identity. |
| `trigger` | Optional | Predicate table or DSL string. Omission is unconditional. |
| `action` | Required | One closed action table. |
| `policy` | `once` by default; `repeatable` | Fire once or on later false-to-true transitions. |

| Action `kind` | Fields | Effect |
| --- | --- | --- |
| `arm_timer` | `name`, `after_nanos` | Arm or replace a relative timer. |
| `cancel_timer` | `name` | Cancel the timer. |
| `start_node` | `node` | Start a declared stopped node. |
| `stop_node` | `node` | Stop a declared node. |
| `create_savepoint` | optional `label` | Materialize a savepoint at the firing boundary. |
| `fork` | optional `label` | Fork a child execution at the firing boundary. |
| `pass` | none | Produce an explicit passing terminal verdict. |
| `fail` | `reason` | Produce an explicit failing terminal verdict. |
| `log` | `level`, `message` | Emit deterministic text; level is `debug`, `info`, `warn`, or `error`. |
| `group` | `actions` | Apply nested actions in declared order as one group. |

### `[[plan.signal]]` common fields

| Field | Required/default | Meaning |
| --- | --- | --- |
| `id` | Required | Stable signal identity. |
| `semantic_version` | Required; only `1` | Evaluator semantic version. |
| `domain` | Required | `virtual_time`, `node_counter`, `operation`, `spatial`, `event`, or `state`. |
| `value_type` | Required | `bool`, `i64`, `u64`, `ratio`, `duration_nanos`, `rate_per_second`, `probability_millionths`, `enum`, `event`, `vector2`, `vector3`, or `bytes`; parameterized types also carry their schema/scalar type. |
| `unit` | Required | One unit from the table below. |
| `scale_decimal_exponent` | Default `0`; `-18..=18` | Exact decimal scaling carried in signal shape. |
| `inputs` | Empty unless required by an operator | IDs of upstream nodes; order is semantic for noncommutative operators. |
| `node` | Required | Closed source, pure operator, or stateful operator specification. |

Signal units are exhaustive:

| Unit | Stored quantity |
| --- | --- |
| `dimensionless` | Integer or rational without a physical unit. |
| `virtual_nanoseconds` | Virtual duration or coordinate. |
| `millimetres`, `square_millimetres`, `millimetres_per_second` | Position, squared distance, or velocity. |
| `millidegrees` | Orientation. |
| `millicelsius` | Temperature. |
| `microvolts`, `microamps`, `microwatts`, `microjoules` | Voltage, current, power, or energy. |
| `femtowatts`, `millidecibels`, `millidecibel_milliwatts` | Exact linear or logarithmic RF/optical quantity. |
| `kilohertz` | Frequency. |
| `bits_per_second`, `bytes_per_second`, `operations_per_second` | Service rate. |
| `parts_per_million`, `probability_millionths` | Ratio or probability; probability is `0..=1_000_000`. |
| `micrometres_per_second_squared`, `micrometres_per_hour` | Acceleration or precipitation rate. |

Signal source kinds:

| `kind` | Required fields | Purpose |
| --- | --- | --- |
| `step` | ordered `points`, `before` | Piecewise-constant values. |
| `pulse` | `start`, `duration`, `inactive`, `active` | One finite interval. |
| `periodic_pulse` | `epoch`, `period`, `width`, `phase`, `inactive`, `active` | Repeating finite intervals. |
| `ramp` | `start`, `end`, `start_value`, `end_value`, `rounding` | Exact linear transition. |
| `triangle`, `sawtooth` | `epoch`, `period`, `phase`, `minimum`, `maximum`, `rounding` | Periodic analytic wave. |
| `event_sequence` | ordered `events` | Typed events with stable same-coordinate order. |
| `trace` | `artifact`, `raw_provenance`, `channel`, `interpolation`, `before`, `after`, `missing`; optional quality channel/threshold and time mapping | Replay a normalized recorded channel while retaining its raw provenance. |
| `telemetry` | `adapter`, `target`, `field`, `boundary_delay=1` | Read delayed production telemetry without a feedback loop. |
| `point_set` | `artifact`, `coordinate_frame`, `interpolation`, `outside` | Sample irregular spatial data. |
| `regular_grid` | `artifact`, `coordinate_frame`, `origin_mm`, `cell_size_mm`, `dimensions`, `interpolation`, `outside` | Sample a dense 3-D grid. |
| `tiled_grid` | `manifest`, `coordinate_frame`, `tile_size_mm`, `interpolation`, `outside` | Sample a bounded tiled grid. |
| `zone_map` | `artifact`, `coordinate_frame`, `boundary`, `overlap` | Resolve polygon/polyhedron membership. |
| `path_profile` | `artifact`, `path`, `interpolation`, `before`, `after` | Sample a quantity by distance along a path. |
| `seeded_field` | `field_seed_domain`, `coordinate_frame`, `quantization_mm`, `correlation_mm`, `distribution`, `distribution_parameters` | Generate a deterministic correlated field. |
| `transmitter_field` | `transmitter`, `coordinate_frame`, `position_signal`, optional `orientation_signal`, `model`, `lookup`, `environment_signals` | Apply calibrated path-loss/antenna/environment transfer. |
| `bernoulli` | `probability_millionths`, `key_domain`, optional `opportunity_filter` | Keyed Boolean draw. |
| `uniform_integer` | `minimum`, `maximum`, `key_domain`, optional `opportunity_filter` | Unbiased keyed inclusive integer draw. |
| `exponential_wait` | `rate`, `sampler_version`, `sampler_table`, `key_domain`, optional `maximum_nanos` | Exact integer inverse-CDF exponential wait. |
| `weibull_wait` | `shape`, `scale_nanos`, `sampler_version`, `sampler_table`, `key_domain`, optional `maximum_nanos` | Exact integer inverse-CDF Weibull wait. |

Interpolation is `exact`, `hold_previous`, `nearest`, or `linear`; linear also
declares `rounding` and `overflow`. Boundary behavior is `error`, `hold`,
`constant`, `repeat`, or `inactive`. Missing-sample behavior is `error`, `hold`,
`interpolate`, or `inactive`. Rounding is `floor`, `ceiling`, `toward_zero`,
`away_from_zero`, or `nearest_ties_to_even`; overflow is `error` or `saturate`.
Stochastic `key_domain` is `opportunity`, `transition`, or `coordinate`.

Pure and stateful operators are also closed. Pure operators cover exact
arithmetic (`add`, `subtract`, `min`, `max`, rational multiply/divide,
`absolute`, `negate`, `clamp`), comparisons, Boolean logic, select, step and
piecewise-linear lookup, enum maps, unit conversion, bounded delay/sample-hold
and windows, distance/spatial sampling/orientation, and typed edge/merge/gate
event operations. Stateful kinds are `hysteresis`, `debounce`, `integrator`,
`leaky_integrator`, `finite_state_machine`, `markov_chain`, `burst_process`,
`counter`, and `queue_model`. Their exact Rust field contracts are in the
[signal schema source](../../../crates/crucible/src/model/fault_signal/mod.rs);
unknown variants or fields are rejected.

### `[[plan.fault_binding]]` fields

| Field | Required/default | Meaning |
| --- | --- | --- |
| `id` | Required | Stable binding identity. |
| `semantic_version` | Required; only `1` | Binding semantic version. |
| `signals` | Required nonempty list; `signal` alias only for one input | Canonical input signals. |
| `sampling` | Required | `at_boundary`, `at_opportunity`, `at_change`, `cadence_nanos`, or `at_event` with its typed parent. |
| `mapping` | Required | Closed signal-to-effect transfer below. |
| `selector` | Required | `exact`, `target_set`, `fault_domain`, or version-1 `dynamic_path`. |
| `effect` | Required | One typed effect specification; `semantic_version=1`. |
| `opportunity_filter` | Required when opportunity sampling cannot be inferred | Adapter, operation set, phase set, and optional target-kind constraints. |
| `search_policy` | Required | Bounded search behavior below. |

| Mapping `kind` | Fields | Result |
| --- | --- | --- |
| `active_when_true` | `invert` | Persistent activation from Boolean input. |
| `active_when_equal` | `value` | Persistent activation for one enum value. |
| `threshold` | `comparison`, `threshold`, optional `clear_threshold`, `residence_nanos` | Stateful threshold/hysteresis activation. |
| `map_parameter` | `parameter` | Map one signal to one registered effect field. |
| `piecewise_parameter` | `parameter`, ordered `points`, `rounding`, `overflow` | Exact finite transfer function. |
| `hazard` | none | Keyed probability outcome at matching opportunities. |
| `impulse_on_event` | none | One impulse per typed event identity. |
| `state_transition` | `transition_table` | Exhaustively registered adapter transition. |
| `service_profile` | `service_profile` | Registered named physical-input service model. |

Search policy kinds are `fixed`, `branch_outcome { maximum_branches }`,
`branch_transition { candidates }`, `branch_parameter { parameter, candidates }`,
`mutate_trace_window { start_nanos, end_nanos, maximum_mutations }`, and
`mutate_mapping { point_indices, maximum_mutations }`.

### Target selector values

| Target kind | Adapter | What it selects |
| --- | --- | --- |
| `network_interface` | network | One endpoint interface. |
| `network_segment` | network | One directed physical or logical segment. |
| `network_medium` | network | One shared medium/channel resource. |
| `network_queue` | network | One bounded queue. |
| `network_forwarder` | network | Switch, router, modem, repeater, or gateway. |
| `network_path` | network | Versioned directed path. |
| `network_attachment` | network | Interface association/attachment. |
| `network_contact` | network | Scheduled or acquired contact. |
| `block_device`, `block_range` | storage | Whole block/flash device or byte range. |
| `storage_controller`, `storage_array` | storage | Controller namespace/path or array member/path. |
| `ninep_device` | storage | One 9p device. |
| `node`, `vcpu` | node | Whole emulated node or vCPU. |
| `register`, `memory_range`, `interrupt`, `clock_source` | node | Architecture-resolved machine object. |
| `accelerator` | node | Declared accelerator device. |

Sensor targets are specification-only and are rejected by this schema.

### Exhaustive effect registry

Every row below is executable. `Parameters` names the primary closed table or
fields; follow the linked family source for nested enum fields. Legal targets,
phases, lifetimes, composition, capabilities, and replay-evidence keys are
enforced by the [effect registry](../../../crates/crucible/src/model/fault_signal/effect_registry.rs).

| Effect `kind` | Parameters and purpose | Configuration source |
| --- | --- | --- |
| `network.availability` | Directional `state` and queued/in-flight policies; make an interface, segment, path, or contact up, down, receive-only, or transmit-only. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.flap` | Down, training, and recovery durations; model timed link transitions. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.negotiated_mode` | Rate, duplex, lanes, FEC, and training duration. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.profile_delta` | Optional latency/rate/error/technology profile components. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.propagation_delay`, `network.access_delay`, `network.jitter` | Exact delay or keyed bounded delay variation. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.service_curve`, `network.token_bucket` | Piecewise service, rate, burst, and initial-token constraints. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.queue_policy` | Byte/frame capacity, discipline/classes, and overflow response. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.frame_loss`, `network.burst_error_state` | Independent or correlated loss/corruption probability state. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.duplicate`, `network.reorder` | Probability/copies/gap or bounded reorder window and selection. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.payload_transform` | Bit flip, field mutation, truncation, or undetected corruption. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.detected_frame_error` | CRC/FCS/framing/FEC class and corrected/retry/drop/reset receiver action. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.mtu` | MTU plus drop, fragment, or typed-error oversize policy. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.pause_backpressure`, `network.recipient_subset` | Class-scoped pause or versioned multicast recipient selection. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.forwarder_lifecycle` | Restart/reset/power-loss transition, downtime, and queue/table retention. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.forwarding_mutation` | Wrong-port, flood, blackhole, loop, or stale-age lookup mutation. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.route_transition` | Old/new paths, convergence events, and in-flight policy. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.control_plane_service` | Bounded control queue, service curve, work size, and overflow. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.firewall_disposition` | Selector/state machine plus accept, reject, or drop. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.connection_state` | NAT, conntrack, load-balancer, tunnel, or DNS table and overflow state. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.shared_medium` | Resources, arbitration, contention/collision/capture, and duty cycle. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.rf_channel` | Carrier/bandwidth, signal/noise/gain/attenuation/fading, SINR transfer, and retry outcomes. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.association` | Candidate set, authentication, selection, hysteresis, timers, handoff, and traffic policy. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.control_result_transform` | Technology operation plus drop, stale, bias, replace, or typed error result. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.contact` | Contact plan, acquisition/teardown, range delay, beam/gateway, and service resource. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `network.custody_queue` | Bundle/byte capacity, priority, expiry, route/contact plan, hop bound, and overflow. | [network parameters](../../../crates/crucible/src/model/fault_signal/network_effect.rs) |
| `storage.availability` | Online/offline/read-only/degraded state. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `storage.reported_capacity` | Guest-visible length and affected-range policy. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `storage.latency`, `storage.service` | Operation-filtered delay/jitter or bandwidth/IOPS/queue/token service. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `storage.operation_failure`, `storage.stall_timeout` | Typed operation error or stall/recovery/timeout schedule. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `storage.completion_reorder`, `storage.duplicate_completion` | Bounded completion ordering or protocol-valid duplicates. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `storage.read_transform` | Bit corruption, stale-version read, or cross-range/device misdirection. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `storage.write_disposition` | Applied, lost, torn, or misdirected persistence. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `storage.persistence_order` | Declared durable partial order and violation behavior. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `storage.volatile_cache`, `storage.volatile_cache_loss` | Bounded cache/admission/eviction or exact selected power-loss set. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `storage.flush_disposition` | Honest, erroring, lying, or stalled flush result. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `storage.media_range`, `storage.flash_state` | Bad/latent/poisoned/read-only ranges or flash wear/retention/disturb state. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `storage.controller_lifecycle`, `storage.array_state` | Reset/reconnect/enumeration/path state or member/rebuild/consistency state. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `ninep.result`, `ninep.visibility` | Typed errno/stale/misdirected result or committed-versus-visible frontier. | [storage parameters](../../../crates/crucible/src/model/fault_signal/storage_effect.rs) |
| `node.lifecycle`, `node.hang` | Boot/crash/reset/power transition or scoped progress outage/watchdog recovery. | [node parameters](../../../crates/crucible/src/model/fault_signal/node_effect.rs) |
| `cpu.service`, `cpu.vcpu_state` | Rational execution capacity/schedule or online/offline/stalled vCPU state. | [node parameters](../../../crates/crucible/src/model/fault_signal/node_effect.rs) |
| `cpu.register_transform` | Architecture-resolved bit flip, stuck mask/value, or replacement. | [node parameters](../../../crates/crucible/src/model/fault_signal/node_effect.rs) |
| `cpu.instruction_transform`, `cpu.exception` | Result corruption/skip/replay or architecture machine-check/exception injection. | [node parameters](../../../crates/crucible/src/model/fault_signal/node_effect.rs) |
| `interrupt.disposition`, `interrupt.storm` | Drop/delay/duplicate/replace delivery or bounded generated sequence. | [node parameters](../../../crates/crucible/src/model/fault_signal/node_effect.rs) |
| `memory.mutation` | Atomic GPA/GVA bit flip or byte replacement at a safe boundary. | [node parameters](../../../crates/crucible/src/model/fault_signal/node_effect.rs) |
| `memory.access_transform` | Stuck/read-corrupt/lost-write/torn-write/poison transform by access class. | [node parameters](../../../crates/crucible/src/model/fault_signal/node_effect.rs) |
| `memory.ecc_event`, `memory.region_state`, `memory.service` | Corrected/uncorrectable ECC; failed/retention/rowhammer state; or latency/bandwidth service. | [node parameters](../../../crates/crucible/src/model/fault_signal/node_effect.rs) |
| `clock.transform`, `clock.source_state` | Offset/drift/jump/freeze/jitter/wander or source failure/fallback/synchronization. | [node parameters](../../../crates/crucible/src/model/fault_signal/node_effect.rs) |
| `accelerator.lifecycle`, `accelerator.result_transform`, `accelerator.memory_event`, `accelerator.service` | Accelerator presence/reset, job/result corruption, memory error, or compute/memory/thermal/power service. | [node parameters](../../../crates/crucible/src/model/fault_signal/node_effect.rs) |

The registry has 71 distinct keys even where adjacent rows above share a
description. A reference-integrity gate compares this document with the closed
registry so a new executable kind cannot ship undocumented.

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
