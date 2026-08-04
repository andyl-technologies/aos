# Crucible Reference

This is a compact map of the user-facing command and scenario surfaces. Use
`crucible --help` and `crucible <command> --help` for the syntax shipped by the
binary.

## Global options

| Option | Purpose |
| --- | --- |
| `--seed <u64|hex>` | Set the root entropy. It overrides `CRUCIBLE_SEED`. |
| `--backend <auto|qemu>` | Select local backend discovery. Production builds expose QEMU only. |
| `--daemon <addr>` | Send lifecycle operations to a daemon. |
| `--qemu <path>` | Override the patched QEMU binary. |
| `--plugin <path>` | Override the matching QEMU plugin. |
| `--store <path>` | Set the content-addressed store root. |
| `--format <jsonl|json|table|markdown>` | Fix report rendering. The default is table on a terminal and JSONL otherwise. |
| `--trace <path>` | Write the event stream to a file instead of standard output. |
| `--artifact-dir <path>` | Set the failure-artifact directory; default `./.crucible`. |
| `-v`, `--verbose` | Increase log verbosity; repeat for more detail. |
| `-q`, `--quiet` | Suppress non-essential output. |

`auto` discovers and validates the packaged QEMU/plugin pair. Supplying only
one of `--qemu` and `--plugin` is an error.

## Commands

| Command | Purpose |
| --- | --- |
| `run` | Execute a scenario to a terminal condition. |
| `verify` | Repeat a scenario and compare fingerprints and canonical logs. |
| `selftest` | Run the packaged determinism gates. |
| `save` | Stop at a coordinate and export a savepoint. |
| `resume` | Continue from a savepoint or checkpoint. |
| `fork` | Continue from a savepoint with a new seed or decision override. |
| `replay` | Reproduce a recorded failure and optionally check its log. |
| `search` | Explore a bounded schedule space. |
| `fuzz` | Sample a scenario family using basic-block coverage. |
| `triage` | Cluster, deduplicate, and minimize findings. |
| `debug` | Inspect a recorded or running execution. |
| `serve` | Run the remote lifecycle API. |
| `completions` | Generate shell completion definitions. |

The task-oriented guides describe the operating constraints around these
commands: [running](running.md), [reproduction](reproduction.md),
[exploration](exploration.md), [debugging](debugging.md), and
[daemon operation](daemon.md).

## Scenario document

A canonical scenario is TOML with exactly four top-level tables:

```toml
[scenario]
id = "checkout-partition"
seed = "42"
app_random_draw_cap = 1024

[world]
id = "checkout-world"

[plan]
id = "partition-plan"

[properties]
id = "checkout-properties"
```

Unknown fields are rejected. Scenario content, including IDs and seed, is part
of the content identity.

### `[scenario]`

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Human-readable scenario identity. |
| `seed` | string | Canonical seed material. |
| `app_random_draw_cap` | unsigned integer | Maximum application-random draws. |

### `[[world.node]]`: VM

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Unique node ID. |
| `arch` | `x86_64` or `aarch64` | Guest architecture; defaults to `x86_64`. |
| `memory_mib` | integer | Guest memory. |
| `cmdline` | string | Additional kernel command line. |
| `smp_vcpus` | integer | Virtual CPU count. |
| `icount_shift` | integer | QEMU instruction-count shift. |
| `kernel` | optional string | Kernel artifact reference. |
| `root_image` | optional string | Root image artifact reference. |
| `initrd` | optional string | Initrd artifact reference. |
| `ready_point` | table | Deterministic point at which the node is ready. |
| `white_box` | `enabled` or `disabled` | Whether white-box observation is enabled. |

`ready_point.kind` accepts:

| Kind | Additional fields |
| --- | --- |
| `fixed_icount` | `retired` |
| `network_idle` | `window_nanos` |
| `console_marker` | `marker` |
| `agent_signal` | none |

### `[[world.node]]`: I/O device

I/O nodes use a tagged `kind` in the same node array:

| Kind | Fields |
| --- | --- |
| `block` | `id`, `owner`, `shift_bits`, `artifact`, `artifact_length`, `read_base_ns`, `write_base_ns`, `flush_ns`, `get_length_ns`, `per_byte_ns` |
| `nine_p` | `id`, `owner`, `shift_bits`, `artifact`, `control_ns`, `data_ns`, `per_byte_ns` |

### `[[world.link]]`

| Field | Type |
| --- | --- |
| `endpoint_a`, `endpoint_b` | node ID strings |
| `latency_nanos`, `jitter_nanos` | unsigned integers |
| `loss_millionths` | unsigned integer |
| `bandwidth_bps` | optional unsigned integer |

Links are identified by their endpoints. Effective latency must remain above
Crucible's minimum after jitter is applied.

## Plans

`plan.kind` selects one of three representations:

| Kind | Entries |
| --- | --- |
| `entries` | `[[plan.entry]]`: `activate` or `heal` at `at_ticks`. |
| `fault_plan` | `[[plan.fault_entry]]`: `at`, `permanent_at`, or `heal`. |
| `event_graph` | `[[plan.event]]`: trigger/action nodes with `once` or `repeatable` policy. |

An event action accepts these `kind` values:

```text
inject_fault  heal_fault  arm_timer  cancel_timer  start_node  stop_node
create_savepoint  fork  pass  fail  log  group
```

Membership faults are `crash`, `partition`, `isolate`, `not_yet_joined`, or
`taxonomy`. Taxonomy faults are:

```text
network_partition  network_loss  network_reorder  network_duplicate
network_corruption_bit_flip  network_corruption_field_mutation
network_corruption_truncation  network_bandwidth  network_latency_bump
node_crash  node_slow  node_clock_skew
block_latency  block_failure  block_reorder  block_duplicate
block_corruption  block_bandwidth
nine_p_latency  nine_p_failure  nine_p_reorder  nine_p_duplicate
nine_p_corruption  nine_p_bandwidth
```

Fields are specific to each fault. Start from a generated scenario, then use a
schema error as a hard stop rather than guessing at a field name. The
[scenario guide](scenarios.md) shows the supported authoring workflow.

## Predicates and assertions

Predicates may be a DSL string or a structured table. Structured
`predicate.kind` values are:

```text
at  after  timer  network_match  console_match  coverage_point
memory_predicate  io_pattern  node_state  assertion_state  quiescent
fault_active  named  guest_marker  all_of  any_of  once  not
```

Assertions are `[[properties.assertion]]` entries with `id`, `message`, and a
`property` table. `property.kind` determines which of `predicate`, `trigger`,
`property`, `deadline_ticks`, and `expectation` is required. Reachability
expectations are `reachable` (with `warn` or `fail` when unreached) and
`unreachable`.

## Run terminal conditions

`run --until` and `resume --until` accept:

- `quiescence` (default);
- `virtual-time`, requiring `--max-virtual-time`;
- `property`; and
- `stopped`.

`--max-quanta` adds an independent scheduler bound to `run`. Durations use the
CLI duration syntax, such as `250ms`, `30s`, or `2m`.

## Output and artifacts

JSON and JSONL are the stable choices for programs. Tables and Markdown are
presentation formats. The event trace is distinct from diagnostic messages;
use `--trace` and `--quiet` when a job needs clean machine output.

The content-addressed store contains scenario forms, schedules, checkpoints,
and related execution objects. A failure reproduction artifact records the
inputs and schedule needed to reproduce a result. A savepoint handle names a
checkpoint for `resume`, `fork`, and debugger attachment. Preserve the store
objects referenced by exported handles and artifacts.

## Exit status

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
wording may change as diagnostics improve.
