# Resource limits

Determinism requires finite state and work. Every collection, queue, history,
payload, trace read, state-machine transition, and search branch in the fault
system has a scenario-owned limit and a compiled hard ceiling.

The registry is
[`resource_limits.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/resource_limits.rs):
`FaultResourceLimits` and `FAULT_RESOURCE_LIMIT_DESCRIPTORS` list every field
with its default and hard ceiling. The same table drives reference generation
and resource diagnostics, so an adapter cannot introduce a hidden semantic
bound.

## Admission and runtime behavior

- A scenario's `resource_limits` may lower any limit but never raise it above
  the compiled ceiling; every value must be positive. Limits are part of
  scenario identity, so the same identity cannot run under different semantic
  limits.
- Admission computes worst-case static usage where possible and rejects a plan
  that exceeds a limit.
- Dynamic limits are checked before mutation. Exceeding one ends the run with a
  typed resource error at the responsible coordinate, reporting current,
  requested, configured, and hard values.
- The runtime never truncates, evicts, samples, coalesces, drops, or disables
  observability to stay under a limit unless that exact policy is part of the
  scenario.

## Limit families

| Family | Example fields |
| --- | --- |
| Signal and binding | `signal_nodes`, `signal_edges`, `signal_state_bytes`, `bindings`, `resolved_targets_per_binding`, `active_contributions_per_target`, `effect_payload_bytes` |
| Trace and spatial | `trace_artifacts`, `trace_entries_per_chunk` (fixed at 4,096), `trace_normalized_bytes_total`, `spatial_grid_cells_total` |
| Network | `network_segments`, `network_path_hops`, `network_loop_hops`, `network_queue_frames`, `network_queue_bytes`, `network_connection_entries`, `network_custody_bundles` |
| Storage and 9p | `storage_pending_operations`, `storage_cache_bytes_per_device`, `storage_persistence_dependencies`, `storage_retained_versions_per_interval`, `ninep_object_versions` |
| Node and QEMU | `vcpus_per_node`, `node_mutations_pending`, `memory_mutation_bytes_per_effect`, `interrupt_storm_events`, `accelerator_jobs_pending` |
| Event, checkpoint, replay | `event_records`, `event_log_bytes`, `fat_checkpoint_bytes`, `resolved_effect_records`, `replay_first_mismatch_context_bytes` |
| Search and minimization | `search_states`, `search_choices_per_state`, `trace_mutation_windows`, `mapping_mutation_points`, `minimization_attempts` |

Signal-graph limits are narrowed into `SignalResourceLimits` for the evaluator,
with additional compiled `HARD_SIGNAL_*` ceilings and a fixed maximum graph
depth of 4,096. The QEMU fault transport has its own compiled bounds on payload
bytes, arena size, and ring capacity in `crucible-qemu-shmem`.

## Algorithmic expectations

Bounds are only useful if the algorithms respect them:

- signal evaluation is iterative in topological order and evaluates each node,
  coordinate, and consumer at most once per boundary;
- trace seek is a chunk-index lookup and one chunk decode, and importers stream
  rather than buffering whole traces;
- medium overlap and route lookup use ordered indexes rather than scanning all
  pending frames;
- checkpoint encode and decode measure, bound, and reserve fallibly before
  allocating, applying `fat_checkpoint_bytes` symmetrically, so a small
  malformed checkpoint cannot request unbounded memory.
