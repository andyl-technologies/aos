# 13 — Resource, state-space, and performance bounds

Determinism requires finite state and work. This file turns every “bounded”
requirement in the RFC into a concrete v1 hard ceiling and scenario-declared
limit. Hard ceilings are compile-time/codec constants and cannot be raised by
TOML. Scenario limits default to the values below and may only be lowered.

## 13.1 Admission behavior

The plan contains `[plan.resource_limits]` with the field names below. The
builder emits all defaults explicitly. Admission computes worst-case static
allocation where possible and rejects a plan exceeding any limit. Dynamic limits
are checked before mutation; exceeding one terminates the run with a typed
resource error at the responsible coordinate. The runtime never truncates,
evicts, samples, coalesces, drops, or disables observability to remain under a
limit unless that exact policy is part of the scenario.

- **[LIMIT-1]** Every unbounded collection, recursion, retry, queue, history,
  payload, trace read, state-machine transition, and search branch is forbidden.
- **[LIMIT-2]** Resource-limit errors are canonical run outcomes with current,
  requested, configured, and hard-limit values.
- **[LIMIT-3]** A limit change enters scenario identity; a host environment may
  lower operational admission policy but cannot make the same scenario identity
  execute with different semantic limits.

## 13.2 Signal and binding limits

| Field | Default | Hard ceiling |
| --- | ---: | ---: |
| `signal_nodes` | 16,384 | 65,536 |
| `signal_edges` | 65,536 | 262,144 |
| `signal_inputs_per_node` | 64 | 256 |
| `signal_state_bytes` | 67,108,864 | 268,435,456 |
| `state_machine_states_per_node` | 4,096 | 65,536 |
| `state_machine_transitions_per_node` | 16,384 | 262,144 |
| `lookup_points_per_node` | 65,536 | 1,048,576 |
| `bindings` | 32,768 | 131,072 |
| `signals_per_binding` | 32 | 128 |
| `resolved_targets_per_binding` | 65,536 | 262,144 |
| `active_contributions_per_target` | 1,024 | 4,096 |
| `effect_payload_bytes` | 1,048,576 | 16,777,216 |
| `events_emitted_per_signal_transition` | 256 | 4,096 |

Graph depth hard ceiling is 4,096. Evaluation uses an iterative topological
order; recursive evaluation is prohibited. One boundary may evaluate each
`(node, coordinate, consumer-domain)` at most once before using memoized output.

## 13.3 Trace and artifact limits

| Field | Default | Hard ceiling |
| --- | ---: | ---: |
| `trace_artifacts` | 1,024 | 16,384 |
| `trace_channels_total` | 16,384 | 65,536 |
| `trace_channels_per_artifact` | 4,096 | 16,384 |
| `trace_entries_per_chunk` | 4,096 | 4,096 |
| `trace_chunks_total` | 4,194,304 | 16,777,216 |
| `trace_entries_total` | 4,294,967,296 | 17,179,869,184 |
| `trace_normalized_bytes_total` | 274,877,906,944 | 1,099,511,627,776 |
| `trace_single_payload_bytes` | 16,777,216 | 67,108,864 |
| `trace_manifest_bytes` | 67,108,864 | 268,435,456 |
| `spatial_grid_cells_total` | 268,435,456 | 1,073,741,824 |
| `spatial_zone_vertices_total` | 16,777,216 | 67,108,864 |

Importers stream chunks and may not retain more than two uncompressed chunks per
active channel plus configured index/cache budget. Trace seek is index lookup
`O(log chunks)` and one chunk decode. Manifest validation is linear in manifest
entries and bounded before allocating payload buffers.

## 13.4 Network limits

| Field | Default | Hard ceiling |
| --- | ---: | ---: |
| `network_interfaces` | 16,384 | 65,536 |
| `network_segments` | 65,536 | 262,144 |
| `network_forwarders` | 8,192 | 32,768 |
| `network_media` | 4,096 | 16,384 |
| `network_queues` | 65,536 | 262,144 |
| `network_paths` | 65,536 | 262,144 |
| `network_path_hops` | 256 | 1,024 |
| `network_medium_participants` | 4,096 | 16,384 |
| `network_resources_per_medium` | 4,096 | 16,384 |
| `network_pending_frames` | 1,048,576 | 4,194,304 |
| `network_frame_bytes` | 16,777,216 | 67,108,864 |
| `network_queue_frames` | 262,144 | 1,048,576 |
| `network_queue_bytes` | 1,073,741,824 | 8,589,934,592 |
| `network_forwarding_entries` | 1,048,576 | 4,194,304 |
| `network_connection_entries` | 1,048,576 | 4,194,304 |
| `network_contact_entries` | 4,194,304 | 16,777,216 |
| `network_custody_bundles` | 1,048,576 | 4,194,304 |
| `network_loop_hops` | 256 | 1,024 |
| `network_retries_per_frame_per_hop` | 64 | 1,024 |
| `network_duplicates_per_frame_per_hop` | 16 | 256 |

Medium overlap lookup must use an interval/resource index, not scan all pending
frames. Route lookup must be bounded radix/prefix lookup or equivalent ordered
index. A frame traverses at most `network_path_hops` plus
`network_loop_hops`; route mutation cannot reset the consumed hop budget.
The QEMU NIC handoff is a transport boundary rather than a modeled path hop,
but it is bounded by the same compiled maximum: each canonical shared-memory
frame records backpressured guest RX attempts and fails with a typed terminal
error before attempt 1,025. Retained retries are deterministically spaced by
4,000,000 guest instructions, so a callback storm cannot consume the bound
before the guest can make progress. Exact checkpoint/restore preserves that
counter, so a restore cannot reset either the retry schedule or budget.
Canonical ring decoding also remains proportional to its authenticated input:
the process-private snapshot holds compact metadata plus only valid payload
bytes, admits the declared frame count before reservation, and does not
materialize fixed-size shared-memory frame slots until copying into an already
configured destination ring. This prevents a small zero-payload checkpoint from
requesting gigabytes of decoded heap while preserving the full configured frame
ceiling. The enclosing QEMU node continuation measures both canonical rings
before allocating, applies the same 1,610,612,736-byte aggregate ceiling on
encode and decode, reserves the outer encoding fallibly once, and streams each
ring into that allocation without a ring-sized temporary copy. Rejection reports
`current`, `requested`, `configured`, and compiled `hard` values. Its
production-envelope tests round-trip both the full 1,048,576-frame queue
capacity and a populated ring beyond the obsolete 64 MiB boundary.

## 13.5 Storage and 9p limits

| Field | Default | Hard ceiling |
| --- | ---: | ---: |
| `storage_devices` | 4,096 | 16,384 |
| `storage_pending_operations` | 1,048,576 | 4,194,304 |
| `storage_request_bytes` | 16,777,216 | 67,108,864 |
| `storage_queue_operations` | 262,144 | 1,048,576 |
| `storage_cache_bytes_per_device` | 17,179,869,184 | 68,719,476,736 |
| `storage_cache_entries_per_device` | 1,048,576 | 4,194,304 |
| `storage_persistence_dependencies` | 4,194,304 | 16,777,216 |
| `storage_media_intervals_per_device` | 1,048,576 | 4,194,304 |
| `storage_retained_versions_per_interval` | 64 | 1,024 |
| `storage_flash_blocks_per_device` | 16,777,216 | 67,108,864 |
| `storage_array_members` | 256 | 4,096 |
| `storage_retries_per_operation` | 64 | 1,024 |
| `storage_completed_history_epochs` | 1,048,576 | 1,048,576 |
| `storage_completed_history_gaps` | 1,048,576 | 1,048,576 |
| `ninep_sessions_per_device` | 65,536 | 262,144 |
| `ninep_fids_per_session` | 65,536 | 262,144 |
| `ninep_object_versions` | 1,048,576 | 4,194,304 |

Large media/flash state uses sparse interval/counter structures; declaring
geometry does not allocate one object per healthy block. Worst-case sparse
entries remain bounded by media-interval and state-byte limits.

## 13.6 Node and QEMU limits

| Field | Default | Hard ceiling |
| --- | ---: | ---: |
| `nodes` | 4,096 | 16,384 |
| `vcpus_per_node` | 256 | 4,096 |
| `node_mutations_pending` | 65,536 | 262,144 |
| `memory_mutation_bytes_per_effect` | 1,048,576 | 16,777,216 |
| `memory_fault_intervals_per_node` | 1,048,576 | 4,194,304 |
| `memory_access_counters_per_node` | 1,048,576 | 4,194,304 |
| `instruction_fault_rules_per_node` | 65,536 | 262,144 |
| `interrupt_fault_rules_per_node` | 65,536 | 262,144 |
| `interrupt_events_pending_per_node` | 262,144 | 1,048,576 |
| `clock_fault_rules_per_node` | 4,096 | 16,384 |
| `accelerators_per_node` | 256 | 1,024 |
| `accelerator_jobs_pending` | 262,144 | 1,048,576 |
| `instruction_replay_count` | 16 | 256 |
| `interrupt_storm_events` | 1,048,576 | 4,194,304 |

Memory access and instruction matching use canonical interval/PC/TB indexes.
They may not linearly scan all rules on each guest access/instruction. Patch-side
command and result rings have explicit capacities and fail before losing a
command or acknowledgement.

## 13.7 Event, checkpoint, and replay limits

| Field | Default | Hard ceiling |
| --- | ---: | ---: |
| `event_records` | 268,435,456 | 1,073,741,824 |
| `event_log_bytes` | 68,719,476,736 | 274,877,906,944 |
| `event_inline_payload_bytes` | 65,536 | 1,048,576 |
| `checkpoint_count` | 65,536 | 262,144 |
| `fat_checkpoint_bytes` | 17,179,869,184 | 68,719,476,736 |
| `thin_replay_events` | 268,435,456 | 1,073,741,824 |
| `resolved_effect_records` | 268,435,456 | 1,073,741,824 |
| `replay_first_mismatch_context_bytes` | 16,777,216 | 67,108,864 |

Logs and checkpoints are chunked content-addressed artifacts. Reaching a byte or
record bound is a typed terminal result; retaining fewer records is allowed only
under an authored observability policy that still preserves every transition,
decision, effect, and referenced full-value artifact required for explanation.

## 13.8 Search and minimization limits

| Field | Default | Hard ceiling |
| --- | ---: | ---: |
| `search_states` | 1,048,576 | 16,777,216 |
| `search_depth` | 65,536 | 262,144 |
| `search_candidates_per_choice` | 256 | 4,096 |
| `search_choices_per_state` | 65,536 | 262,144 |
| `trace_mutation_windows` | 65,536 | 262,144 |
| `mapping_mutation_points` | 65,536 | 262,144 |
| `minimization_attempts` | 1,048,576 | 16,777,216 |

Search strategies additionally declare a finite fuel count. For a finite
mutation product, `search_states` is one global counter: materializing each
candidate root consumes one state and expanding any frontier within that
candidate consumes one more. The counter never resets between candidates.
Replay, minimization trials, and candidate generation consume their separately
declared finite bounds. Exhaustion returns a complete bounded-search result and
never silently switches strategy.

## 13.9 Future sensor bounds

These are specification values and create no v2 code:

| Field | Default | Hard ceiling |
| --- | ---: | ---: |
| sensor devices | 16,384 | 65,536 |
| channels per sensor | 256 | 4,096 |
| buffered samples per channel | 1,048,576 | 4,194,304 |
| scalar sample bytes | 65,536 | 1,048,576 |
| camera/audio/radar/LiDAR frame bytes | 67,108,864 | 268,435,456 |
| detections/returns per frame | 1,048,576 | 4,194,304 |

## 13.10 Algorithmic requirements

- Signal graph admission is `O(nodes + edges)` excluding explicit lookup/table
  validation; opportunity evaluation visits only dependency closure.
- Trace seek is `O(log chunks)` plus one chunk decode.
- Binding target lookup and effect lookup are `O(log n + matches)` or better.
- Queue selection meets the discipline's indexed bound and cannot scan unrelated
  queues/media.
- Route/path lookup is bounded by address width/path hops, not total frames.
- Storage interval resolution is `O(log intervals + overlaps)`.
- QEMU memory/instruction fault matching is `O(log rules + matches)`.
- Checkpoint serialization is linear in retained canonical state and streams
  content payloads rather than copying the complete store closure.

## 13.11 Performance gates

Performance is non-semantic but prevents technically complete unusable paths.
The harness defines pinned small, medium, and maximum-admitted host profiles.
For each profile, the implementation PR records baselines for:

- signal evaluations and keyed decisions per second;
- trace random seeks and sequential samples per second;
- point-to-point, routed, shared-medium, RF, and contact frame-hop resolutions;
- block/9p operations with cache/media effects;
- QEMU instructions per second with no active match, sparse rules, and active
  instruction/memory hooks;
- checkpoint bytes per second and replay events per second;
- memory use at each default bound fixture.

Merge requirements are: no-active-fault overhead at most 10% for existing live
network/block/9p workloads; QEMU no-matching-rule overhead at most 15% for each
new hook class enabled with an empty rule index; and no benchmark regression over
20% from the first complete implementation baseline without an RFC amendment.
Maximum hard-ceiling fixtures may be admission-only when executing them would
exceed the pinned CI profile, but default-bound fixtures must execute.

- **[LIMIT-4]** Performance shortcuts MUST NOT change canonical results, event
  ordering, arithmetic, or checkpoint state.
- **[LIMIT-5]** A benchmark that cannot distinguish disabled, empty-index, sparse,
  and active-match overhead is insufficient for QEMU hook acceptance.
- **[LIMIT-6]** The release reference MUST publish default/hard bounds and typed
  errors for each field; hidden implementation bounds are prohibited.
