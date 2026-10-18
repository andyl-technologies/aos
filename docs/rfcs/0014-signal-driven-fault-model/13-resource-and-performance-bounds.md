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
before allocating, applies the authored `fat_checkpoint_bytes` ceiling and
64 GiB hard ceiling symmetrically on encode and decode, reserves the outer
encoding fallibly once, and streams each ring into that allocation without a
ring-sized temporary copy. Each individual network ring is additionally capped
at the 8 GiB `network_queue_bytes` hard ceiling. Rejection reports `current`,
`requested`, `configured`, and compiled `hard` values. Its production-envelope
tests round-trip both the full 1,048,576-frame queue capacity and a populated
ring beyond the obsolete 64 MiB boundary.

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

`ninep_object_versions` counts every live visibility update at or above the
compaction floor, the compacted per-path residue (one or two versions per
path), stale or misdirected directive objects, and exact virtual fids. It is
therefore bounded by distinct authored paths plus unreleased updates rather
than by run length. `ninep_sessions_per_device` is always one, because a
`Tversion` retires the previous session.

Large media/flash state uses sparse interval/counter structures; declaring
geometry does not allocate one object per healthy block. Worst-case sparse
entries remain bounded by media-interval and state-byte limits.

Media and flash continuations are keyed by the identity of one resolved
binding action, so a re-upserted binding starts a new continuation. A replaced
or removed action never returns, and an existing continuation is consulted
again only through a retained directive that already names it. After the
storage adapter installs a directive, it passes the identities of every live
persistent media and flash action to the device, which retires each
continuation that is neither live nor named by a retained directive.
`storage_media_intervals_per_device` therefore counts live and in-flight
contributors, not every contributor installed during the run. Retired media
counters are dropped because no later request reads them. A retired flash
continuation folds its changed-cell XOR masks into a device-level residual that
every read applies, so reads stay bit-identical; like the masks of an inactive
continuation, the residual is never cleared by a later program or erase. A
continuation with an in-progress erase decision is never retired.

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

`thin_replay_events` and `resolved_effect_records` bound the running work-item
and record counters of the segmented resolved-effect trace (RFC-0020 section
15.10). They are checked against the counters before an append, never by
collecting the trace, and a checkpoint stores the counters beside the sealed
segment references and the open tail; `fat_checkpoint_bytes` bounds that
encoded position.

Logs and checkpoints are chunked content-addressed artifacts. Reaching a byte or
record bound is a typed terminal result; retaining fewer records is allowed only
under an authored observability policy that still preserves every transition,
decision, effect, and referenced full-value artifact required for explanation.
`event_records` is one aggregate ceiling across referenced events, pending
observations, raw QEMU occurrences, issued-action and commit ledgers, and active
rule identities. Referenced events count cumulatively: each emission is charged
once, when its evaluation stages, against running record and byte counters that
the production checkpoint stores beside a history chain digest. The runtime
retains only the occurrences a registered block or 9p consumer can still select
(RFC-0020 CMEAS-26), so neither accounting nor checkpointing rescans the emitted
history. Pending observations and raw occurrences drain at every boundary and
are measured directly. The host derives the remaining capacity before a plugin
control pump or fault transaction. It freezes every non-target node at its
current ownership, arms only the node whose control callback is about to run,
and subtracts newly staged records before arming the next node. Restore first
authenticates the complete checkpoint identity and requires empty live
occurrence-event ownership, then installs the same aggregate policy before its
first fingerprint control pump and requires ownership to remain empty after that
pump. It never gives each collection or node an independent copy of the authored
allowance; LIMIT-2 coordinates report the complete canonical current count and
the plan-authored aggregate ceiling rather than a per-node remainder. Before any
production adapter APPLY can become visible, the controller also owns the
deterministic emitted-event, boot-request, and explorer-choice publication batch
and reserves those persistent destinations plus the exact evaluation-observation
tail. Publishing that model-owned batch after APPLY only moves staged owners.
QEMU occurrence evidence, which cannot exist before APPLY, uses the separately
bounded, fallible raw-event drain described above and poisons the continuation
if authentication or typed allocation fails.

The controller's terminal-lifecycle process ownership uses one versioned
`run-state.json` envelope (version 3) and an append-only
`lifecycle-exits.jsonl` exit log beside it. The envelope atomically couples the
current and staged QEMU process identities to the lifecycle phase,
authenticated action and evidence hashes, the committed exit-log prefix, and the
runtime event-record and byte bases. There is no separately published manifest
or journal and no legacy fallback, so a rename cannot expose half of a
process-generation transition. Completed exits are history that is only counted
and validated after commit, so they live in the log rather than the envelope,
which therefore stays bounded by node count. The log holds one canonical
compact JSON line per committed exit; the envelope records its record count,
byte length, and a SHA-256 chain over the lines. A lifecycle commit first
truncates the log to the recorded prefix, appends the transaction's exits, and
syncs the file (and its directory when new); only then does it rename the
envelope that records the longer prefix. A crash between the two steps leaves
an unreferenced tail, which the next append or a recovery takeover of a dead
owner truncates; a failed append or rename restores the committed reference so
a retry writes the same bytes. Encoding is measured before one fallible exact
reservation and then writes only within that reserved storage. Recovery bounds
the envelope before reading, performs a count-only preflight before
constructing owned maps or record vectors, charges the envelope plus the
recorded log length against the remaining `event_log_bytes`, charges journal
nodes plus recorded exits against the remaining aggregate `event_records`
without reading the log, and rejects any phase, generation, transition, or
process-identity ownership matrix that the live publisher cannot produce. It
then streams only the recorded log prefix once, verifying each record's
canonical encoding and fields, non-decreasing transactions, per-transaction
node uniqueness, the record count, and the chain; a live owner's in-progress
tail is ignored.

Canonical QEMU node, host-I/O, production fault-runtime, and complete VMState
envelopes admit their representation against `fat_checkpoint_bytes` and its
64 GiB hard ceiling before final allocation. Nested owners retain independent
typed bounds; sequence decoders use fallible reservation even for indefinite
hostile CBOR. Durable closure manifests and lifecycle objects also decode text
through an envelope-bounded scratch buffer and reserve each final owned string
fallibly before copying, including canonical strings larger than the CBOR
library's default scratch space. The complete VM snapshot uses a
length-delimited envelope that borrows nested inputs rather than first
materializing duplicate vectors. The
scheduler-facing network queue encoder additionally enforces
`network_queue_frames` and the 8 GiB `network_queue_bytes` hard ceiling. Durable
store and fresh-process load apply the identical authored ceiling to every
large continuation and to the aggregate content-addressed closure. Allocation
or representation failure is a LIMIT-2 outcome carrying the exact current,
requested, configured, and hard values rather than a process abort. The raised
resource policy also covers the closure publication transaction. Every target
and artifact path is owned before the first QMP save, all live QEMU snapshots
are deleted in reverse order before the closure rename, and a staging or delete
failure cannot enter durable publication. The production rename seam admits
the exact published count, durably removes a rejected destination, and retains
an indeterminate identity whenever parent-directory durability cannot establish
one outcome. Fresh-process recovery authenticates published identities and
durably removes abandoned transaction staging before another capture.

The raised
resource policy is carried only by the versioned node-v7, host-I/O-v4,
block-snapshot-v3, block-fault-state-v2, 9p-snapshot-v5, I/O-core-v2,
production-runtime-v8, and VM-snapshot-v4 formats; production runtime identity
uses the v11 domain and VM snapshot identity uses the
`exact-snapshot.v7` domain, so old policy identities cannot alias new artifacts.

## 13.8 Search limits

| Field | Default | Hard ceiling |
| --- | ---: | ---: |
| `search_states` | 1,048,576 | 16,777,216 |
| `search_depth` | 65,536 | 262,144 |
| `search_candidates_per_choice` | 256 | 4,096 |
| `search_choices_per_state` | 65,536 | 262,144 |
| `trace_mutation_windows` | 65,536 | 262,144 |
| `mapping_mutation_points` | 65,536 | 262,144 |

Search strategies additionally declare a finite fuel count. For a finite
mutation product, `search_states` is one global counter: materializing each
candidate root consumes one state and expanding any frontier within that
candidate consumes one more. The counter never resets between candidates.
Replay and candidate generation consume their separately declared finite
bounds. Exhaustion returns a complete bounded-search result and never silently
switches strategy.

The fault plan carries no minimization limit. The fault runtime performs no
minimization; failure-preserving finding minimization is bounded by the
compiled 4,096-candidate minimization policy of RFC-0020 section 03.10, which
is published there and retained in every minimized reproduction's policy
identity rather than hidden. An authored plan that still names a
`minimization_attempts` field is rejected as an unknown resource limit.

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
