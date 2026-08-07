# 11 — Storage durability, media, array, and 9p semantics

This file defines the state model needed to implement every storage taxonomy row
without treating persistence faults as generic completion errors. Block and 9p
operations use the same deterministic opportunity and replay machinery but keep
their protocol semantics typed.

All named policies and typed results are declarations in the closed
`world.storage_policy_artifact` registry specified by §9.7. Runtime code resolves
the declaration during admission and retains its content identity in evidence.
It never assigns behavior by comparing an ID string, consulting a host file, or
falling back to a generic I/O error. Cross-artifact references are class-checked
before any guest starts.

## 11.1 Storage state layers

Each block device owns these bounded layers:

```text
guest request/completion protocol
        |
admission and request queue
        |
controller/namespace/path state
        |
volatile write cache and ordering frontier
        |
durable logical block map
        |
media geometry, health, wear, and physical cell/sector map
```

Canonical state contains request and completion queues, service/token remainder,
controller/path/namespace state, volatile entries, persistence dependencies,
durable logical versions, media range overlays, flash counters/state, array
state, retry counters, and every sequence/frontier below.

- **[STORE-1]** Guest completion, controller acceptance, volatile-cache
  acceptance, and durable persistence are distinct events and coordinates.
- **[STORE-2]** A success completion MUST identify the highest durability layer
  reached under the declared device policy; success never implicitly means
  durable.
- **[STORE-3]** State required to answer a later read or flush MUST be bounded,
  canonical, checkpointed, and included in locked-replay preconditions.

## 11.2 Geometry and versions

Required immutable fields:

| Field | Rule |
| --- | --- |
| `logical_block_bytes` | Positive power of two, 512–65,536. |
| `physical_sector_bytes` | Positive power of two and multiple of logical block size. |
| `atomic_write_bytes` | Positive multiple of logical block size, no greater than physical sector size unless device contract proves larger atomicity. |
| `length_bytes` | Positive multiple of logical block size. |
| `discard_granularity_bytes` | Zero only when discard unsupported; otherwise aligned power-of-two multiple. |
| `maximum_request_bytes` | Positive, aligned, and bounded by §13. |

Every admitted write is split deterministically at atomic-write boundaries into
`WriteFragmentId(request_id, fragment_index, start, length)`. Each fragment has
an intended byte digest, controller sequence, cache sequence if cached, durable
sequence if persisted, and logical version ID. No host filesystem or block-device
atomicity is assumed.

Reads resolve each requested byte range against a canonical interval map. Mixed
versions across fragments are allowed only when produced by an explicit torn,
misdirected, or reordered-persistence effect and are recorded in the read
evidence.

## 11.3 Request lifecycle

```text
produce
  -> admit or reject
  -> controller queue
  -> service/execute
  -> resolve status and data transform
  -> enter volatile cache or durable-media queue
  -> persist according to dependencies/service
  -> complete to guest
```

Device policy declares whether completion may occur at controller acceptance,
volatile-cache acceptance, or durable persistence for each operation. A fault
may alter disposition only through registered effects; it may not rewrite the
base policy invisibly.

Admission applies offline/read-only/capacity/queue rules before allocating a
request ID. Rejected attempts receive a stable attempted-opportunity identity.
Timeout is a modeled consumer deadline, not host elapsed time. A dropped
completion retains the resolved internal operation outcome so reset/retry and
locked replay remain explainable.

## 11.4 Volatile cache

A cache entry contains fragment ID, bytes or content reference, logical range,
cache sequence, dependency set, dirty state, and optional persistence deadline.
Capacity is exact bytes plus entry count. Eviction policy is `fifo`, `lru` by
modeled access order, or `writeback_sequence`; ties use fragment ID. Dirty
eviction either schedules persistence or fails according to the device policy;
it never silently discards data.

Cache-loss selectors are:

- all dirty entries;
- entries after a cache sequence;
- entries whose range intersects a selector;
- a keyed bounded subset;
- entries not protected by a declared power-loss-protection domain.

Target scope and power-loss protection filter the eligible set before the
selector runs. `keyed_subset` selects `min(count, eligible entries)` by keyed
rank and then restores canonical sequence order. Loss resolution records the
complete pre-loss entry-set digest and atomically removes only the selected
volatile versions on the device-identity-bound owning worker; no request service
can interleave between those steps. Record execution returns the observed digest.
Locked replay supplies the recorded digest as a mandatory precondition and fails
before selection or mutation when it differs. Reads after loss resolve the prior
durable version.

Controller-accepted entries occupy a separate bounded byte/entry buffer and do
not consume volatile-cache capacity. Controller reset/loss selects only that
layer; volatile-cache loss selects only cache entries. Promotion and flush merge
the two layers by their shared global write sequence, preserving exact issue
order without conflating their capacities or loss domains.

## 11.5 Persistence dependency graph

Persistence is a finite DAG. A fragment may persist when its dependencies are
durable and media/controller service admits it. Dependencies arise from:

- per-request fragment order when declared;
- ordered/FUA writes;
- flush/barrier frontiers;
- filesystem/9p transaction policy;
- array stripe/parity ordering;
- explicit fault-induced persistence order.

Ready fragments are selected by durable dependency depth, controller sequence,
range start, and fragment ID. A reordered-persistence effect changes declared
edges or priority through a closed transformation and records before/after graph
digests; it cannot create a cycle. Cycles fail at the effect boundary.

## 11.6 Write dispositions

| Disposition | Exact semantics |
| --- | --- |
| `apply` | Selected fragments follow normal cache/persistence policy. |
| `lost` | Selected fragments never enter cache or media; guest status/acknowledgement is an explicit independent field. |
| `torn` | Deterministic atomic fragments or byte masks apply; unselected bytes retain their prior durable/logical version. |
| `misdirected` | Selected fragments apply to an explicit resolved replacement range; source range is unchanged. |
| `program_failure` | Flash page program applies the declared prefix/subset or none and returns the declared media/controller status. |

Torn selectors operate at configured atomic fragments by default. Byte-level
tearing requires `allow_subatomic_tearing = true`, an exact bit/byte mask, and a
capability that exposes that lower fidelity honestly. Misdirection validates
replacement range, alignment, overlap, and capacity before execution. The
authored replacement `ByteRange` is a bounded transfer window, not an implicit
request-relative address. The resolved operation starts at the window's
`start`; its complete request byte count is copied contiguously and must fit
within `length`. Admission requires the window to accommodate the largest
request legal for every selected block target (the lesser of a selected block-
range length and that device's declared maximum request size), so a live adapter
never invents truncation, wrapping, modulo addressing, or a host-dependent
offset. The unused suffix of a larger window is unchanged. Source and
destination windows are physical-device bounded and logical-block aligned; the
concrete operation still enforces its atomic-fragment alignment.

Cross-device misdirection is a two-device transaction. The owner stages the
destination mutation through the destination's own geometry and normal
controller/cache/durable policy, stages the source request with a lost local
write and the sole guest completion, and commits both complete device states
together. Any destination admission, state-limit, mutation, or source completion
scheduling failure leaves both devices byte-identical to their pre-operation
checkpoints. Same-device misdirection uses the same atomic-fragment rules without
creating a second device transaction.

Acknowledged lost/torn/misdirected writes are distinct from failed writes. The
event log records guest status, logical visibility, cache state, and durable
state separately.

## 11.7 Flush, barriers, FUA, and lying flush

A flush captures `flush_frontier`, the set of cache/controller sequences admitted
before the flush opportunity. An honest successful flush completes only when all
required entries through that frontier are durable. Later writes are not
implicitly included. FUA writes require their own fragments durable before
success.

Flush dispositions:

| Kind | Guest result | Internal result |
| --- | --- | --- |
| `honest` | success after frontier durable | durable frontier advances normally |
| `error` | typed failure | persistence may continue only if policy explicitly says so |
| `stall` | no completion until recovery/timeout | frontier retained |
| `lie` | success at modeled resolve coordinate | durable frontier does not advance for selected entries |

A lying flush records both reported and actual frontier. A subsequent honest
flush may persist the entries unless they were separately lost. Reset/power loss
then applies cache-loss policy to the actual state, not the reported frontier.

A stalled flush captures its exclusive controller/cache sequence frontier when
the request resolves. Recovery persists exactly entries below that captured
frontier before releasing the original success; writes admitted later remain
volatile. Timeout releases the configured typed failure without persistence or
reported-frontier advancement. The retained record includes the original
request coordinate, resolved dynamic delay, recovery response, timeout response,
and captured frontier. Release is one transaction with response scheduling: a
scheduling failure commits neither overlay nor durability state and leaves the
completion retained for exact retry.

## 11.8 Reset, reconnect, namespace, and path state

Controller states are `offline`, `initializing`, `online`, `resetting`,
`reconnecting`, `degraded`, and `failed`. A transition declares treatment of
unadmitted, queued, executing, resolved, cached, and completed-but-undelivered
operations. Each is `reject`, `fail`, `retry_preserve_id`, `retry_new_id`,
`complete`, `drop_completion`, `preserve`, or `lose` as applicable; no default.

Namespace/path changes use immutable versioned sets. Capacity changes specify
whether truncated ranges become inaccessible, read as zero, or retain hidden
data for a later expansion. Expanding capacity initializes bytes by declared
zero/content artifact, never host garbage.

Multipath selection uses versioned path policy and stable operation keys.
Failover treatment of in-flight operations and duplicate-suppression identity is
explicit.

Every path references a typed `path` artifact; every remote medium references a
typed `remote_protocol` artifact. These references have no string-convention or
host-default meaning. A controller-lifecycle effect may name only namespaces and
paths owned by every controller selected by its binding.

## 11.9 Media range and latent faults

Media overlays are canonical non-overlapping intervals produced by splitting
overlapping declarations at all boundaries. At each resulting interval,
contributors combine by severity and ordered transform rules.

| State | Activation and behavior |
| --- | --- |
| `bad` | Immediate persistent typed error or configured deterministic corruption. |
| `latent` | Becomes bad/corrupt after time, read count, write count, temperature integral, or explicit event threshold. |
| `poisoned` | Read produces uncorrectable status and optional platform error event. |
| `read_only` | Writes/erase rejected while reads resolve normally. |

Threshold counters increment at stable media opportunities, not guest retries
that fail before media. Scrub/repair is an explicit operation that may clear or
relocate state according to media policy.

## 11.10 Flash model

Required geometry includes page, erase-block, planes/dies if modeled, endurance,
and read/program/erase service. Each erase block stores erase count, last erase
coordinate, temperature exposure accumulator, failed-page/range overlays, and
read-disturb counters.

- Program changes only permitted bit direction until erase under the declared
  flash convention; violations return typed program failure.
- Erase resets cell/page content to the declared erased byte and increments the
  exact erase count.
- Wear lookup maps erase count and environment to program/erase failure,
  retention, latency, and read-only thresholds.
- Retention evaluates a versioned integer lookup over time since program,
  temperature exposure, wear, and page identity; selected bit changes are keyed
  by page/cell/opportunity.
- Read disturb increments neighboring-row/page counters under an explicit
  adjacency map and triggers registered corruption at exact thresholds.
- Program/erase partial application uses exact page/sector selectors and records
  resulting physical/logical mapping.

Flash translation-layer behavior, when modeled, is a bounded canonical map with
allocation, garbage-collection, and wear-leveling policy. If absent, logical
pages map directly; the runtime does not invent an FTL.

## 11.11 Magnetic/sector media and read correction

Sector media may declare corrected-retry thresholds, remap/spare pools, and
read/write error lookup state. A corrected read records retries and service
delay but returns correct data. Exhausted correction produces typed error or
explicit corruption. Remapping consumes a deterministic lowest-ID eligible spare
and preserves or loses content according to the triggering effect.

## 11.12 Arrays, RAID, and rebuild

Array declarations contain layout (`mirror`, `stripe`, or explicit parity
layout), members, stripe/chunk geometry, quorum, read/write selection, degraded
policy, rebuild target/source selection, and consistency policy. Parity math is
a versioned exact byte operation with golden vectors.

Member/path failures update array state before the next opportunity. Rebuild is
a bounded background operation sharing the same storage service model and
creating stable range opportunities. Rebuild failure, latent source errors,
second failures, and writes racing rebuilt ranges use explicit ordering and
result policies. Checkpoints include rebuild cursor, target versions, and array
consistency digest.

## 11.13 Read transforms

- Bit corruption selects exact returned bit positions keyed by binding and read
  opportunity; it does not mutate durable media unless a separate media effect
  does so.
- Stale read selects a retained prior logical version by explicit version ID,
  maximum age/version distance, or keyed choice from a bounded eligible set.
- A misdirected read of `request.count` bytes uses exactly
  `[source_range.start, source_range.start + request.count)` within its declared
  source window; the window suffix is not read.
- Mixed-version reads record every source interval/version.

Retained versions consume bounded history budget. Admission rejects scenarios
whose stale-read policy can require more versions than the declared limit.

## 11.14 9p and filesystem-facing semantics

The 9p adapter models typed request/result fields, fid/session state, namespace
objects, data versions, and visibility frontiers; it does not claim to simulate
an arbitrary host filesystem. Supported operations are the closed 9p set already
declared by Crucible's device codec.

- Errno injection returns only an errno valid for the operation/schema.
- Stale metadata/data selects a retained object/data version and preserves its
  associated attributes consistently unless a field-specific corruption effect
  says otherwise.
- Delayed visibility separates committed update sequence from the per-session or
  global visible frontier under an explicit policy.
- Namespace/data reordering respects declared dependencies; impossible object
  references are rejected rather than created.
- Reset/reconnect declares fid/session retention and pending-request treatment.

9p state, responses, and versions are content-addressed independent of host
inode numbers, mtimes, directory iteration, and filesystem behavior.

## 11.15 Completion duplication and protocol validity

A duplicate completion is injected only at the modeled guest transport boundary.
It carries the same request identity and payload unless an ordered payload
transform applies. The device/guest protocol decides whether the duplicate is
ignored, rejected, or causes a modeled protocol error; the simulator records
that outcome and never invokes undefined host behavior. Test fixtures must cover
ring/index wrap and duplicate-after-reset cases.

Authored `gap_nanos` is the delay between adjacent completions. For additional
copy index `i` starting at zero, the resolved delivery delay from the primary is
`gap_nanos * (i + 1)` using checked integer arithmetic. The resolved directive
stores these strictly increasing primary-relative delays; overflow rejects the
effect before device mutation. `reset` is not an evidence-only label: delivery
of the first duplicate must execute the live guest transport reset transition,
including its specified pending-request and post-reset request-ID treatment.
The duplicate policy therefore references a reset-kind typed
`controller_transition` artifact.
That artifact independently fixes requests arriving during reset, queued and
executing requests, resolved results, completed-but-undelivered results,
controller-buffer and volatile-cache retention, monotonic versus new-epoch
request-ID allocation, pre-reset duplicate-history retention, namespace/path
re-enumeration, the typed failure result, and exact recovery duration. A new
epoch increments before its request counter restarts at zero, so request
identity is the `(epoch, request_id)` pair and can never alias an old duplicate.

## 11.16 Storage replay evidence

Every storage effect record retains the applicable subset of:

- request/fragment/range/version IDs;
- queue/service/cache/durable frontiers;
- dependency graph digest;
- guest status and completion coordinate;
- intended, cached, durable, returned, and transformed byte digests;
- controller/namespace/path/array state versions;
- media range, wear, threshold, retry, and flash counters;
- exact before state required by a destructive locked replay.

- **[STORE-4]** Locked replay MUST verify all state that made a persistence or
  media decision eligible before applying it.
- **[STORE-5]** Save/restore at every lifecycle stage in §11.3 MUST equal an
  uninterrupted run, including service remainder and completion ordering.
- **[STORE-6]** Every storage taxonomy row MUST have a live block or 9p gate;
  media/array logic may use a deterministic modeled backend, but guest transport
  and completion behavior must be exercised through live QEMU.
- **[STORE-7]** No storage effect may be implemented solely by changing the
  returned status when its specified semantics modify cache, durability, media,
  namespace, path, array, or future-read state.
