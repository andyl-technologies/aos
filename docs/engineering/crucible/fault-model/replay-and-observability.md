# Recording, replay, and observability

Physical recordings must not smuggle parser, clock, floating-point, or
missing-data behavior into a run, and every resolved effect must be explainable
and reproducible. The fault model uses three artifact layers and three replay
modes.

Sources: [`trace.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/trace.rs),
[`trace_import.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/trace_import.rs),
[`runtime.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/runtime.rs), and
[`runtime/observation.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/runtime/observation.rs).
The user-facing import contract is in
[recorded signals](../../../users/crucible/recorded-signals.md).

## Artifact layers

1. **Raw capture.** CSV, JSON Lines, PCAP, or PCAPNG bytes. Raw bytes are
   provenance only; canonical evaluation never parses them.
2. **Normalized trace.** A `SignalTraceManifest` plus content-addressed
   `SignalTraceChunk`s, produced by a deterministic importer
   (`trace-csv-v1`, `trace-jsonl-v1`, `trace-pcap-v1`, `trace-pcapng-v1`).
   Importing the same bytes with the same importer and options yields
   byte-identical output. No locale, host clock, file metadata, or float
   participates.
3. **Resolved effect trace.** What the model actually did during a run, with
   the evidence needed to re-apply or verify it.

## Normalized trace format

```text
SignalTraceManifest {
  schema, time basis, source-to-virtual time mapping,
  coordinate frame?, spatial redaction?, provenance,
  channels[] { id, value type, unit, scale, chunks[] }
}
SignalTraceChunk {
  channel, ordered entries[] { coordinate delta, value, validity }
}
```

A chunk holds entries for exactly one channel and at most
`TRACE_ENTRIES_PER_CHUNK` (4,096); every non-final chunk is full and empty
chunks are forbidden. Channels are ordered by ID and chunks by first
coordinate, so two importers cannot give equal data different identities by
chunking differently. Large traces are seekable by coordinate through the chunk
index without decoding earlier chunks.

Sample channels have strictly increasing coordinates; event channels may share
a coordinate only with an explicit event sequence. NaN, infinity, implicit
nulls, and ambiguous units are rejected or normalized under explicit importer
policy. Time mapping is piecewise affine (`TraceTimeSegment`), and drift
correction, rounding, discontinuities, and out-of-order handling are importer
outputs inside the normalized identity. Cross-device alignment comes from
recorded markers or explicit offsets, never from file timestamps.

Spatial traces are normalized to integer millimetre local Cartesian
coordinates. A `SpatialRedaction` (translation, rotation, quantization) happens
before publication and changes identity; the canonical plaintext digest stays
the semantic identity, while storage protection is an orthogonal envelope.
Physical truth trajectories and guest-observed location are distinct channels.

## Replay modes

`FaultReplayMode` selects how a run treats a resolved-effect trace:

- **`recomputed_cause`** re-evaluates signals and bindings from the same
  scenario, normalized sources, seed, and schedule, verifying sample hashes,
  opportunity IDs, keyed decisions, composed effects, adapter outcomes, and
  fingerprints. It proves the evaluator and adapters are deterministic.
- **`locked_effect`** treats the recorded resolved effects as authoritative
  while still checking each record against the encountered target, phase,
  opportunity, precondition, and capability version. It reproduces incidents
  across model calibration changes, provided effect and capability semantic
  versions are identical; there are no compatibility shims.
- **`outcome_only_network`** replays a recorded per-frame outcome stream with a
  `NetworkOutcomeAlignment`.

Every evaluated boundary and opportunity produces one `ResolvedReplayWorkItem`,
even when its effect list is empty. Recording passes and inactive bindings
keeps sparse faults from shifting onto earlier frames and authenticates
state-machine-only transitions. Each work item and effect carries a
derivation fingerprint over the post-derivation signal/binding continuation;
recomputed replay compares it before any adapter mutation.

A `ResolvedEffectRecord` carries the effect key and semantic version, binding,
resolved target, opportunity, coordinate, phase, lifetime, mapping output,
transition sequence and cause, contributors, capability, an evidence digest,
and the backend-observed `precondition_digest`. Destructive memory, register,
and storage mutations verify that exact digest before applying locked bytes;
absence or mismatch fails before mutation. Locked
replay fails at the first mismatch, with expected and observed context, and
never falls back to recomputation. Host network and storage adapters preserve
the scheduler coordinate exactly; only QEMU node effects carry a
retired-instruction refinement.

### Network outcome alignment

| Alignment | Matches |
| --- | --- |
| `exact_frame_key` | Producer, destination, producer sequence, expansion/response/forwarding ancestry, length, and payload digest; scheduler coordinate may differ. |
| `producer_direction_sequence` | Producer identity, link direction, and producer sequence. |
| `exact_event_coordinate` | Virtual/retired-instruction coordinate and same-coordinate sequence. |
| `ordered_time_bucket` | Compatible frames in recorded order within one positive-width virtual-time bucket. |

Every mode also requires exact target, operation, phase, and direction. Each
observed frame consumes exactly one aligned work item, and aligned effects are
rebound to the live frame's opportunity and coordinate before application, so
key- and sequence-based alignment tolerate timing drift. Zero width, a
non-frame record, incompatible context, reordering, exhaustion, or leftover
items fail replay; ambiguous matches are errors, not nearest-packet guesses.

## Event log records

`FaultObservationKind` adds these records to the unified event log:
`signal_transition`, `signal_sample`, `signal_state_transition`,
`binding_activation`, `binding_deactivation`, `fault_opportunity`,
`effect_choice`, `effect_combined`, `effect_committed`, `effect_applied`,
`effect_rejected`, `network_profile`, `association_transition`, and
`trace_alignment`. Ordering follows the scheduler's canonical event order and
adapter phase order. Bindings declare an observability policy so unchanged
high-rate samples need not be logged, but every transition and applied effect
stays explainable from retained artifacts and state. Content-addressed profiles
and values are referenced rather than repeated.

A retained run can answer which signal caused an effect, which binding and
transfer function mapped it, which opportunity it affected, which other targets
share the cause, the before and after state, and whether the outcome was
computed or locked.

## Checkpoints and findings

Checkpoint state includes trace manifests and reachable chunk references,
source cursors, stateful signal state, active contributions and transition
sequences, adapter state, the resolved-effect replay cursor, search overrides,
and fingerprints over all of it (see
[bindings and runtime](bindings-and-runtime.md#runtime-and-checkpoint-state)).
Reverse execution restores an earlier checkpoint and replays; inspection never
mutates canonical signal state, and a debugger edit to a signal, mapping,
trace, or outcome forks a non-canonical branch.

A signal-fault finding embeds the authenticated transitive closure of
normalized trace, spatial, and sampler objects its fixed scenario needs, plus
any search-materialization recipe and generated artifacts, so replay works in
an isolated store after the producer's store is gone. Artifact export lists
provenance dependencies so operators can spot sensitive traces in the closure.
