# 05 — Recording, normalization, replay, observability, and calibration

The framework must accept real physical recordings without allowing parser,
clock, floating-point, or missing-data behavior to become hidden nondeterminism.
It must also explain and reproduce the concrete effects that a signal program
resolved.

## 5.1 Three artifact layers

### Raw capture

The raw capture is retained byte-for-byte when licensing, size, and privacy
policy allow. It may be CSV, PCAP/PCAPNG, modem diagnostic output, telemetry
JSON, binary sensor data, satellite contact logs, SMART/NVMe logs, power-quality
samples, or a vendor format. Raw bytes are provenance, not canonical evaluator
input.

Raw metadata records:

- capture tool and version;
- source device/instrument identifiers or redacted stable aliases;
- original clocks/time zones/epochs;
- declared units and calibration;
- capture start/end and gaps;
- importer version and command options;
- privacy/redaction policy;
- raw content hash.

### Normalized signal artifact

The importer produces a canonical artifact containing:

- artifact schema and semantic version;
- monotone integer time axis or ordered event coordinates;
- named typed/unit-bearing channels;
- integer/fixed-point values;
- validity/quality indicators;
- coordinate-frame metadata;
- explicit gaps and discontinuities;
- chunk index if chunked;
- raw provenance hash and importer identity;
- canonical digest.

### Resolved effect trace

During execution, Crucible records what the model actually did:

- signal transition/sample reference;
- binding and target;
- opportunity ID and context;
- mapped effect parameters;
- keyed decision input/result where probabilistic;
- composition result;
- adapter application result;
- delivery/completion/state-transition outcome;
- before/after digests for destructive mutation;
- backend capability semantic version.

- **[REP-1]** Canonical evaluation MUST read normalized signal artifacts, never
  parse raw capture formats during a run.
- **[REP-2]** A normalized artifact MUST retain a reference to raw provenance or
  an explicit reason that raw material was not retained.
- **[REP-3]** Importing the same raw bytes with the same importer semantic
  version and options MUST produce byte-identical normalized output.

## 5.2 Canonical trace format

The logical format is independent of its final binary encoding:

```text
SignalTraceManifest {
  schema
  time_basis
  source_to_virtual_mapping
  coordinate_frame?
  channels[] {
    id
    value_type
    unit
    scale
    interpolation_capabilities
    chunks[] { start, end, sample_count, content_hash }
  }
  provenance
}

SignalTraceChunk {
  channel_id
  strictly ordered samples[] { coordinate_delta, value, validity }
  ordered events[] { coordinate_delta, event_sequence, payload }
}
```

Chunks are independently content-addressed and contain at most 4,096 samples or
events from exactly one channel. Every non-final chunk contains exactly 4,096
entries; empty chunks are forbidden. The manifest orders channels by canonical
channel ID and chunks by their first coordinate, fixing boundaries so two
importers cannot produce equal logical samples with different identity by
arbitrary chunking.

- **[REP-4]** The trace format MUST define byte order, integer widths, varint or
  fixed-width encoding, string normalization, channel order, chunking, and digest
  domains.
- **[REP-5]** Sample channels MUST have strictly increasing coordinates. Event
  channels MAY share coordinates only with an explicit stable event sequence.
- **[REP-6]** NaN, infinity, implicit null, locale-dependent decimal parsing, and
  ambiguous unit strings MUST be rejected or normalized under explicit importer
  policy before canonicalization.
- **[REP-7]** Large traces MUST be seekable by coordinate without decoding all
  prior chunks, while stateful signal operators remain checkpointed separately.

## 5.3 Time alignment

Real captures often contain several clocks. Normalization distinguishes:

- source timestamp;
- capture-host timestamp;
- device monotonic counter;
- sequence number;
- synchronization markers;
- Crucible virtual time.

Each imported channel declares an exact affine mapping where possible:

```text
virtual_nanos = floor((source_ticks - source_epoch) * numerator / denominator)
                + virtual_epoch_nanos
```

Piecewise clock correction uses explicit segments and discontinuities. An
uncertain mapping may include a quality channel, but canonical evaluation still
chooses one exact coordinate per sample.

- **[REP-8]** Time mapping, drift correction, rounding, discontinuity treatment,
  and out-of-order policy MUST be importer outputs included in normalized
  identity.
- **[REP-9]** Cross-device alignment MUST use recorded markers or explicit
  operator-provided offsets; the importer MUST NOT infer alignment from host file
  modification times.
- **[REP-10]** A scenario MUST map trace time to simulation time explicitly,
  including trim, repeat, scale, and epoch behavior.

## 5.4 Spatial normalization

Geographic or facility recordings may use latitude/longitude/altitude, map
coordinates, odometry, or local frames. The importer writes:

- original coordinate reference metadata;
- local Cartesian origin and axis convention;
- integer millimetre coordinates;
- orientation representation and normalization;
- transform semantic version;
- uncertainty/validity channels when available.

For privacy-sensitive movement traces, a deterministic redaction transform may
translate/rotate or quantize the local frame. The redacted normalized artifact
gets a different identity and records the redaction policy without retaining
secret coordinates in ordinary reproduction artifacts.

- **[REP-11]** Physical truth trajectory and observed GPS/location channels MUST
  have distinct channel IDs and semantics.
- **[REP-12]** Spatial redaction MUST occur before canonical artifact publication
  and MUST be identity-bearing.

## 5.5 Replay modes

### Recomputed-cause replay

Crucible loads the same scenario, normalized sources, seed, and schedule, then
reevaluates signals and bindings. It verifies:

- signal transition/sample hashes;
- opportunity identities;
- keyed decisions;
- mapped and combined effects;
- adapter outcomes;
- event-log and execution fingerprints.

The trace contains one work-item envelope for every evaluated boundary and
opportunity, even when it resolves to no adapter action. Each envelope carries
the post-derivation fingerprint and an ordered, possibly empty, effect list.
Consequently, a pass outcome, an inactive binding, and a state-machine-only
transition are authenticated rather than disappearing from the replay stream.

This mode proves the signal evaluator and adapters are deterministic.

### Locked-effect replay

Crucible uses the resolved effect trace as the authoritative operation-level
outcome. It still validates that each record matches the encountered target,
phase, opportunity, payload/state precondition, and backend capability. It does
not require rederiving the effect from the original physical model.

This mode supports incident reproduction across model calibration changes while
the exact effect and backend capability semantic versions remain identical. A
version mismatch is rejected; this implementation does not carry compatibility
shims for older effect semantics.

### Outcome-only network replay

A recorded packet/network outcome stream is a specialized locked-effect source.
It contains every observed network-frame work item, including pass frames with
an empty effect list; sparse or sporadic faults therefore retain their exact
position in the stream.
Alignment modes are:

- **exact stable frame key** — matches producer, destination, producer-owned
  sequence, protocol-expansion ancestry, generated-response ancestry,
  forwarding-mutation ancestry, immutable length, and payload digest while
  allowing the replay scheduler coordinate to differ;
- **producer/direction sequence** — matches the producer identity, link
  direction, and producer-owned sequence;
- **exact event coordinate and sequence** — matches virtual/retired-instruction
  coordinate and same-coordinate scheduler sequence;
- **ordered time bucket** — requires a positive bucket width and consumes
  compatible target/operation/phase/direction frame groups in recorded order
  within the same `floor(virtual_nanos / width)` bucket.

Every mode also requires exact target, operation, phase, and direction. Every
observed frame consumes exactly one aligned work item, whether its effect list
is empty or nonempty. Once a recorded work item aligns, each typed effect is rebound to the observed frame's
current opportunity identity and scheduler coordinate before adapter
application. Thus frame-key and producer-sequence replay can tolerate timing
drift without applying an old opportunity identity to the live frame. A zero
bucket width, non-frame record, incompatible context, reordering, exhaustion,
or leftover work item fails replay.

Ambiguous matching is an error, not a “closest packet” guess.

- **[REP-13]** Every reproduction artifact MUST name replay mode and the required
  cause/effect artifacts. A signal-fault finding MUST embed the authenticated
  transitive closure of normalized trace, spatial, and sampler objects needed
  by its fixed scenario. If search materialized a trace or mapping mutation, it
  MUST additionally embed the ordered candidate recipe, original program and
  binding identities, per-case provenance, and generated artifact identities.
  Replay restores that closure into an isolated content-addressed store and
  MUST remain valid after the producer's store is unavailable.
- **[REP-14]** Locked replay MUST fail at the first mismatch with expected and
  observed opportunity context, not silently fall back to recomputation.
- **[REP-15]** Every resolved record MUST carry the backend-observed before-state
  digest. A destructive memory/register/storage mutation MUST verify that exact
  digest before applying locked bytes; absence or mismatch fails before
  mutation.
- **[REP-16]** Recomputed and locked replay SHOULD converge on the same final
  execution fingerprint when model and capability versions match.

## 5.6 Event-log vocabulary

The unified event log gains records in these classes:

| Event | Required evidence |
| --- | --- |
| `signal_transition` | program, node, old/new value or digest, coordinate, cause source |
| `signal_sample` | node, source chunk/sample identity, coordinate, value/digest |
| `signal_state_transition` | node, old/new state, triggering input/opportunity |
| `binding_activation` | binding, targets, mapped parameters, coordinate |
| `binding_deactivation` | binding, targets, reason, coordinate |
| `fault_opportunity` | opportunity ID, domain, target, operation, phase |
| `fault_choice` | binding, opportunity, probability/candidate set, keyed result |
| `effect_combined` | target, phase, contributors, combined effect digest |
| `effect_applied` | adapter, effect, resolved target, application evidence |
| `effect_committed` | binding, target, atomic commit outcome, canonical application evidence |
| `effect_rejected` | capability/precondition/application error |
| `network_profile` | segment/path, directional components, profile digest |
| `association_transition` | old/new attachment/path, timers, frame treatment |
| `trace_alignment` | expected/observed source operation and match rule |

Full values need not be repeated on every event when a content-addressed profile
or signal value is already retained. The log remains sufficient to explain a
failure without reverse-engineering an opaque total delay or error code.

- **[REP-17]** Event-log ordering MUST follow the scheduler's canonical event
  order and adapter phase order.
- **[REP-18]** Sampling observability MUST be configurable to avoid logging every
  unchanged high-rate signal, but every transition and applied effect MUST remain
  explainable from retained artifacts and state.
- **[REP-19]** Human diagnostics MAY summarize; JSON/JSONL records MUST use stable
  typed fields and semantic versions.

## 5.7 Checkpoints and time travel

A checkpoint retains:

- normalized trace manifests and reachable chunk references;
- source cursors and last sample coordinates;
- stateful signal-node state;
- active binding contributions and transition sequences;
- adapter state such as queues, routes, associations, service tokens, wear,
  thermal, battery, and calibration;
- resolved-effect replay cursor;
- search overrides and branch provenance;
- fingerprints covering all above state.

The debugger should answer:

- Which physical/recorded signal caused this effect?
- Which binding and transfer function mapped it?
- Which opportunity did it affect?
- Which other targets share the same cause?
- What would the profile/effect have been immediately before and after?
- Was the outcome computed or locked?

- **[REP-20]** Reverse execution across a signal or binding transition MUST
  restore an earlier checkpoint and replay; debugger inspection MUST NOT mutate
  canonical signal state.
- **[REP-21]** A debugger edit to a signal, mapping, trace, or resolved outcome
  MUST fork a non-canonical branch with new scenario/schedule provenance.

## 5.8 Calibration

Calibration compares normalized observations with model predictions without
changing canonical execution during a run. A calibration job declares:

- source trace channels;
- model outputs to compare;
- exact error metrics or bucketed summaries;
- bounded parameter candidates or an off-run external fitting process;
- resulting lookup table/mapping artifact;
- training/validation split and provenance.

An externally fitted model becomes canonical only after export as exact lookup,
piecewise, field, or parameter artifacts. The fitting algorithm itself need not
be part of the runtime determinism contract, but its outputs and provenance are
content-addressed.

- **[REP-22]** A calibrated artifact MUST record source datasets, fitting tool
  identity, selected parameters, validation metrics, and canonical export
  version.
- **[REP-23]** Calibration MUST NOT rewrite an existing signal-program content
  address. Applying a new calibration creates a new scenario identity.

## 5.9 Capture and import tooling

Import tooling should support staged adapters for:

- packet captures and per-packet outcomes;
- interface counters, queue telemetry, route/association logs;
- modem radio metrics and cellular handoff logs;
- Wi-Fi scan/association/rate telemetry;
- GNSS/IMU/movement traces;
- satellite contact/weather/range/beam traces;
- disk latency/error/SMART/NVMe telemetry;
- sensor samples and calibration metadata;
- power quality, battery, thermal, fan, vibration, and environmental telemetry.

Importers run as hermetically built AOS tools in CI/reproducible pipelines. They
may ingest external files supplied by the user, but do not depend on undeclared
host parsers or vendor binaries.

- **[REP-24]** Every importer MUST provide malformed-input, unit, boundary,
  chunking, deterministic-output, and golden-vector tests.
- **[REP-25]** Proprietary formats that require unavailable vendor tools MUST be
  converted outside canonical execution, then imported through a documented
  open normalized interchange format with retained provenance.

## 5.10 Privacy, security, and resource limits

Movement, radio, device, and datacenter traces may be sensitive. The store and
artifact exporter must support:

- location redaction;
- stable device aliases;
- payload stripping while retaining packet metadata/digests;
- channel allowlists;
- encryption/access policy outside the canonical plaintext object format;
- provenance indicating transformations;
- export closure inspection.

Trace processing also needs admission limits: artifact bytes, channels, samples,
events per coordinate, string sizes, state bytes, graph nodes, window lengths,
and decompression ratios.

- **[REP-26]** Scenario and artifact admission MUST enforce configured resource
  bounds before allocating unbounded state or beginning a run.
- **[REP-27]** Artifact export MUST list source/provenance dependencies so an
  operator can detect sensitive raw or normalized traces in the closure.
- **[REP-28]** Redaction and encryption policy MUST NOT be confused with model
  identity: the canonical normalized plaintext digest remains the semantic
  identity, while storage protection is an orthogonal envelope.

## 5.11 Testing gates

Required test classes are:

1. canonical importer golden vectors;
2. evaluator vectors for interpolation, mapping, state, and keyed choices;
3. raw-to-normalized repeatability;
4. uninterrupted versus checkpoint/resume equivalence;
5. recomputed versus locked replay equivalence;
6. mismatch fail-loud tests;
7. chunk-boundary and missing-data tests;
8. cross-domain shared-cause correlation tests;
9. time-travel across transitions;
10. resource-limit and malformed-artifact tests.

- **[REP-29]** No importer or adapter is production-capable until all applicable
  gate classes above are green under adversarial boundary fixtures.
