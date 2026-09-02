# Recorded signal inputs

Crucible can drive faults from CSV, JSON Lines, classic PCAP, and PCAPNG
captures. Raw files are imported before execution into canonical,
content-addressed manifests and chunks. Runtime evaluation reads only those
normalized objects; it never reparses a host file during replay.

Trace import is currently a public Rust API, not a `crucible` CLI subcommand.

## Import pipeline

```text
raw bytes
  -> import_signal_trace(format, bytes, options)
  -> manifest + canonical chunks
  -> store_imported_signal_trace(DagStore, raw bytes, imported trace)
  -> manifest content hash
  -> SignalSourceSpecification::Trace
  -> ProductionVmLifecycleConfig::with_signal_artifacts
```

The store operation persists and verifies the raw provenance object, every
chunk, and the manifest. `load_stored_signal_trace` revalidates the entire
dependency closure before returning it.

## Required import options

`TraceImportOptions` makes every normalization choice identity-bearing:

| Field | Purpose |
|---|---|
| `channel` | Stable output channel ID. |
| `shape` | Exact value type, unit, and decimal scale. |
| `event_channel` | Permits equal coordinates only when stable event sequences distinguish them. |
| `time_basis` | `Nanoseconds`, `DeviceTicks`, or `Sequence`; packet captures require nanoseconds. |
| `time_mapping` | One or more adjacent integer affine mappings from source coordinates to virtual nanoseconds. |
| `source_alias` | Stable device/capture identity without relying on a host filename. |
| `privacy_policy` | Content hash of the policy under which the capture is admitted. |
| `coordinate_frame` | Optional frame for spatial vector channels. |
| `redaction` | Optional deterministic spatial transform; valid only for millimetre vector channels. |

Time mappings use checked integer arithmetic, positive numerator and
denominator, and an explicit rounding rule. Multiple segments must be adjacent,
non-overlapping, and cover their declared interval without gaps. This prevents
locale, floating-point, host-clock, and implicit interpolation choices from
changing identity.

## CSV contract

CSV is UTF-8 with exactly this header and column order:

```csv
coordinate,event_sequence,value,validity
1,,7,valid
2,,8,valid
```

- `coordinate` is a canonical unsigned integer: no sign, fraction, exponent,
  or unnecessary leading zero.
- `event_sequence` is empty for ordinary sampled channels and a canonical
  unsigned integer for event channels.
- `value` is parsed according to the declared `SignalValueType`.
- `validity` is one of `valid`, `invalid_quality`, `missing`, or
  `discontinuity`.

CSV scalar values support Boolean, signed/unsigned integer, duration, rate,
probability-millionths, exact ratio, enum, event text, and lowercase hexadecimal
bytes. Use JSON Lines for vector values or structured event payloads.

## JSON Lines contract

Each nonempty UTF-8 line is one object. Unknown fields, floating-point numbers,
and missing required fields are rejected.

```json
{"coordinate":1,"value":7}
{"coordinate":2,"value":8,"validity":"valid"}
```

Required fields are `coordinate` and `value`. Optional fields are
`event_sequence` and `validity`; omitted validity means `valid`. Values are
checked against the declared shape. Structured event payloads are converted to
canonical JSON with sorted object keys, and only integer JSON numbers are
accepted.

## PCAP and PCAPNG contract

Packet captures import as event channels whose value type is an event schema.
The complete captured packet bytes become the event payload and same-time
packets receive stable sequence numbers in capture order.

- The import time basis must be `Nanoseconds`.
- The declared shape must be an event type and `event_channel` must be true.
- Classic PCAP endianness and microsecond/nanosecond variants are normalized.
- PCAPNG interface timestamp resolution is honored per interface.
- Truncated, ambiguous, unsupported, or out-of-bounds records are rejected.

Importing packet bytes does not itself align them to a guest frame opportunity.
Any effect that relies on capture-to-frame alignment must declare an
unambiguous alignment contract; missing or ambiguous alignment fails admission.

## Value quality, interpolation, and boundaries

The manifest retains validity at every point. The trace source separately
declares interpolation and behavior before/after available samples or across
missing data. Choose these policies as part of the scenario rather than
silently filling gaps in a preprocessing script.

Use event channels for impulses and ordinary channels for sampled values. Equal
coordinates are invalid for an ordinary channel; for an event channel they
must carry stable, ordered event sequences.

## Provenance, privacy, and redaction

The normalized manifest records:

- the raw-content hash;
- importer identity and semantic version;
- a hash of all import options;
- the stable source alias;
- the privacy-policy hash; and
- any coordinate frame and redaction transform.

The raw bytes are stored by `store_imported_signal_trace`, so an exact artifact
closure can prove which capture produced the normalized objects. If policy does
not permit retaining raw data, do not call this helper and invent an omission:
constructing alternative provenance is a separate API workflow whose omission
reason and policy must still validate.

Redaction is deterministic and identity-bearing. Applying it after import would
produce different runtime bytes without changing the recorded options, so the
importer only supports the declared spatial transform during normalization.

## Supplying artifacts to execution

For a direct lifecycle integration, retain the `Arc<dyn DagStore>` used during
import and attach it:

```rust
let config = ProductionVmLifecycleConfig::new(
    qemu,
    plugin,
    kernel,
    root_image,
    run_state_root,
)
.with_signal_artifacts(trace_store);
```

The signal source references the manifest content hash and channel ID. At
startup the runtime authenticates the manifest and all referenced chunks,
checks shape and channel agreement, and enforces resource limits. Exact
checkpoints copy transitively referenced signal objects into their execution
closure.

The packaged CLI has no command that turns a raw capture path into canonical
objects. Its local `search` path attaches the selected `--store` for signal
materialization, and reproduction artifacts can carry signal objects into
replay. Ordinary packaged `run` and `verify` do not currently attach `--store`
as the lifecycle's signal-artifact store. Use the direct Rust lifecycle for a
new trace-driven run, or a supported search/replay artifact path; do not assume
that a manifest placed in `--store` is automatically available to every
command.

## Search and replay

Ordinary replay reevaluates the admitted normalized trace. Search may only
mutate trace windows and mapping points declared by its bounded search material;
the chosen replacements become part of the schedule/evidence. Locked-effect
replay can instead validate a previously resolved effect trace without
rerunning signal search.

On a mismatch, compare raw provenance, import options hash, manifest hash,
channel/shape, mapped coordinate, validity/interpolation result, and selected
effect opportunity in that order.
