# Native observed execution integration

The daemon owns the executable RFC-0025 path in `node_scenario` and
`node_observed_executor`. Its scenario payload family is 25; legacy scenario,
QEMU assignment, observation, and ThinReplay bytes retain their existing
schemas. A separate observed execution nonce identifies an actual attempt;
the planned scenario/configuration and complete owner roster identify the
requested realization. Neither identity authorizes reconstruction of an old
execution or deterministic reuse of nondeterministic results.

## Installed factories and admission

`InstalledNodeCatalog` supports the owned exact virtual clock, a fault-free
exact byte-preserving link, and the actual source-built reference-device child. Each node selects its implementation
independently. The catalog regenerates the complete immutable descriptors,
ownership/capture inventory, schema set, clock policies, and requirements from
its installed profiles, then requires exact submitted bytes. It measures the
running host executable and independently checks the operator-selected expected
child executable. Only actually owned, parked native instances receive live
incarnation authority. Full production graph admission authenticates those
instances; caller-supplied qualification references do not establish authority.

`NodeObservationService::compile` runs on the owning daemon actor. A remote
client must use this method because a scenario generated in a different client
executable would bind the wrong host implementation artifact. Node-scenario
content uses bounded CNP/1 base64url bytes. Scenario/configuration parsers reject
unknown fields and editions, duplicate JSON keys, changed content references,
and excessive bytes or roster sizes.

The clock uses the installed exact 1 ps contract and its independently signed
complete runtime-envelope archive supports durable cold restoration. The
original output-only reference profile has permanently closed ingress: its
exclusive native adapter accepts only an authenticated empty original cut.
The distinct `ReferenceNativeLinked` profile exposes a shared opaque-octet
interface and can select closed-source or input-consuming native checksum
windows. Both reference profiles retain unsupported exact continuation and
explicitly accepted physical nondeterminism. Any coupled world containing one
of these native devices therefore produces a tainted observed attempt.

A connected reference producer → exact host link → reference consumer is an
executable installed graph. The link forwards the producer's original checksum
JSON octets without interpretation; the consumer checksums those same octets.
The first connection preserves the actual quantized publication coordinate and
the second samples input at the consumer's declared boundary. Positive native
link latency, original staged input ACKs, finite connection credits and native
future bounds prevent the consumer from outrunning potential input. Quantized
outputs retain original consumed-input causal parents without inventing an
instruction-level evaluation timestamp. Connection FIFO, credit and custody
domains belong to actual endpoint owners and enumerate every execution writer.

Connected transfer state and reference native state have no installed durable
archive. The observed factory also refuses authored external ingress, faults,
QEMU, gem5, KVM and fork until their independent native qualifications are
installed. Unsupported selections and policies fail closed; provider names or
proof labels do not create capabilities.

## Original execution and custody

Preparation reserves a finite whole-world retirement slot before native
allocation. The worker authenticates exact planned-artifact/graph correspondence
and durably reserves its nonce before activation. The activation publisher
stores the complete original owner roster and generation in immutable CAS and
a write-once `node-world-activations/` ref. Unknown publication cannot authorize
execution. Every round uses the original retained causal scheduler, staged input
ACK, opaque runtime grant and native operation token.

The executor retrieves immutable native proof bodies from the original completed
operations and durably copies them to CAS before output ACK. Actual ingress,
outputs, native receipts and payload bytes become independently authenticated
result provenance. Their aggregate in-memory encoding is bounded to 16 MiB.
Repeated publication uses the original result; a stored nonce never launches a
new native world. Read/retry authentication compares exact retained realization
and input identities without manufacturing native authority.

The owning actor stays on its original thread after submission handles are
dropped. It contains every original world, transfers complete unresolved native,
input, operation and scheduler custody into the pre-reserved retirement queue,
and polls authentic reclamation with a bounded timer. Native callback unwinds
retain the original execution permit and enter monotonic quarantine. A failing
GC fence stops admission while cleanup continues. Poisoned root inventory fails
closed. `NodeObservationRetention` is an independent cloneable GC owner; register
it before admission and retain it until `is_retired()` confirms every world was
reclaimed. Cleanup-only root records count against finite admission capacity.

## Local verification

Build the actual child using the source-built AOS toolchain on this machine:

```sh
NIX_CONFIG='builders = ' bash tools/dev/aos-dev cargo build \
  --manifest-path crates/Cargo.toml -p crucible-node-provider \
  --bin crucible-reference-device --locked
```

Run actual native mixed-world and actor containment tests:

```sh
CRUCIBLE_REFERENCE_DEVICE="$PWD/crates/target/debug/crucible-reference-device" \
NIX_CONFIG='builders = ' bash tools/dev/aos-dev cargo test \
  --manifest-path crates/Cargo.toml -p crucible-daemon --lib --locked \
  node_observed_executor::tests -- --include-ignored --nocapture
```

These tests use durable directory CAS/ref backends, real production admission,
an actual owned virtual clock, and a real guarded child process. They verify
mixed-world taint, completed provenance, unchanged nonce retries, changed-input
refusal, and owning-actor cleanup after command-channel disconnection. Campaign
worker tests separately exercise transaction and callback-unwind semantics with
explicit host test doubles; they do not qualify native execution or clocks.

Local functional verification passed six daemon tests, including the actual
connected producer/link/consumer path, six immutable-profile tests, and fourteen
observed-worker transaction tests. The connected native test verifies original
bytes and checksum, quantized input-parent provenance, finite-credit progress,
unchanged retries and complete mixed-world nondeterministic classification. Native evidence tests verify every copied receipt's exact
content hash after complete original-world reclamation. The profile tests also
verify that the actor's closed profile advertises no CNP endpoint or resume
extension; the separately launched public reference provider retains those
capabilities. These focused development tests do not replace the production
build, complete test-target compilation, process ABI/license gates, or complete
vendor conformance qualification.
