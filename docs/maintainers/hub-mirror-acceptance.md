# Managed mirror producer acceptance

Managed R2 mirror execution has a separate acceptance purpose from direct
uploads. The upstream range reader, none/zstd NAR verifier, durable mirror
journals, final-key reservation, Native acknowledgement archive and private
stage cleanup require their own actual measurements. Direct SDK qualification
does not cover these producer operations.

The public contract is `aos_hub_core::mirror_acceptance`. The Worker checks
`MirrorAcceptanceArtifact` before a production effect, after independently
loading direct acceptance and resolving the actual full managed profile.
Missing acceptance, an unfamiliar purpose, a different build or profile,
expired evidence and controlled evidence refuse new production dispatch.
Retained unknown physical effects remain held independently of acceptance.
The verified review cutoff is retained and checked again in the final provider
callback after buffer or request-capacity waits. A wait cannot renew it.

## Reviewer authority and installation

The signature domain is
`aos.hub.accepted-managed-mirror-producer.v1`, with a terminating zero byte.
The version and `managed_r2_mirror_v1` purpose are signed together with every
identity and evidence field. A direct-upload signature cannot verify in this
domain, even when both reviewer roles are authorized to use the same key.

`HUB_MIRROR_QUALIFICATION_PUBLIC_KEY` installs the trusted mirror reviewer
public key. This is a review role, not a provider token or a provider mutation
key. Existing reviewer custody can serve both purposes when policy explicitly
authorizes both reviews; a second permanent cloud key is not required.

`HUB_MIRROR_ACCEPTANCE` holds the accepted JSON document in a separate KV
binding. `mirror_acceptance_key(deployment, source, script)` derives its exact
address. Installation does not replace the measured script. The signature
binds the actual compiled source, script version, deployment and HTTPS origin,
workers-rs version, complete actual managed profile and prerequisite direct
evidence commitment. Changing any of these requires a new review.

## Actual evidence and release pack

Structural validation checks a submitted report's consistency and bounds. It
cannot establish that measurements occurred. Before signing, the reviewer
must inspect the retained raw transcripts, actual provider and Native SQL
observations, failed attempts and source-built release provenance identified
by the evidence digests.

Hosted acceptance requires:

- Three positively acknowledged large objects at the 2 GiB admitted ceiling,
  with positively verified encoded and uncompressed representations covering
  that ceiling, plus at least 1,000 independent metadata objects.
- Bounded full-original examples for none, zstd and metadata, their retained
  stage and final incarnations, the exact Native commit digest and independent
  final byte readback. Example records are a sample of the complete workload;
  the workload report retains the complete population.
- Actual observations for every closed safety case: unknown create, part,
  close, promotion and cleanup; positive prefix replay; lost Native and archived
  acknowledgement; persistent restart; changed binding and source; Native
  revocation; expired plans; private namespace refusal; metadata during bulk.
  Time, HEAD and absence settle no unknown operation.
- Actual provider concurrency including upstream fetches at the accepted
  ceiling, metadata completion during bulk, bounded captured Native controls
  and zero bulk object bytes through Native. Retain actual whole-invocation CPU
  and wall measurements, correlated to the installed CPU limit readback and
  the finite ten-minute immutable-read deadline.
- Actual whole Worker peak memory below 128 MiB. The measurement includes
  Wasm heap, Rust vectors, JavaScript and SDK copies, decoder allocation and
  pending requests. Measuring just a payload or a VM's available memory is
  insufficient. The implementation admits one bulk buffered producer and two
  separately reserved metadata producers per isolate. Each bulk part and
  decoder window is at most 8 MiB; metadata encoded/plain bytes and decoder
  windows are each at most 256 KiB. Decoded blocks are at most 128 KiB and
  native reader views at most 64 KiB. Measure both metadata producers while a
  bulk verifier is active, including all SDK copies. Four parts in one control
  do not authorize four retained bulk part buffers.
- A complete source-built ordinary release pack with exact installed Wasm,
  JavaScript and compressed script hashes, actual sizes and cold startup
  samples. The schema enforces the 64 MiB uncompressed script and one-second
  startup ceilings. The installed account's applicable compressed upload limit
  remains an additional release gate.

Counters and digests supplied by an operator are review candidates, not
acceptance. No supported-capability flag or configured zero violation count
can replace actual observed measurements.

## Controlled candidate execution

A controlled none/zstd roundtrip is useful evidence for implementation review.
It cannot qualify hosted R2 or grant normal mirror admission. Its raw profile
commitment uses `mirror_candidate_profile_digest`, a separate domain over the
actual protected managed descriptor, private policy and fixed buffer geometry.
It contains no accepted `DirectRuntimeQualification` wrapper.

The candidate executor must use a separate protected control purpose, fresh
Native fixture SQL originals and the closed
`.aos-mirror-qualification/<run>/final` destination prefix. It runs the same
physical journal, verification and publication code against that isolated
namespace. Candidate controls must never be a fallback when production
acceptance is absent. A controlled evidence document retains raw profile facts
and a source-derived `emulated-<digest>` script identity; it cannot carry a
production accepted profile or prerequisite direct evidence as though those
had been measured. `require_production` always rejects it, including when it
has a valid reviewer signature.

The initial controlled gate should positively execute metadata, none and zstd
roundtrips with actual provider readback and durable Native acknowledgement,
then inject lost acknowledgements, an unknown provider mutation and runtime
restart. Preserve every raw attempt. Larger workloads and actual hosted
memory, startup, throughput and provider contract qualification are separate
remaining launch gates.
