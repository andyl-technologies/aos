# Patch 0075 - `crucible-authenticated-event-request-envelope`

Patch `0075` makes QEMU occurrence events independently verifiable after a
checkpoint is restored into a fresh plugin process. It also closes the
accelerator one-shot identity gap left by patch `0074`: a result transform is
selected by the exact opportunity-chosen job sequence, and its event carries
the original opportunity identity rather than a digest invented at completion.

## Mandatory event envelope

Every QEMU node occurrence payload uses event-envelope version 1. There is no
raw-evidence compatibility path. The GPL plugin refuses to initialize unless
QEMU exports the matching envelope-version function, and it rejects a missing,
unknown, truncated, oversized, or trailing envelope before publishing anything
to the public event ring.

The bounded envelope contains:

| Field | Purpose |
| --- | --- |
| Magic, version, and reserved bytes | Closed schema selection and fail-closed evolution |
| Request and evidence lengths | Checked slicing within the hard payload limits |
| SHA-256 of the request and evidence | Detects corruption before either object is decoded |
| Binding hash and rule command sequence | Reconnects the occurrence to the committed transaction |
| Target-node hash | Prevents a restored event from crossing node identity |
| Expected opportunity hash | Authenticates the opportunity selected by an APPLY action |
| Original `NodeFaultPayloadV1` request | Reconstructs all command-specific validation state |
| Raw command-specific evidence | Describes the real QEMU mutation or lifecycle event |

QEMU creates the envelope before queuing the event and checkpoints the complete
envelope. Restore validates its hashes, lengths, request identity, event
identity, target, and command schema before staging it. The plugin repeats those
checks after polling. It reconstructs register, instruction, exception, memory
ECC, clock, and accelerator expectations from the embedded request; no
process-local map and no synthetic default can substitute for restored state.
Only the raw evidence is copied onward into the public shared-memory event
payload, so no QEMU-private structure or native pointer crosses the licensing
boundary.

Clock impulse evidence also records the pre-mutation additive offset. The
public typed decoder rejects an offset or jump unless checked arithmetic proves
that the old additive value plus the requested signed mutation equals the new
value (and proves that a drift-only impulse leaves it unchanged). Transaction
acceptance is logged as `effect_committed`; only this validated QEMU occurrence
is logged as `effect_applied`.

The largest internal envelope is exactly two hard payload limits plus its fixed
header. Both QEMU and the plugin perform checked arithmetic before allocating.
Event admission still reserves bounded queue capacity before mutation, and an
allocation or validation failure enters the existing authenticated terminal
path instead of dropping evidence.

The plugin acknowledges a tokenized control pump only after both its result and
occurrence queues drain. The host may consume occurrence records to release
that fence, but those records remain scheduler-owned staged state and use the
plan's remaining aggregate `event_records` allowance. Multi-node control work
freezes non-target staging and transfers the one remaining allowance to each
target in canonical node order. Before taking driver-staged ownership or
dequeueing the public ring, the host admits the complete aggregate count and
fallibly reserves its canonical destination; refusal therefore leaves the event
owned and the control token outstanding for a typed retry. Fresh restore
authenticates identity and rejects pre-existing live event ownership before it
installs that policy, then rejects any event published by its first
control-boundary fingerprint. Exact checkpoint capture rejects staged or
ring-owned occurrences both before quiescence and after the quiescing control
pump; no such ownership is omitted from a durable snapshot.

## Exact accelerator completion identity

An `accelerator.result_transform` payload adds two required typed fields: the
selected job sequence and its immutable job digest. These fields come from the
`AcceleratorJob` opportunity retained in `BindingActionCause`; an accelerator
result action without that typed opportunity is rejected before submission.
The digest is BLAKE3 over
`crucible_shmem::canonical_accelerator_job_material`, which includes the class,
job kind, queue, deterministic service demand, output-capacity contract, and
input bytes. It excludes process generation, transport sequence, and device
identity because the opportunity and resolved target bind those independently.

QEMU admits only a nonzero opportunity identity for the APPLY operation. At
completion it first requires the exact sequence, then applies the authored job
kind, queue, and occurrence selector. A nonmatching sequence cannot consume the
one-shot or advance its occurrence policy. On the exact match, the event uses
the command's checkpointed opportunity hash. The plugin verifies that hash
against the envelope and verifies the evidence sequence against the request.
Consequently, changing the modeled job digest changes the opportunity identity
and can no longer be silently accepted as evidence for another job.

The expected opportunity hash is part of rule digests, rule copies, and node
VMState. Accelerator VMState retains its existing bounded one-shot entry, which
references the fully restored rule. Restore is atomic: a corrupt request,
opportunity, sequence, digest, reservation, or event envelope rejects the whole
section before live state changes.

## Required proofs

- A raw pre-envelope event is rejected; there is no legacy fallback.
- Corrupting either digest, either length, any identity field, the target node,
  the request, the evidence, or reserved bytes rejects the event.
- A plugin process with empty local correlation maps can consume a QEMU-restored
  event and reconstruct its exact typed expectation from the envelope.
- A different job sequence does not consume an armed accelerator one-shot; the
  selected sequence mutates exactly once; a later matching-class job is
  unchanged.
- Changing the expected opportunity hash or job digest makes validation fail.
- Arm, checkpoint, terminate the plugin process, restore under a fresh plugin,
  and complete produces the same authenticated occurrence as uninterrupted
  execution.
- Corrupting the restored rule or queued envelope fails restore atomically.
- Terminal cleanup releases an unconsumed one-shot without manufacturing an
  occurrence.
- Both x86_64 and AArch64 TCG builds compile the API and event consumers; live
  behavior runs on each architecture supported by the gate environment.
- Removing patch `0075` makes the envelope-version, fresh-restore, and exact-job
  negative controls fail.
- Patch regeneration verifies the deterministic commit and tree, DCO sign-off,
  catalog row, and thin corresponding-source bundle.

This patch changes only QEMU and QEMU-plugin GPL-side files. The public
fixed-width command/result/event and shared-memory layouts are unchanged; the
envelope is an internal QEMU-to-plugin byte protocol that the plugin validates
before producing the existing public event representation.
