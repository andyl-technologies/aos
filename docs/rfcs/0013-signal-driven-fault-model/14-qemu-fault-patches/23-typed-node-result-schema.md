# Patch 0072 — `crucible-typed-node-result-schema`

Patch `0072` preserves the fixed node-command result schema when an immediate
typed impulse also emits command-specific occurrence evidence. The command
result and occurrence event are separate protocol records with separate
consumers; one must never replace the other.

## Protocol invariant

Every successful immediate node impulse produces both:

1. one `NodeFaultEvidenceV1` command result, authenticated by the result header,
   containing the exact request identity and before/after state hashes; and
2. one typed occurrence event, authenticated by the event header, whose payload
   contains the command-specific architectural evidence.

The result ring is the two-phase transaction acknowledgement. The event ring is
the causal record of what the mutation did. Their payload schemas, sequence
spaces, evidence hashes, retention rules, and validation paths remain distinct.
QEMU must not place a lifecycle, clock, interrupt, hardware-error, or other
command-specific event payload in the result ring.

The host retains the authenticated APPLY command sequence and result
before/after hashes beside the issued action in its canonical continuation. An
occurrence is admissible only when its `rule_command_sequence` names that exact
APPLY result and its command kind matches the issued effect. Immediate impulses
must additionally carry the same before/after hashes on both channels. The host
then applies exhaustive command-specific decoding to the occurrence payload;
there is no accepted unknown-kind or unvalidated typed-payload branch.

## QEMU change

After an immediate impulse executes, `plugins/crucible-fault-node.c` first
enqueues the command-specific occurrence evidence. It then re-encodes the
canonical fixed node result from the committed staging record and hashes those
exact bytes into the result header. The before/after hashes are the values
produced by the mutation, not the prepare-only prediction.

Deferred impulses retain their dedicated deferred status and completion path;
this patch does not misreport a deferred transition as synchronously applied.
The result bridge publishes the final typed result only after QEMU completes or
fails the deferred mutation, and the host validates that terminal result before
committing its binding state.

## Required proofs

- The per-patch microtest proves the impulse payload replacement was removed and
  the canonical result encoder and result digest remain present.
- Patch regeneration proves exact diff bytes, commit/tree identities, DCO, and
  the tracked corresponding-source bundle.
- A live production node impulse proves the host independently validates the
  fixed command result and command-specific occurrence event.
- A separate real-QEMU transaction retains the authentic result and occurrence
  records. The gate corrupts only a host-side copy of each record in turn and
  requires the production result or event decoder to reject that copy while
  the untouched other channel still validates. No fake QEMU, synthesized
  success record, or alternate decoder participates in this proof.
- The result half invokes the same production validator used by transaction
  commit. It authenticates the evidence bytes and status, decodes the original
  request, and requires exact command kind, operation, target kind, model phase,
  generation, action hash, target hash, schema hash, request SHA-256, and
  before/after hash agreement. The gate has no reduced result validator.
- The same derivation builds the tracked QEMU patch prefix ending at `0071`,
  builds the Rust plugin against that exact prefix identity, and runs the live
  transaction. It must fail while decoding the command result and must never
  print `PASS`; this proves that removing only `0072` is detected before an
  occurrence can be classified as committed.
  This prefix build is compatibility-test-only and explicitly non-distributable;
  it carries no false full-series corresponding-source claim. Its machine-readable
  release policy marks it as an internal component, disables standalone release,
  gives it no release route, and declares it non-publishable. Because no matching
  prefix corresponding-source artifact exists, closure publication fails closed.

The patch changes only QEMU/GPL-side code and uses the existing versioned
shared-memory result and event protocols. It adds no pointer, callback, native
layout, or implementation object to the process boundary.
