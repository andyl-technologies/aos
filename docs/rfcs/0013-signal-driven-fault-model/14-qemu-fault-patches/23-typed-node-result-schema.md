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
- Corrupting either channel fails closed even if the other channel remains
  valid.
- Reverting only this patch makes the live typed-impulse gate fail at command
  result decoding before it can classify the occurrence as committed.

The patch changes only QEMU/GPL-side code and uses the existing versioned
shared-memory result and event protocols. It adds no pointer, callback, native
layout, or implementation object to the process boundary.
