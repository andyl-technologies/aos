# Patch 0074 - `crucible-accelerator-result-opportunity`

Patch `0074` implements the one-shot lifecycle required by
`accelerator.result_transform`: an APPLY command arms a future matching device
completion atomically, while evidence is emitted only when that real completion
is mutated.

## Transaction and occurrence semantics

At the authorized node boundary, QEMU validates the complete selector and
mutation, copies the immutable typed rule, reserves exactly one event slot, and
returns the ordinary typed `applied` command result. That result means "armed";
it does not claim that a device occurrence has happened. The result's
before/after hashes are equal because arming changes no guest-visible result.

The host retains the APPLY command correlation after accepting that result. At
accelerator completion, QEMU evaluates the selector and occurrence policy. A
non-match leaves the one-shot armed. The first match joins retained result rules
in canonical `(binding_hash, action_hash, command_sequence)` order, mutates the
real device output before virtqueue completion, consumes the reserved event
slot, publishes authenticated typed occurrence evidence, and destroys the
one-shot. The host releases the correlation only after validating that event.

There is no deferred command result and no callback wait: waiting for a future
job inside command commit would deadlock guest progress. There is also no
synthetic occurrence, timer substitute, or test-double completion path.

## VMState and terminal behavior

Accelerator VMState version 4 serializes a bounded, strictly ordered list of
armed one-shots. Each entry contains its full typed rule and occurrence
counters, command icount, pre-arm state hash, and remaining event reservation.
Restore revalidates the command kind, APPLY operation, target, selector,
mutation, order, bounds, and reservation count before atomically installing the
staged list. Armed entries count toward the aggregate reserved-event invariant,
but not the deferred-command invariant because their command result is already
terminal.

Entering terminal fault state cancels all unobserved one-shots and releases
their reservations. Terminal evidence explains the run failure; QEMU never
manufactures occurrence evidence for a job that did not complete. Reset and
device reconnect preserve armed rules so the original selector determines the
first eligible post-transition completion. A restored terminal state must have
no armed entries.

Patch `0074` also closes the typed-result contract for genuinely deferred node
impulses: their eventual success or failure result carries the same canonical
`NodeFaultEvidenceV1` payload and evidence digest as an immediate result.

## Required proofs

- A live guest TPU job receives the exact transformed output and the host
  validates the later occurrence against the earlier APPLY result.
- A nonmatching job leaves the one-shot armed; the first matching job consumes
  it; a second matching job is unchanged.
- A checkpoint taken after arming but before completion restores the reservation
  and produces byte-identical output and evidence on replay.
- Corrupting the restored rule, order, selector, reservation count, or VMState
  version fails restore before state commit.
- Terminal entry clears every armed reservation without emitting a false
  occurrence.
- A real deferred node mutation produces a canonical typed terminal result on
  both success and failure.
- Removing patch `0074` makes the live accelerator and deferred-result gates
  fail, while machines without the co-sim accelerator remain inert.
- Patch regeneration verifies its commit, tree, sole DCO sign-off, catalog row,
  and thin corresponding-source bundle.

The patch changes only QEMU/GPL-side code and the loaded GPL-side plugin. It
uses the existing versioned command/result/event protocols and introduces no
native layout, pointer, callback table, or QEMU-private object across the
process boundary.
