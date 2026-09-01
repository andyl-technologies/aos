# Patch 0113: restore accelerator rule indexes

Patch `0113-crucible-restore-accelerator-rule-indexes.patch` reconstructs the
accelerator's private persistent-rule indexes during fresh-process VMState
restore.

## Problem

The node-fault VMState already restores the authenticated persistent rule
ledger. Accelerator VMState restored device memory, counters, and armed result
impulses, but its lifecycle, result, memory, and service lookup arrays remained
the empty cold-start arrays. A service rule installed before a checkpoint was
therefore absent when the restored guest submitted its first job.

## Contract

During VMState preparation, the accelerator visits the staged node ledger and
retains sorted references for each of its four command kinds. Accelerator
commit atomically swaps those arrays with the live indexes alongside the
device state. Preparation failure or transaction abort releases every retained
reference without changing the live accelerator.

The production live hardware gate installs half-capacity thermal/power policy,
captures the armed state, destroys QEMU and its plugin, restores into a fresh
process, and requires exact service evidence for all three guest jobs.

## Compatibility

No rule is serialized twice, and no VMState or shared-memory bytes change. The
new indexes are derived ownership over the already-versioned node-rule ledger,
so the existing accelerator VMState version remains authoritative.
