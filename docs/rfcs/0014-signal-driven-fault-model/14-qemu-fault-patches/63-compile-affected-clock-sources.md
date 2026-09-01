# Patch 0112: compile only affected clock sources

Patch `0112-crucible-compile-affected-clock-sources.patch` binds post-commit
clock compilation to the exact rule changed by the node-fault transaction.

## Problem

The original rule-change callback recompiled every registered clock source.
At a stopped control boundary, an unrelated device source can legitimately
lack a projectable raw value. Its failure then rejected an otherwise valid,
already-committed transition for a different source.

## Contract

A clock-transform rule selects sources with the existing target predicate. A
clock-source-state rule selects only identities carried in its typed source
hash set. Other rule kinds and unselected sources perform no compilation or
timer rearm.

The selected source retains the existing all-or-terminal compilation path. The
production live hardware gate proves one degraded local-APIC source transition
and its timer rearm while unrelated sources remain registered.

## Compatibility

The patch changes no shared-memory field, VMState payload, QEMU plugin API, or
capability identity. It narrows internal work to the source owned by the
authenticated transaction.
