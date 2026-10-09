# Crucible node contract implementation studies

These documents describe how the existing implementation could reach the target
defined by [RFC-0025: Crucible Simulation Node Contract](../../rfcs/0025-crucible-node-contract/README.md).
They are nonnormative engineering plans, not an implementation, an interoperability
specification, or evidence that a backend has been qualified.

The source audit was performed on 2026-10-07 against commit
`1037fd8490479ad8eeef9349dd1043bb799fc405`. Source paths and line numbers in these
documents refer to that revision. They may move during implementation. Requirement
identifiers refer to RFC-0025; the RFC controls if these plans disagree with it.

## Reading order

| Document | Purpose |
| --- | --- |
| [Current state](current-state.md) | Audited abstractions, ownership, hardcoded assumptions, dependency directions, and target gaps |
| [Refactoring plan](refactoring-plan.md) | Extraction and renaming boundaries, compatibility classifications, and implementation constraints |
| [Phased implementation](phased-implementation.md) | Dependency-ordered tasks, deliverables, exit criteria, risks, and rollback points |
| [Qualification plan](qualification-plan.md) | Existing regression coverage, new behavioral qualification, performance methodology, and requirement traceability |
| [Implementation status](implementation-status.md) | Tested implementation stages, active integration work, and native qualification gaps |

## Scope and engineering posture

The public integration surface is a simulation-node contract. QEMU, gem5, KVM,
deterministic host models, and external adapters are implementations or providers
of nodes. Compute, block storage, filesystem, clocks, links, and other roles do
not need a VM-shaped lifecycle. A logical node, an execution owner, and a state
owner need not have a one-to-one relationship.

Implementation starts by wrapping the current QEMU and host-device paths without
changing execution, canonical ordering, native receipt authority, serialized
bytes, or persisted identities. Graph and schema changes follow as explicitly
versioned features. Exact gem5 and quantized KVM are separate qualification
workstreams; neither is a justification for weakening the current QEMU exact
contract.

The complete connected graph must be admitted before activation. An unsupported
timing, device, capture, or replay combination is refused. Capability discovery
does not authorize a backend to substitute a weaker operating mode after launch.

## What this documentation change verifies

Documentation review can verify source references, local links, requirement
coverage, and internal consistency. It cannot establish runtime correctness,
timing accuracy, device parity, complete state preservation, or performance.
The original audit and phased plan describe intended work. The separate
[implementation status](implementation-status.md) records implemented stages;
[reference baseline](reference-baseline.md) records measured reference runs and
their exact artifact identities. Neither changes a profile's qualification.

Large traces, profiles, raw timing logs, and native state dumps remain local
qualification artifacts. Future change descriptions should include concise
summaries and artifact identities; this plan does not require committing raw
evidence or publishing it through release assets.

## Changes that require a separate decision

- Implementing the specified CNP/1 transport, encodings, operation registry,
  bounds, and extensions requires an explicit protocol migration. Host Rust
  traits are not a wire ABI and existing QEMU messages remain adapter-specific.
- Backward readers and canonical identity migration need a compatibility design
  before a writer begins emitting a new format.
- Cross-implementation initialization, such as KVM-to-gem5 architectural
  conversion, creates a distinct realization and lineage. It is not exact restore.
- Any claim of hard wall-clock deadlines for physical hardware requires a separate
  resource and timing qualification. Logical causality alone does not establish
  real-time performance.

## Open implementation decisions

The phased plan assigns feasibility tests and acceptance exits for these choices:

1. Keep common host traits in the engine with device wrappers initially, or
   extract a lower dependency crate when independent providers need it?
2. Which current canonical formats can retain legacy decoding, and which need
   a deliberate cutover with explicit refusal?
3. Which detailed CPU/device configurations can meet complete gem5 state
   preservation, including durable restore after source exit?
4. Which kernel and machine configurations can mediate every KVM clock and I/O
   path required by the quantized profile?
5. Which native simulator components should be public logical nodes, and which
   remain private implementation details inside one declared owner?
6. What evidence storage and distribution mechanism should a deployed executor
   use for third-party qualification manifests?

These choices remain constrained by the RFC's causal, ownership, timing, parity,
and state-preservation requirements.
