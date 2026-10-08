# RFC-0025: Crucible simulation node contract

- **Status:** Proposed.
- **Date:** 2026-10-07.
- **Audience:** Crucible maintainers, scenario authors, simulator and hardware
  vendors, device-model authors, and independent executor implementations.
- **Updates:** The node composition, provider abstraction, timing
  negotiation, and state compatibility contracts of
  [RFC-0010](../0010-crucible/README.md),
  [RFC-0014](../0014-signal-driven-fault-model/README.md), and
  [RFC-0020](../0020-crucible-campaigns/README.md).
- **Preserves:** Coordinator authority over scheduling and assertions; original
  execution and queue custody; implementation-bound exact state; and the
  [Crucible/QEMU licensing and process boundary](../0010-crucible/37-licensing-process-boundary.md).

## Abstract

This RFC specifies a common participation contract for Crucible simulation
nodes. A node can represent a compute system, block device, filesystem, clock,
network link, or externally implemented component. Node role, implementation,
timing mode, repeatability, state-preservation scope, and observation facilities
are independent properties. A scenario selects and binds these properties
before execution; the executor refuses compositions it cannot support.

The coordinator issues bounded grants and orders interactions through typed
ports. Exact participants stop at authenticated simulation boundaries.
Quantized participants sample inputs and publish outputs according to an
explicit window contract. This allows hardware-accelerated and physical
components to participate without pretending that hardware execution stops at
an exact simulated timestamp. Exact participants retain finer internal timing
when connected to quantized ports.

Logical node identity is separate from execution ownership and capture
ownership. One simulator can implement several visible components while
advancing and capturing its native interconnected state once. Independently
modeled devices retain their own authoritative state. Whole-world state
includes owner artifacts, pending interactions, ordering, timing contracts, and
implementation identities; incompatible restoration is refused before
activation.

The contract is language-neutral. Rust traits illustrate a host API, while
CNP/1 defines a local process-provider control profile. A vendor can implement
the process interface without linking Crucible's host implementation. Neither
trait inheritance nor a capability claim replaces qualification of the actual
realized configuration.

## Scope

This RFC defines node participation, composition, timing, state preservation,
provider interoperability, and conformance. Its normative contract comprises
the numbered chapters and CNP/1 reference records linked below. Requirement
language follows BCP 14 as specified in
[conventions](00-conventions-and-model.md).

Implementation-specific artifacts retain the interpretation defined by their
bound protocol and state-format versions. A change to those semantics requires
an explicit compatible binding or conversion under chapter 05.

## Document map

| Chapter | Contract |
| --- | --- |
| [00 — Conventions and model](00-conventions-and-model.md) | Terminology, normative requirements, identities, guarantees, and composition |
| [01 — Node contract](01-node-contract.md) | Common operations, role facets, providers, ownership, lifecycle, and host trait model |
| [02 — Ports, capabilities, and admission](02-ports-capabilities-and-admission.md) | Typed connections, supported versus selected contracts, manifests, and graph admission |
| [03 — Time and scheduling](03-time-and-scheduling.md) | Exact shared time, grants, lookahead, representable boundaries, event ordering, and concurrency |
| [04 — Quantized and physical nodes](04-quantized-and-physical-nodes.md) | Window grants, input/output commitment, hardware observations, deadline policy, and mixed timing |
| [05 — State and replay](05-state-and-replay.md) | Exact capture, durable and live materialization, whole-world restore, compatibility, and conditional replay |
| [06 — Provider protocol and security](06-provider-protocol-and-security.md) | CNP/1 transport, encoding, operation correlation, retries, errors, trust, and process boundaries |
| [07 — Reference profiles and examples](07-reference-profiles-and-examples.md) | Compute, device, clock, link, and hardware profiles; mixed-world examples |
| [08 — Conformance](08-conformance.md) | Independent qualification classes, evidence, negative cases, state preservation, and performance |
| [09 — Decisions and extensions](09-decisions-and-extensions.md) | Design rationale, extension registration, version policy, additional profiles, and references |

Chapter 06 includes two normative references:

- [CNP/1 core object schemas](reference/cnp-v1-core-types.md) define portable
  descriptors, bindings, positions, events, custody records, and manifests.
- [CNP/1 primitive vectors](reference/cnp-v1-vectors.json) fix small encoding,
  canonicalization, domain-separated hash, and rejection examples. These are
  protocol fixtures, not complete node descriptors or execution evidence.

## Reading paths

A provider implementer starts with chapters 00–02, chooses a timing contract
from chapters 03–04, and implements the process mapping in chapter 06. Chapter
05 determines which state and replay claims are available. Chapters 07–08
define profile requirements and the evidence needed to advertise support.

A scenario author starts with the composition and capability rules in chapter
02 and the mixed-timing examples in chapter 07. A quantized participant changes
the timing contract of the ports that interact with it; it does not silently
coarsen every participant's internal model. Nondeterminism and state limitations
remain visible in the world binding and result.

## Design commitments

1. **A node participates; its role does not select its implementation.**
   Compute is one role, with QEMU, gem5, and KVM-based realizations as possible
   implementations. Storage, clocks, and links participate through the same
   common contract with different role facets.
2. **Time is permission, not a label on completed work.** The coordinator does
   not admit a participant beyond a possible input merely because the provider
   can buffer its outgoing messages or rewrite a clock afterward.
3. **Exact and quantized are explicit contracts.** An exact stop receipt and a
   closed quantized window describe different facts. Native admission/control
   protocol versions are separate from those timing modes.
4. **One authoritative owner per state domain.** Public composition does not
   duplicate mutable native state, create one process per logical node, or
   permit independent stepping of coupled simulator components.
5. **Capabilities are configuration-specific.** A provider name, instruction
   set, or successful boot does not prove device parity, exact stopping, or
   complete state preservation.
6. **State is implementation-bound.** Restoration preserves an admitted
   implementation's own future-affecting state. A change of CPU model, device
   graph, timing mode, provider, or state format requires compatible evidence or
   a separately identified conversion.
7. **Nondeterminism remains observable.** Stable coordinator ordering cannot
   make physical execution repeatable. Transcript replay is conditional on the
   captured interaction history and cannot authorize arbitrary counterfactual
   branches.

## Relationship to other Crucible RFCs

RFC-0010's fixed instruction-cost model remains a compute-profile choice; it is
not the universal conversion from work to time. This RFC retains the exact
picosecond coordinate while requiring each realization to declare its
representable boundaries and timing model.

RFC-0014's fault semantics and authoritative observations remain host-side.
Portable fault requirements are distinguished from implementation-specific
mechanisms and evidence. Declaring a new provider does not make an unsupported
fault or guest protocol available.

RFC-0020's campaign exploration remains applicable to worlds that meet its
selected materialization and replay guarantees. Nondeterministic attempts need
observed execution identities rather than a deterministic cache assumption
that one planned configuration identifies one resulting state.

The QEMU/plugin remains a separate process from the Apache host. Native owner
handles, pointers, callback tables, and Rust objects do not become a shared
memory API. QMP and shared-memory adapters can implement the host
contract without claiming that their native wire formats are CNP/1.

## Non-goals

- Cycle-accurate behavior from a fixed-cost instruction model.
- Exact physical CPU microstate capture through ordinary hardware virtualization.
- Portable restoration between unrelated simulators.
- A universal binary Rust plugin ABI or a native callback ABI shared with QEMU.
- Automatic device substitution when a selected provider lacks a required ABI.
- Making a nondeterministic world deterministic by ordering its observations.
- Hard real-time guarantees from logical simulation barriers.
- Remote or distributed-provider interoperability; those profiles
  require explicit transport, fencing, and timing contracts.

## Conformance

Provider conformance is assessed for a specific implementation, configuration,
and selected contract. Chapter 08 defines the evidence classes and qualification
obligations for each advertised guarantee.
