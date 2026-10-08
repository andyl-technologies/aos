# 09 — Decisions, extensions, and version policy

This chapter records the design choices and defines how a provider extends the
contract without silently changing an admitted world's behavior. It does not
allocate Internet protocol numbers or claim IANA registration.

## 1. Decision register

| Decision | Choice | Rationale and consequence |
| --- | --- | --- |
| D-01 | Universal simulation-node participation | Compute, storage, clocks, links, and physical adapters share admission, interaction, and lifecycle semantics. Their role-specific operations remain typed. |
| D-02 | Role, implementation, timing, and guarantees are separate | Avoids a Cartesian hierarchy of exact/quantized compute/disk/link subclasses and prevents a timing claim from implying repeatability or capture support. |
| D-03 | Logical nodes and mutable owners have separate identities | Native simulator components can be visible without independent mutation or duplicate restoration. Connections do not imply state ownership. |
| D-04 | One shared integer picosecond coordinate | Avoids floating-point ordering and preserves the existing exact timeline. Provider resolution and guest clock readings are distinct properties. |
| D-05 | Exact advancement uses admitted boundaries and complete input knowledge | A scalar ceiling or capability manifest cannot replace retained authorization or justify passing possible input. |
| D-06 | Quantized advancement has separate grants and acknowledgments | KVM and physical devices can participate through explicit sampling/publication windows without false exact-stop receipts. |
| D-07 | Mixed timing is expressed at ports and connections | Exact nodes retain finer internal events; crossings follow admitted rounding, sampling, and publication rules. |
| D-08 | Canonical commitment follows logical event order | Host completion order, thread scheduling, and transport arrival order do not choose deterministic simulation order. |
| D-09 | Event-driven nodes need no artificial CPU RUN | A disk/link/clock can contribute an event frontier and quiescence proof rather than pinning the world minimum with an unused execution cursor. |
| D-10 | Timing guarantees are orthogonal to repeatability | Exact event placement can carry nondeterministic payloads; deterministic computation can still expose coarse time. Both facts are retained. |
| D-11 | Exact modeled-state continuation is the detailed-simulator requirement | Architectural registers alone do not preserve caches, speculation, queues, random engines, and future event trajectories. |
| D-12 | Live branching and durable restart are distinct capabilities | Private process memory can preserve a live object graph without establishing restore after the source process has exited. |
| D-13 | Restoration validates the complete world before RUN admission | Independent provider preparation cannot expose a partially restored world. Activation readiness is separate from permission to execute. |
| D-14 | Backend changes produce fresh roots or explicit conversions | Reusing boot assets is portable; reinterpreting another implementation's saved state is not. |
| D-15 | Nondeterminism taints interacting execution | Conditional transcript replay can preserve an observed boundary history but does not reconstruct an arbitrary physical future. |
| D-16 | Host budgets are operational policy | A watchdog can terminate stalled work; it cannot establish the simulated timestamp or a deterministic application timeout. |
| D-17 | Host traits are source interfaces; process providers use a wire profile | Rust object layout and vtables are not a vendor binary ABI. Native QEMU integration retains its process/license boundary. |
| D-18 | Portable semantics and implementation mechanisms are distinct | A fault, port, or state guarantee is defined independently of QMP commands or a simulator's private class names. |
| D-19 | Capabilities are admitted and qualified per configuration | The same provider binary may realize models with different devices, timing resolutions, capture scopes, and host requirements. |
| D-20 | Strict failures have explicit retained effect disposition | Timeout, cancellation, and disconnected control sessions cannot authorize blind replay of a possibly completed effect. |
| D-21 | Versioned compatibility precedes rollout | Mechanical source renames preserve existing bytes; changed graph, mode, and state semantics require new format identities. |
| D-22 | Performance evidence is workload-specific | Boot, dispatch, device service, and capture costs are measured separately. Detailed CPU fidelity is not normalized to a fixed instruction cost. |

## 2. Identifier namespaces and extension registration

Core roles, ports, features, errors, and operation kinds are defined by the
versioned contract and its registry. A provider can add a role or protocol
without extending every host trait, but admission needs its exact semantic
definition and schema. An opaque vendor payload is not automatically a valid
interaction.

- **[CN-EXT-1]** An extension declaration MUST identify its owner-controlled
  namespace, semantic version, schema digest, applicable operations or ports,
  resource bounds, timing effects, state effects, error behavior, and required
  features. It MUST NOT redefine a core identifier under vendor ownership.
- **[CN-EXT-2]** An admitted world MUST bind every behavior-affecting extension
  and its selected version into its immutable execution binding. An unknown
  required extension MUST cause refusal before activation. An ignored optional
  extension MUST NOT influence simulation behavior, permission, state identity,
  or an advertised guarantee.
- **[CN-EXT-3]** A provider MUST NOT infer acceptance of an extension from an
  unrecognized descriptor field, payload byte sequence, role name, or success
  response to a different operation. Extension negotiation MUST return the
  selected identifier, version, and schema digest explicitly.

Registration records have the following content:

| Field | Meaning |
| --- | --- |
| `identifier` | Namespaced semantic identifier, following the syntax in chapters 02 and 06 |
| `owner` | Namespace authority and publication origin |
| `semantic_version` | Exact published semantic version |
| `schema_digest` | Canonical schema content identity |
| `specification` | Immutable specification reference sufficient for independent implementation |
| `dependencies` | Exact core and extension contracts required |
| `required_features` | Negotiated conditions without which the extension cannot operate |
| `timing_effects` | Input/output boundaries, representable resolution, and causal obligations |
| `state_effects` | Authoritative state domains, capture dependencies, and compatibility rules |
| `limits` | Message, queue, allocation, and operation bounds |
| `conformance` | Positive and negative test classes and applicable qualification evidence |

Core registrations are maintained with the RFC's protocol/schema inventory.
Vendor registrations are admitted under configured trust policy. Registering a
definition is distinct from qualifying an installed implementation of it.

## 3. Compatibility domains

Compatibility is a relation proved for a particular use, not a single global
version number. These domains can change independently:

| Domain | Compatibility question |
| --- | --- |
| Common operation semantics | Do lifecycle, permissions, result disposition, and retry rules agree? |
| CNP control version | Can the peers frame, decode, correlate, and validate control messages? |
| Port semantic contract | Are requests, responses, timing, ordering, and error meanings compatible? |
| Guest platform/device ABI | Will the guest discover and operate the required machine and devices? |
| Shared-memory transport ABI | Do layout, offsets, ownership, atomics, bounds, and generations agree? |
| Capture format | Can the selected implementation restore every encoded state domain? |
| Execution binding | Are implementation, model, devices, ports, timing, and qualification unchanged or explicitly accepted? |
| Observation/fingerprint schema | Do hashes and observations cover the same defined state and events? |
| Scenario/campaign format | Can the authoring and persisted execution semantics be decoded without reinterpretation? |

- **[CN-EXT-4]** An implementation MUST validate each compatibility domain
  required by the operation. Success in control decoding or guest boot MUST
  NOT imply state-format, timing, replay, or device compatibility.
- **[CN-EXT-5]** A compatibility transition that changes admitted behavior or
  future-affecting state MUST create a new versioned binding or explicitly
  identified conversion. It MUST NOT silently relabel an old state artifact as
  a new implementation's state.
- **[CN-EXT-6]** A legacy decoder MUST preserve the legacy format's documented
  meaning and authentic implementation binding. It MUST NOT select a provider
  from the current command-line default when a stored execution requires a
  different or unknown implementation.

A control minor version can add optional, non-behavioral information when the
base decoding rules allow it. A new required operation, changed boundary
meaning, altered canonical identity, or changed effect disposition needs
explicit negotiation and a new semantic contract. Numeric version proximity
does not establish compatibility.

## 4. Conformance and publication rules

A published profile identifies required semantics; a qualification statement
identifies evidence for a concrete configuration. A provider may implement a
subset of optional facets, but it cannot claim a profile while omitting one of
that profile's required properties.

- **[CN-EXT-7]** A published conformance statement MUST identify the exact
  implementation/configuration binding, selected modes, qualification class,
  exercised state and interaction domains, and known exclusions. A source
  review, mock adapter, successful boot, or passing parser test MUST NOT be
  described as live timing or exact-continuation qualification.
- **[CN-EXT-8]** Removal or weakening of an admitted capability MUST require
  refusal or a newly admitted world. A provider MUST NOT downgrade timing,
  state preservation, protocol features, or evidence requirements during an
  existing realization to recover from an operational failure.

The publisher records immutable specification and test identities. Test logs
can remain in a dedicated evidence system or local retention with a concise
manifest. Repository source and release assets are not substitutes for a
purpose-built evidence service. No evidence-hosting mechanism is required by
this RFC; unavailable evidence means an unavailable qualification claim.

## 5. Deliberately deferred profiles

The local provider contract is the baseline. The following require additional
specifications rather than implied support:

- Remote provider transport authentication, durable fencing, reconnect across
  machines, and resource ownership after network partitions.
- Cross-host live migration of a simulator's complete state.
- Cross-implementation state conversion with architectural and timing-loss
  declarations.
- Hard real-time physical-device execution and guaranteed host scheduling.
- Physical-device rollback or branching where the device itself has no such
  capability.
- Arbitrary cross-ISA compute-state conversion.

- **[CN-EXT-9]** A deferred profile MUST NOT be advertised as core conformance
  without an admitted versioned definition covering its additional failure,
  ownership, timing, state, and security semantics.

Deferral is not a prohibition on independent work. It prevents two vendors from
using the same core label for incompatible behavior.

## 6. Review questions and implementation decisions

The semantic requirements above are target-state decisions. These delivery
questions remain implementation choices constrained by that contract:

1. Keep common host traits in the engine with device wrappers initially, or
   extract a lower dependency crate when independent providers need it?
2. Which current canonical formats can retain legacy decoding, and which need
   a deliberate cutover with explicit refusal?
3. Which detailed CPU/device configurations can meet complete gem5 state
   preservation, including durable restore after source exit?
4. Which kernel and machine configurations can mediate every KVM clock and I/O
   path required by the quantized profile?
5. Which existing native simulator components should be public logical nodes,
   and which remain private implementation details inside one declared owner?
6. What evidence storage and distribution mechanism should a deployed executor
   use for third-party qualification manifests?

These questions do not permit missing input knowledge, duplicate state
ownership, false exact receipts, implicit device substitution, or silent
cross-implementation restore. The
[implementation companion](../../plans/crucible-node-contract/README.md)
assigns phased feasibility tests and acceptance exits.

## 7. Normative and informative references

Normative requirement terminology follows
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html). Canonical JSON in the
process profile follows [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html),
with Crucible's explicit string encoding for wide integer values and its
domain-separated identity construction in chapter 06.

The existing Crucible RFCs are informative context where this proposal changes
their node/timing generality. The licensing/process boundary remains a
constraint on any implementation:

- [RFC-0010: Crucible](../0010-crucible/README.md).
- [RFC-0014: Signal-driven fault model](../0014-signal-driven-fault-model/README.md).
- [RFC-0020: Crucible campaigns](../0020-crucible-campaigns/README.md).
- [Crucible/QEMU process boundary](../0010-crucible/37-licensing-process-boundary.md).
- [Repository licensing policy](../../legal/licensing.md).

Provider-specific implementation references and limitations are identified in
chapter 07. They are not substitutes for the normative node contract or its
qualification tests.
