# 37 — Licensing and the Crucible/QEMU process boundary

This file specifies the architectural boundary that keeps the Crucible host and
QEMU independently licensed without sacrificing the shared-memory fast path. It
is an engineering contract, not a conclusion about any particular legal case.
The repository-wide license map is [`LICENSING.md`](../../../LICENSING.md).

Requirement IDs in this file use the prefix `BOUND`. Every requirement is
guarded by `gate:license-boundary`, an **Always** gate owned by
`crucible-harness`; ABI-shape requirements are additionally guarded by
`gate:abi-conformance`.

## 37.1 Component and license map

```text
Apache-2.0 host process                 GPL-2.0-only QEMU process
┌──────────────────────────┐           ┌──────────────────────────┐
│ engine, scheduler,       │           │ patched QEMU             │
│ assertions, CLI          │           │ crucible-qemu-plugin     │
│                          │           │                          │
│ permissive protocol/SHM  │◄═════════►│ permissive protocol/SHM  │
│ implementation           │  public   │ implementation           │
└──────────────────────────┘  ABI      └──────────────────────────┘
             Unix socket: setup/control only
             shared memory: high-throughput data plane
```

- **[BOUND-1]** Original host-side Crucible code MUST remain Apache-2.0 unless a
  file carries a more specific license. `crucible-protocol` and
  `crucible-shmem`, the reusable boundary components, MUST be licensed
  `MIT OR Apache-2.0`. *Gate:* `gate:license-boundary`. *Spec:* §37.1.

- **[BOUND-2]** `crucible-qemu-plugin`, every patch or new implementation loaded
  into or linked with QEMU, and every other in-QEMU integration component MUST
  remain within QEMU's applicable GPL-compatible/upstream license scope. The
  plugin takes its boundary-crate dependencies under the GPL-compatible license
  choice; it MUST NOT depend on an Apache-only host crate. *Gate:*
  `gate:license-boundary`. *Spec:* §37.1.

- **[BOUND-3]** Repository, package, and release metadata MUST describe AOS as a
  multi-license aggregate and MUST NOT claim that a distribution containing
  QEMU is wholly Apache-2.0. Third-party notices and more specific upstream file
  licenses MUST be preserved. *Gate:* `gate:license-boundary`. *Spec:* §37.1,
  §37.4.

## 37.2 A public process protocol, not an implementation ABI

The host and QEMU remain distinct operating-system processes. A socket pair
negotiates versions and transfers descriptors during setup. Once setup
completes, the socket is quiescent and high-frequency scheduling, clock, frame,
I/O, observation, and doorbell traffic flows through shared memory. This retains
the zero-IPC-round-trip steady state defined by [SHM-1] and [PROTO-1].

- **[BOUND-4]** Apache host code and GPL-side QEMU code MUST communicate only as
  separate processes through the versioned control and shared-memory protocols.
  Apache-only code MUST NOT link QEMU libraries, include QEMU headers, load into
  QEMU, export QEMU callbacks, or exchange direct calls with in-QEMU code.
  *Gate:* `gate:license-boundary`. *Spec:* §37.2.

- **[BOUND-5]** The socket MUST remain the cold setup/control plane and shared
  memory MUST remain the hot data plane. A boundary refactor MUST NOT replace
  shared memory with per-quantum or per-frame socket round trips merely to make
  the process boundary visible. *Gate:* `gate:license-boundary`,
  `gate:abi-conformance`. *Spec:* §37.2; preserves [G-9], [SHM-1], [PROTO-1].

- **[BOUND-6]** The shared region MUST be a public, documented, independently
  implementable protocol. It MAY contain fixed-width integers, explicitly sized
  atomics, checked region-relative offsets, version/feature fields, ring
  geometry, sequence/generation numbers, tagged entries, and serialized byte
  payloads. It MUST NOT contain process-native pointers, QEMU private objects,
  function or callback tables, compiler-selected enum layouts, Rust trait
  objects, or ownership of a mutable process-private object. *Gate:*
  `gate:license-boundary`, `gate:abi-conformance`. *Spec:* §37.2.

- **[BOUND-7]** The normative field semantics, byte layout, ordering rules, and
  compatibility policy MUST be public. Rust definitions may remain the
  mechanically checked source used to generate the C view, but no semantic
  contract may exist only in Rust or QEMU implementation internals. An
  independent peer built from the specification and golden vectors MUST be able
  to interoperate. *Gate:* `gate:license-boundary`, `gate:abi-conformance`.
  *Spec:* §37.2, [`13-shmem-abi.md`](13-shmem-abi.md) §13.2.

## 37.3 Versioning and review

- **[BOUND-8]** Every incompatible control frame, shared-memory field, layout,
  atomic-ordering, or semantic change MUST bump the applicable ABI major version
  and fail closed against the old peer. Compatible additions require an explicit
  minor version or feature bit. The change MUST regenerate both language views
  and golden vectors. *Gate:* `gate:license-boundary`,
  `gate:abi-conformance`. *Spec:* §37.3.

- **[BOUND-9]** A change that moves code across the boundary requires explicit
  license-boundary review. CI MUST reject a QEMU dependency in an Apache-only
  crate, an Apache-only dependency in the plugin, a missing or inconsistent
  component license declaration, a forbidden shared-memory construct, or a
  generated ABI mismatch. *Gate:* `gate:license-boundary`. *Spec:* §37.3.

## 37.4 Packaging and corresponding source

- **[BOUND-10]** The host controller, patched QEMU/plugin backend, and aggregate
  distribution MUST remain distinguishable package outputs with accurate license
  metadata, even when a convenience package installs all of them. *Gate:*
  `gate:license-boundary`. *Spec:* §37.4.

- **[BOUND-11]** Any release surface that distributes the patched QEMU binary
  MUST also publish matching complete corresponding source. The artifact MUST
  include the exact QEMU source, all applied patches, plugin and QEMU-side source,
  generated interface files needed to build it, build/configuration scripts,
  retained notices, and a binary/source identity binding. Missing source MUST
  fail release construction. *Gate:* `gate:license-boundary`. *Spec:* §37.4,
  [`26-packaging-aos-integration.md`](26-packaging-aos-integration.md).

## 37.5 Guest assertions compatibility

Ongoing guest-assertion work fits this boundary without changing the assertion
model. Assertion definitions, evaluation, verdicts, and artifact semantics stay
in the Apache host. The optional guest doorbell is an observation protocol, not
an assertion evaluator.

- **[BOUND-12]** Guest assertion semantics and evaluation MUST remain host-side.
  Any QEMU/plugin change needed to trap, read, validate, or publish a guest
  observation remains GPL-side and MUST cross to the host only as a versioned
  shared-memory or doorbell-protocol record. No QEMU structure, guest pointer, or
  callback may cross that boundary. *Gate:* `gate:license-boundary`,
  `gate:abi-conformance`. *Spec:* §37.5, [`16-guest-host-channel.md`](16-guest-host-channel.md),
  [`18-assertions-properties.md`](18-assertions-properties.md).

## Implementation checklist

- [x] **T-BOUND-1** Keep component license declarations and dependency scopes
  consistent across host, boundary, and in-QEMU components. — satisfies
  [BOUND-1], [BOUND-2], [BOUND-3], [BOUND-4], [BOUND-9], [STD-34]; spec §37.1,
  §37.2, §37.3.
- [x] **T-BOUND-2** Enforce the public shared-memory protocol constraints and
  independent conformance peer in `gate:license-boundary` and
  `gate:abi-conformance`. — satisfies [BOUND-5], [BOUND-6], [BOUND-7],
  [BOUND-8], [BOUND-9]; spec §37.2, §37.3.
- [x] **T-BOUND-3** Make packaging/release construction emit accurate aggregate
  metadata and matching QEMU corresponding source — satisfies [BOUND-3],
  [BOUND-10], [BOUND-11]; spec §37.1, §37.4.
- [ ] **T-BOUND-4** Keep guest assertion evaluation host-side while gating the
  observation protocol across the boundary. This task remains deferred to the
  ongoing guest-assertions work; the checked boundary gate already enforces the
  compatibility invariant for code merged before it. — satisfies [BOUND-12];
  spec §37.5.
