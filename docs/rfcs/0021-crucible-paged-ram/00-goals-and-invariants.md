# 00 - Goals, invariants, and terminology

## 0.1 Problem statement

Campaign throughput is constrained by host memory committed to many guest
machines and retained execution sources. Configured guest RAM is an addressable
logical capacity; it is not necessarily the active working set. Deterministic
software execution permits cold logical pages to be fetched from host storage
without introducing modeled guest time. Incremental content identity avoids
scanning those same cold pages merely to observe unchanged machine state.

The objective is to make this separation a system contract. It must remain
true through CPU execution, DMA, fault injection, fingerprint sampling,
reset, restore, fork, cancellation, storage failure, and distributed transfer.
More concurrency is a measured consequence, not an unconditional promise:
random-access guests with large active working sets can be slower and can
exhaust storage bandwidth before host RAM.

## 0.2 Required invariants

- **[INV-1] Guest transparency.** Every guest supported by the existing
  admitted machine profile MUST run unmodified. The feature MUST NOT require
  a guest kernel patch, balloon driver, agent, paravirtual swap device, changed
  guest memory map, or guest awareness of residency policy. Paging MUST NOT
  reduce configured guest RAM or convert RAM into a different guest device.
- **[INV-2] Modeled time in deterministic profiles.** For QEMU-SIM and any
  qualified deterministic gem5 profile, host page faults, preservation,
  reclamation, prefetch, hashing, and storage waits MUST NOT advance modeled guest time,
  consume modeled execution quanta, alter deterministic event order, or
  change an architectural result. The existing modeled CPU/memory timing
  contract MUST remain identical across admitted residency policies. The
  nondeterministic quantized KVM profile MUST instead satisfy the explicit
  clock, budget, input, and publication contract in chapter 14; it MUST NOT
  advertise this deterministic guarantee.
- **[INV-3] Deterministic identity.** Given the same logical memory and
  complete machine state at the same admitted boundary, fingerprints MUST
  match regardless of host residency, host page size, storage representation,
  eviction order, sharing, process placement, or runtime policy revision.
- **[INV-4] Authoritative contents.** Every logical page version MUST have
  an authoritative resident copy or an authenticated readable preserved copy
  before execution may access it. Releasing the last correct resident copy
  before preserving its latest version is forbidden. Missing backing MUST
  NOT mean zero-filled memory.
- **[INV-5] Coherent observations.** A published root MUST describe one
  admitted coherent boundary. RAM, device pre-save changes, CPU state,
  virtual time, fault state, and host-controlled deterministic inputs MUST
  satisfy the boundary contract of their enclosing fingerprint/checkpoint.
- **[INV-6] Operational failure separation.** Resource exhaustion, corrupt
  backing, permission denial, pager loss, and host supervision expiry MUST
  be reported as host operational failures. They MUST NOT fabricate guest
  assertions, guest crashes, modeled timeout events, or valid resume state.
- **[INV-7] Owned lifetimes.** Reachable roots, mutable page versions,
  in-flight operations, hot sources, children, and quarantined instances MUST
  retain their backing and resource ownership until the final use ends.
- **[INV-8] Process boundary.** QEMU implementation state MUST remain GPL
  side and process private. Cross-process contracts MUST use versioned public
  identities and checked offsets, preserving the repository license boundary.
- **[INV-9] Dynamic control.** An authorized operator MUST be able to change
  the effective host RAM policy without reconstructing the guest. Revision,
  generation, reservation, convergence, and failure semantics MUST be explicit.
- **[INV-10] Bounded work.** Admission MUST bound the resources necessary
  to make forward progress and fail closed. A disk-oriented policy MUST NOT
  promise zero physical memory usage or an unbounded number of concurrent VMs.

Transparency applies to guest-visible execution, not to host completion time
or host observability. Host logs may show different latency, page faults, cache
behavior, or infrastructure failures. A deterministic machine profile may
already restrict accelerators, devices, or nondeterministic inputs; this RFC
does not broaden that profile to arbitrary unsupported QEMU configurations.
It MUST NOT impose a new guest-side paging dependency within that profile.

The common contract addresses logical regions, execution owners, capture owners,
coherent boundaries, and paging contexts. An execution owner controls one or
more nodes; a capture owner preserves an enumerated set of state domains. They
need not be one process or one public node. Chapter 14 allocates the common
requirements to named implementation profiles. QEMU-specific mechanisms in this
RFC apply to QEMU-SIM, not by inference to gem5 or KVM.

## 0.3 Goals and non-goals

Required outcomes are a measurable kernel-swap baseline; precise custom paging;
runtime adjustable policy; incremental roots with independently verifiable
contents; complete tracking of supported write origins; coherent hot forks;
durable logical checkpoints; lazy restore from a locally available authenticated
closure; and bounded, cancellable missing-state transfer.

Remote postcopy, a network fault server, coordinated live migration, shipping
gem5 or KVM support, arbitrary accelerators, guest-visible memory overcommit, and
simulation of realistic hardware RAM latency are separate work. The new memory
foundation may support them, but none is claimed by this RFC. Storage compression,
encryption, deduplication across trust domains, and concurrent eviction during
guest execution are separately qualified extensions, not correctness shortcuts.

Existing admitted simulation memory faults and modeled memory-service timing
must continue to work across residency changes; deferring realistic controller
extensions does not defer that integration. Continuous parallel reference/fault
RAM images are deferred as described in chapter 12. Independent full recomputation
is validation of the actual image, not a mandatory runtime overlay.

## 0.4 Vocabulary and identity domains

| Term | Meaning |
| --- | --- |
| Logical RAM | Bytes of declared backing regions in the admitted memory inventory, independent of host placement; not necessarily the latest coherent architectural view of a detailed memory hierarchy |
| Execution owner | Exclusive authority for native execution of an admitted set of nodes |
| Capture owner | Authority preserving explicitly owned future-affecting state domains at a coherent boundary |
| Paging context | Generation-bound mapping, backing, fault-service, and resource authority for one independently mutable branch |
| Logical page | A fixed 4,096-byte unit; the final page of a region may have fewer valid bytes |
| Region | Stable, uniquely owned logical byte sequence identified by a portable region ID |
| Page coordinate | `(region_id, logical_page_index)` in one validated topology |
| `PageDigest` | BLAKE3-256 commitment to valid length and page bytes, excluding coordinate |
| `RegionTreeDigest` | Commitment to a region's ordered pages and exact length |
| `RamRootDigest` | Commitment to named scope, complete topology, and selected ordered region trees |
| `ContentId` / `PageObjectId` | Existing storage identity of an encoded object, distinct from logical RAM identity |
| `page_version` | Operational generation used to reject stale preservation/fetch completions |
| Dirty epoch | Independent consumer interval recording candidate modified pages |
| Resident | Present in a usable host mapping; not necessarily locked in physical memory |
| Preserved | A correct version can be reconstructed from authenticated owned backing |
| Durable | Meets the checkpoint store's crash-recovery and retention publication contract |
| Source seal | Immutable logical source state at a coherent boundary; residency may still change |
| Effective policy | Currently admitted operational policy, separate from authored campaign semantics |
| Convergence | Bounded progress from current residency toward an admitted policy target |

A preserved mutable spill record need not be a durable checkpoint object.
The operating system can retain cached bytes even after QEMU unmaps or drops
its resident copy. “Disk-oriented” means cold logical contents may all be
externalized and only an admitted working set materialized. “Resident-required”
means a separately admitted guarantee backed by reservation, prefaulting,
locking, and verified host capabilities. Ordinary virtual mappings alone do
not establish that guarantee.

## 0.5 Conformance and requirements ownership

- **[CONF-1]** Every advertised implementation profile and paging backend MUST
  bind the actual implementation/build, resolved semantic configuration,
  operating mode, capture fidelity, and supported mapping,
  fork, restore, supervision, and resource capabilities. Unsupported modes
  MUST be rejected before they are used. Silent fallback that weakens an
  explicitly requested guarantee is forbidden.
- **[CONF-2]** The implementation MUST maintain a requirement-to-evidence
  inventory covering all normative identifiers in this RFC and each enabled
  backend. Requirements shared by consumers MUST be satisfied at each consumer's
  integration boundary, not merely by a unit test of a common helper.
- **[CONF-3]** The release MUST declare the current logical encoding edition,
  protocol majors, fingerprint definitions, checkpoint schema, and policy
  schema. Noncurrent combinations MUST be rejected before execution.

Chapter 02 owns hash construction. Chapter 03 owns tracking and coherent RAM
views. Chapter 04 owns local page states and fault authority. Chapter 05 owns
resource and deadline updates. Chapter 06 owns fork/lifecycle transactions.
Chapters 07 and 08 own durable storage and transfer publication. Chapter 14
owns implementation-profile allocation and explicitly scoped timing guarantees.
A consumer may add stricter admission constraints but may not weaken a shared invariant.
