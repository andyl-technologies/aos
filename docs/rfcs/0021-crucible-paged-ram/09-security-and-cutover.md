# 09 - Security, process boundaries, and experimental cutover

This chapter specifies the security obligations of host RAM paging and the
coordinated transition to the new logical RAM contract. The requirements below
are proposed work. They do not claim that the current implementation supports
Merkle RAM, a custom pager, or runtime residency changes. Normative terms have
the meaning established in [the RFC overview](README.md).

## 9.1 Threat model and trust decisions

A guest is untrusted input to the emulator. Guest writes, page-table changes,
device programming, memory-access patterns, and repeated reads of cold pages
can exercise every pager path without guest cooperation. Paging MUST preserve
the guest-transparency contract in
[00-goals-and-invariants.md](00-goals-and-invariants.md). Transparency does not
authorize exposing host storage paths, native addresses, pager handles, or host
resource policy through a guest device.

The backing store may return corrupt, missing, stale, short, reordered, or
duplicated data. A remote store may be unavailable indefinitely. Local storage
may run out of space or report failed writeback. The host kernel can reclaim
memory independently of Crucible's desired residency. A control client can
submit stale policy revisions or repeatedly request expensive convergence.
Process termination can occur between preserving bytes, publishing metadata,
and releasing a lease. These conditions are part of the threat model even when
the operator does not expect malicious infrastructure.

The unkeyed BLAKE3-256 constructions in
[02-logical-ram-and-merkle-format.md](02-logical-ram-and-merkle-format.md)
provide content integrity under the usual collision and second-preimage
assumptions. They do not provide encryption, access control, execution
authorization, or storage availability. A root received from an unauthenticated
source proves only a relationship to that source's chosen bytes. It does not
prove that those bytes belong to the requested campaign boundary.

- **[SEC-1]** A restore or transfer receiver MUST authenticate the expected
  scoped `RamRootDigest` through the complete checkpoint or transfer contract
  before authorizing execution. It MUST verify page contents and tree
  relationships against that expected root. A page's `PageDigest`, or a store's
  representation `ContentId`, alone MUST NOT authorize resume.
- **[SEC-2]** Untrusted region inventories, tree records, page references, and
  backing descriptors MUST be validated before allocation or access. Validation
  MUST bound counts, sizes, depths, offsets, aggregate work, decompressed output
  when applicable, and outstanding requests. All offset arithmetic MUST reject
  overflow and out-of-range results. Duplicate or ambiguous ownership and
  noncanonical tree geometry MUST fail closed.

Ordered tree position commits to logical placement; content-addressed page
identity deliberately permits sharing identical bytes at different positions.
A receiver MUST reconstruct the specified ordered tree rather than treating a
set of valid pages as a complete memory image. Page substitution, region
reordering, changed logical lengths, wrong scope, and using the padding leaf as
a real zero page are different failures. Explicit zero-page representation is
permitted only with the canonical semantics in chapter 02. A missing object
MUST NOT be interpreted as a zero page.

## 9.2 Root authenticity, ownership, and availability

There are three separate relationships: immutable logical contents, the right
to retain their backing objects, and the availability of the service that can
materialize them. An authentic root can survive deletion of one of its pages;
it then becomes unusable, not unauthentic. A running VM can have a valid page
hash while its newest writable bytes exist only in resident memory. Therefore,
eviction requires stronger evidence than possession of a root.

- **[SEC-3]** Every reachable immutable root and active mutable backing version
  MUST have explicit lifetime ownership. Checkpoints, retained templates,
  children, transfers, pending reads, and unfinished publication MUST retain the
  necessary backing objects until their ownership ends. Garbage collection MUST
  NOT infer that a nonresident page is unused. Publication MUST establish durable
  child retention before exposing a durable root.
- **[SEC-4]** Eviction MUST preserve the newest logical page version before
  releasing the last authoritative resident copy. The completion receipt MUST
  bind the VM or backing owner, page coordinate, and content generation.
  Completion for an older generation MUST NOT mark a newer page clean. Read
  completion MUST likewise validate the requested generation before installation.

A mutable spill file is not automatically a content-addressed snapshot.
Checksums for that file need owner and generation binding so that an intact old
slot cannot be mistaken for the current page. Immutable pages fetched from the
checkpoint store require their canonical `PageDigest` and tree membership to be
validated. Physical storage records may aggregate many logical pages; their
independent representation authentication remains necessary and does not
replace logical authentication.

- **[SEC-5]** Pager or backing failure MUST produce a typed host operational
  failure. The implementation MUST NOT resolve a blocked access with zeroes,
  stale bytes, a guest-visible memory error, or an invented modeled device
  completion. Loss of backing authority MUST prevent resume. Cancellation and
  teardown MUST preserve outstanding ownership until no operation can install
  bytes or publish a root into a retired VM generation.

The timeout and cleanup contracts are defined in
[05-runtime-policy-and-supervision.md](05-runtime-policy-and-supervision.md).
An operator may choose a long permitted storage latency, but configuration
cannot make an unverified page usable. Pager availability is an infrastructure
prerequisite, not part of the guest's deterministic memory semantics.

## 9.3 Public process and license boundary

The repository requires Apache host code and QEMU/plugin code to remain separate
processes. Their integration uses versioned control and shared-memory protocols.
The normative obligations are [BOUND-4 through BOUND-9](../0010-crucible/37-licensing-process-boundary.md)
and [the licensing policy](../../legal/licensing.md). This RFC preserves them.

- **[SEC-6]** Code linked into, compiled into, or loaded by QEMU MUST remain in
  QEMU's applicable GPL-compatible scope. QEMU RAMBlock access, native mappings,
  mutable dirty structures, and QEMU callback ownership MUST remain process
  private. Apache-only crates MUST NOT depend on QEMU headers, QEMU libraries,
  callback entry points, or an Apache-only component loaded into QEMU.
- **[SEC-7]** Cross-process paging records MUST be public, versioned, and
  independently implementable. They MAY carry fixed-width identities, checked
  region-relative offsets, bounded byte payloads, sequence numbers, explicit
  ownership generations, and feature declarations. They MUST NOT carry native
  pointers, RAMBlock structures, function tables, native Rust enum layouts, or
  ownership of a mutable process-private tree. Byte layout, atomic ordering,
  cancellation, stale-completion handling, and failure semantics MUST be
  specified and covered by independent C/Rust vectors.

The simplest ownership split places QEMU mapping and fault handling on the GPL
side and gives the host documented storage requests addressed by identity and
offset. An external Apache pager that directly consumes a userfaultfd descriptor
would introduce kernel-mediated fault messages and native virtual-address
semantics. Such a design requires explicit license-boundary and protocol review;
existing descriptor transfer during setup does not automatically approve that
new integration. Review must identify which process interprets an address, which
process owns mutable mapping state, and how this fits the permitted public
integration surfaces. No implementation may silently broaden those surfaces.

The public process boundary remains hot shared memory and cold socket control.
Paging MUST NOT turn routine scheduling into serialized socket exchanges merely
to avoid documenting a new public data record. Conversely, a local pager
implementation detail need not become shared-memory state merely because both
processes need operational metrics.

- **[SEC-8]** Boundary changes MUST pass `gate:abi-conformance` and
  `gate:license-boundary`. New or removed QEMU files MUST update
  `pkgs/emulation/qemu-patches/LICENSES.md`. Release artifacts containing patched
  QEMU MUST co-retain matching complete corresponding source through the
  Crucible suite publication policy. A raw QEMU, plugin, or wrapper root MUST
  NOT bypass that policy.

## 9.4 Host prerequisites and resource containment

Kernel mechanisms are capabilities that must be established on the deployed
host. Compile-time header availability is insufficient. A custom pager must
negotiate the userfaultfd operations and mapping modes actually supported, probe
the required behavior, and treat denied access as a host admission failure.
Support for newer write-protection, asynchronous tracking, fork, or mapping
features MUST NOT be assumed from a generic claim that userfaultfd exists.

- **[SEC-9]** Each backend MUST declare its kernel, filesystem, and permission
  prerequisites. Startup MUST verify them without weakening host security
  policy. Required cgroup delegation, swap backing, fault permissions, descriptor
  limits, mapping limits, filesystem guarantees, and storage capacity MUST be
  checked. Unsupported configurations MUST be rejected with a precise host-side
  reason before guest execution or explicit activation of that backend.

The kernel-swap path requires real usable swap and applicable cgroup memory
controls. The custom pager requires emergency memory for its own buffers,
metadata, queues, control operations, and recovery. Resource accounting must
also cover page cache and shared pages; reclaim advice is not proof of achieved
residency. Configuration MUST NOT place the pager in a cycle where reading a
guest page requires reclaiming the same page or allocating from an exhausted
budget with no reserved progress capacity.

An admission probe must not require global sysctl changes or privileged daemon
reconfiguration as a hidden side effect. Operators can configure prerequisites
through normal system administration. A backend that cannot operate under the
approved configuration remains unavailable. Automatic fallback is permitted only
when explicitly selected by policy, semantically equivalent, and admitted under
its own resources; it MUST NOT erase dirty epochs or conceal missing backing.

## 9.5 Confidentiality and persistence of guest bytes

Spilling guest RAM changes where secrets live. Credentials, application data,
decrypted disk contents, and kernel state may appear in local backing files,
host swap, filesystem cache, remote objects, retained templates, and crash
diagnostics. A content digest exposes equality and may allow guessing low-entropy
contents. Deduplication and data-access statistics can reveal workload
relationships even without returning page bytes.

- **[SEC-10]** Paging storage MUST follow the campaign's access-control and
  confidentiality policy. Private local spill objects MUST use restrictive
  ownership and permissions, verified descriptors, and private namespaces.
  Path substitution, aliasing, unsafe reopening, and descriptor reuse across VM
  generations MUST be rejected. Remote page access MUST authenticate the caller
  and transport according to the selected store policy.
- **[SEC-11]** The implementation MUST state whether each storage path encrypts
  RAM at rest. Host swap encryption MUST NOT be implied by encrypted checkpoint
  storage, nor vice versa. Cross-tenant deduplication MUST require an explicit
  security decision. Logs, metrics, and diagnostics MUST NOT expose raw RAM,
  secret-bearing byte previews, or sensitive backing locations by default.

Encryption does not change logical `PageDigest` or `RamRootDigest` semantics;
encrypted representation authentication belongs to the storage layer. Rotation,
retention and key loss must be considered together with leases. A root retained
after losing its decryption key is unavailable and cannot be resumed.

Read amplification is also a confidentiality and denial-of-service concern. A
bounded request for one page MUST NOT materialize an unbounded region or leak
unrelated guest bytes. Prefetch, metadata caches and transfer batches require
explicit bounds. Cancellation must release cached plaintext according to the
storage policy. Deleting a file or dropping a lease does not guarantee secure
erasure on copy-on-write filesystems, SSDs, shared caches, or backup systems;
the retention policy must describe actual guarantees rather than promise
physical erasure from ordinary unlink operations.

## 9.6 Coordinated experimental cutover

This RFC intentionally selects an immediate coordinated experimental cutover.
The new release has one authoritative RAM algorithm and one current execution
contract. Backward-compatible readers, converters, legacy launch paths, and
production dual-algorithm support are not requirements and MUST NOT be added
solely to preserve the previous experimental formats.

- **[CUT-1]** The cutover MUST reject old peers, old RAM digest semantics, and old
  checkpoint or replay authority before executing guest instructions. A 32-byte
  field with unchanged layout is not semantic compatibility. Any incompatible
  shared-memory semantics MUST bump the applicable ABI major; additions require
  explicit version or feature declarations.
- **[CUT-2]** Retained templates and already-running processes from the previous
  build MUST NOT be adopted or resumed in place under the new build. Distributed
  workers MUST advertise the complete current contract capability and reject
  assignments they cannot satisfy. Mixed release sets MUST fail admission.
- **[CUT-3]** Cutover MUST NOT automatically delete prior experimental artifacts.
  They may remain archived or inspectable through their original build outside
  the new runtime authority. The new release MUST NOT silently reinterpret or
  convert them. Cleanup is a separate operator action under normal retention
  rules.

The implementation review must enumerate every affected version, including
unchanged schemas whose contents incorporate changed identities. The following
table is a current-source inventory, not a promise of exact future version
numbers. The release MUST allocate and record one consistent new version set.

| Surface | Current source contract | Cutover obligation |
|---|---|---|
| Logical RAM digests | Flat writable-RAM SHA-256 domain `crucible.qemu.guest-ram.v1` | Adopt chapter 02's unkeyed BLAKE3-256 scoped Merkle schema and bind its version and coverage. |
| Production fingerprint | `crucible.qemu.black-box-execution-fingerprint.v1` | Change domain and define the RAM scope; never relabel an old digest. |
| Harness fingerprint | Definition v2; full-memory algorithm v1 | Replace definition and algorithm identity together. |
| Trace plugin | Trace-fingerprint v7 | Version fields and aggregate semantics containing the new RAM root. |
| Shared/control protocol | Shared-memory ABI 30; control protocol 3 | Bump changed semantics and negotiate new records before mapping or execution. |
| Instruction/hardware evidence | `CRUCIEV1`, `crucible.instruction-state.v1`, before/after full RAM SHA-256 | Version evidence, system digest and selectors/preconditions that name them. |
| Lifecycle evidence | `CRUCLFS1` with full-RAM FNV contribution | Version snapshot semantics and affected precondition/result evidence. |
| Memory mutation evidence | Separate mapping, translation, dirty and range-content contracts | Preserve valid unchanged meanings; version any changed scope or generation semantics. |
| QMP checkpoint | Schema 2; CRUCRAM direct/delta representation | Replace or version the RAM representation and validate full identity bindings. |
| Portable exact closure | Closure v9, root envelope v5, production objects v5, index v1 | Version the manifest/representation and every enclosing semantic contract affected. |
| Hot-fork protocol | Multiple template, barrier, resource and child-runtime schemas | Inventory changes for pager/tree ownership and quiescence; bump affected schemas. |
| Worker/replay authority | Pinned build, ABI inventory, exact closure and guarded comparison | Bind the new RAM contract; expire incompatible process-local authority. |

Sources for this inventory are listed in
[01-current-system-and-integration.md](01-current-system-and-integration.md).
The current instruction evidence verifies combined state digests independently
on both sides; both implementations and canonical vectors must change together.
Serialized artifact SHA-256 and CAS `ContentId` remain representation
authentication and MUST NOT be replaced by a logical root without a new
specified representation contract.

- **[CUT-4]** The coordinated release MUST update public specifications,
  generated language views, canonical vectors, package identities, reproduction
  metadata, worker capability checks, retained-template admissions and
  corresponding-source artifacts as one reviewed contract set. Tests MUST
  demonstrate early rejection for every intentionally unsupported predecessor.

There is no requirement to compute the previous flat digest during production
execution. The independent full-Merkle oracle in
[10-validation-and-performance.md](10-validation-and-performance.md) validates
the new construction directly and remains mandatory. Compatibility deletion
does not remove determinism, authentication, or validation obligations.
