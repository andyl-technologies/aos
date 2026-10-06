# RFC-0021: Crucible host-paged RAM and persistent memory identity

- **Status:** Proposed (design only; no implementation implied)
- **Date:** 2026-10-05
- **Source baseline:** `9d8ab78dff67348bbb38e2eda609eca67e413561`
- **Related designs:** RFC-0010, RFC-0014, RFC-0020

## Abstract

Crucible executes unmodified guest machines using a deterministic QEMU TCG
profile. Today each machine reserves its configured guest RAM, and several
observation paths scan complete RAM contents. That combination limits parallel
campaign density even when guest working sets are small. This RFC separates
logical guest memory from host residency, makes memory identity incremental,
and defines ownership of memory across execution, retained hot sources,
children, exact checkpoints, and transfer.

The proposal uses stable virtual mappings, content-authenticated logical pages,
ordered persistent BLAKE3-256 Merkle trees, complete boundary write tracking,
and an explicit host pager. A kernel-managed swap backend supplies a simpler measured
baseline; a custom backend supplies precise per-machine policy. Residency and
reclamation policy can change during execution without changing modeled guest
time or deterministic state identity. Infrastructure timeouts become separately
supervised operations with bounded progress and completion policies.

The same immutable page identities and dirty epochs enable cheap hot-fork
baselines, direct root-based checkpoints, authenticated local lazy restore,
and bounded transfer of missing pages and subtrees. These capabilities share
foundations but have separate release gates. Remote demand paging and live
migration are not prerequisites for local paging or archive transfer.

The initial paused-only pager requires a sound inter-boundary peak reservation
and physical-access lifetime proof. Smaller guaranteed execution footprints
remain gated on independently progressing reclamation that preserves interrupt,
scheduler, and timer ordering. Existing simulated faults remain compatible with
cold RAM and atomic mutation transactions; continuous reference/fault RAM images
are deferred. Infrastructure phases retain finite supervision, and outer-cap
changes use separate revisioned operational transactions. Archive storage
receipts are distinct from restore readiness and execution handoff authority.

## Document status and terminology

This is a repository design record, not an IETF submission. Uppercase MUST,
MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT
RECOMMENDED, MAY, and OPTIONAL have the meanings assigned by
[BCP 14](https://www.rfc-editor.org/rfc/rfc2119.html), subject to the uppercase
convention in [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html).
Lowercase uses are ordinary prose. Numbered requirement identifiers provide
stable review and acceptance-test references within this proposed edition.

Statements explicitly described as *current*, *baseline*, or *informative*
describe the source revision above. Requirements and schemas describe proposed
behavior. A source link demonstrates an integration point; it does not prove
that its proposed replacement already exists. Chapter 02 is authoritative for
logical memory encoding; physical object and protocol encodings belong to the
versioned implementation contracts identified in chapters 07–09.

Crucible remains experimental. Deployment makes one coordinated cutover to
the new protocol, fingerprint, checkpoint, and runtime-policy contracts.
Old formats and mixed peers are rejected. There is no compatibility reader,
converter, automatic digest translation, or production dual-algorithm period.
Existing artifacts are not automatically deleted. Implementation phases may
be developed separately, but incompatible pieces MUST NOT be deployed as a
partially upgraded production combination.

## Reading guide

| Chapter | Subject |
| --- | --- |
| [00](00-goals-and-invariants.md) | Goals, non-goals, guest transparency, conformance, terminology |
| [01](01-current-system-and-integration.md) | Current behavior and source integration map |
| [02](02-logical-ram-and-merkle-format.md) | Logical topology, scopes, exact digest construction, test vectors |
| [03](03-write-tracking-and-fingerprints.md) | Writer completeness, dirty epochs, immutable captures, observation |
| [04](04-host-paging.md) | Backend choice, fault service, eviction states, kernel prerequisites |
| [05](05-runtime-policy-and-supervision.md) | Runtime controls, resource transactions, operation deadlines |
| [06](06-hot-fork-and-lifecycle.md) | Source seals, child reconstruction, pager rebinding, lifetime ownership |
| [07](07-checkpoints-and-storage.md) | Direct logical checkpoints, durable objects, scalable indices, restore |
| [08](08-state-transfer.md) | Authenticated root differences, retention, cancellation, publication |
| [09](09-security-and-cutover.md) | Trust, process/license boundary, version registry, coordinated cutover |
| [10](10-validation-and-performance.md) | Independent oracles, adversarial acceptance, measured budgets |
| [11](11-implementation-plan.md) | Work packages, dependency graph, stop/go evidence |
| [12](12-decisions-and-open-questions.md) | Decisions, alternatives, unresolved deployment choices |
| [13](13-references.md) | Repository and external reference documents |

The companion [format vectors](format-vectors.json) are machine-readable
examples of chapter 02's logical encoding. They are documentation fixtures,
not a claim that a production implementation passes them.

## Principal conclusions

Use `mmap` for stable address space and fault integration, with explicit
host-side preservation and reclamation for precise control. Mapping a file
alone does not supply per-VM residency guarantees or fork-safe writable RAM.
Use a persistent Merkle digest for RAM observations, with page-content identity
separate from storage-object identity. Share complete write tracking between
consumers while keeping each consumer's epoch and lifetime independent.

Physical residency is operational state. Logical page contents, machine state,
and virtual-time progression remain deterministic. A stalled backing store
delays host completion; it never changes the guest's modeled memory latency.
Failures are typed host failures and do not become guest findings.

All relevant foundations change together: admission, launch, dirty tracking,
fingerprints, fork barriers, checkpoint schemas, content storage, transfer,
supervision, host capability checks, and protocol versions. Acceptance requires
both an independent logical-state oracle and proof that the real adversarial
paths were exercised.
