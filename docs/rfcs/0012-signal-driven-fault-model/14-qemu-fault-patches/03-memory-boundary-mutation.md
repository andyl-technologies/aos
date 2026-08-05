# Patch 0049 — `crucible-memory-boundary-mutate`

## Purpose

Adds exact-boundary impulse mutation of guest RAM by guest physical address or
pre-resolved guest virtual address. It is the live backend for
`memory.mutation`; it does not implement persistent access transforms, MMIO
mutation, or debugger writes.

## Capability and dependencies

- Provides `qemu.memory.mutate.gpa.v1` on both architectures.
- Provides `qemu.memory.mutate.gva.x86_64.v1` and
  `qemu.memory.mutate.gva.aarch64.v1` only with exact translation evidence.
- Depends on 0047–0048 and existing raw-state/dirty-tracking facilities.

## Command payload

Required fields: address space (`gpa` or `gva`), vCPU/address-space context for
GVA, address, length, transform (`bit_flip` or `replace`), byte mask or
replacement bytes, atomicity (`all_or_nothing`), expected before digest, and
expected translation digest for GVA. Length is positive and bounded by the
[resource contract](../13-resource-and-performance-bounds.md).

Bit numbering is little-endian within each addressed byte: bit zero is the least
significant bit. Byte order is increasing guest address. Replace mask selects
bytes/bits; unselected bits remain unchanged.

## Address resolution

GPA mutation accepts only normal guest RAM or explicitly supported device-memory
RAM regions. ROM, MMIO, aliases with ambiguous ownership, unmapped holes, and
host pointers are rejected. The result records MemoryRegion identity, RAMBlock
identity, offset, length, and mapping generation.

GVA mutation walks the selected vCPU's architecture page tables at the safe
boundary using QEMU's architecture translation machinery. It records each
virtual page, resolved GPA, permissions, page size, and translation-generation
digest. Cross-page ranges are split; any failed/disallowed page rejects the
entire all-or-nothing command before mutation.

## Atomic mutation

QEMU resolves every fragment, reads and hashes all before bytes, validates the
precondition, constructs all after bytes, then writes fragments under the safe
boundary. On any failure before commit, no byte changes. A failure during commit
is an internal fatal error because the patch must prove its RAM writes cannot
partially fail after validation.

The patch uses QEMU RAM APIs that notify dirty tracking, migration, code/TB
invalidation, IOMMU/address-space listeners where required, and device memory
observers. Executable-page mutation invalidates affected translated blocks before
guest execution resumes. The mutation cannot target QEMU host memory.

## Composition and evidence

Same-boundary overlapping commands apply in canonical effect order. Each command
validates the before digest visible after earlier commands and records before and
after bytes/digests. Locked replay supplies the expected intermediate digest.

Evidence includes translations, region IDs, before/after bytes when within
inline limit or content hashes otherwise, dirty-page set, invalidated TB range,
icount, vCPU context, and node fingerprint.

## VMState

Applied RAM changes flow through ordinary RAM/dirty snapshot state. Pending
commands are serialized by patch 0059. No separate mutation shadow memory exists.

## Live microtests

1. x86-64 and AArch64 guests verify GPA and GVA bit flips/replacements in data,
   cross-page data, and executable code followed by TB invalidation.
2. Verify unmapped, ROM, MMIO, permission, translation-digest, before-digest,
   overflow, zero-length, and over-limit failures leave all bytes unchanged.
3. Apply overlapping commands in permuted submission order and verify canonical
   intermediate/final bytes.
4. Save before/after mutation and prove restore/fingerprint equivalence.
5. Revert patch and prove capability/mutation live gate fails.
6. Compare non-sim patched and unpatched QEMU.

## Licensing checklist

All QEMU memory-system changes are GPL-side and inert outside armed sim-fault
mode. The Apache host sees only public addresses, bytes, IDs, and hashes. QEMU
types/MemoryRegion pointers never cross shared memory. Modified-file notices,
new-file inventory, DCO, catalog, and corresponding source update together.

- **[QFP-MEM-1]** An acknowledged all-or-nothing mutation MUST change exactly
  the recorded bits and all required dirty/TB state, or the run fails fatally.
- **[QFP-MEM-2]** GVA locked replay MUST verify identical page translation before
  applying bytes.
