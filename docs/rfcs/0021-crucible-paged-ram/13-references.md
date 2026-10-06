# 13 - References

## 13.1 Normative repository policies and related designs

Repository policies apply independently of this proposal's status.

- [AOS build and contribution instructions](../../../AGENTS.md): hermetic
  source builds, QEMU process/license boundary, code and release obligations.
- [Licensing policy](../../legal/licensing.md): QEMU/GPL and Apache host
  separation, public protocol obligations, corresponding-source publication.
- [RFC-0010 licensing process boundary](../0010-crucible/37-licensing-process-boundary.md):
  normative boundary requirements and compatibility handling.
- [RFC-0010 Crucible](../0010-crucible/README.md): deterministic execution,
  boundary protocols, observations, checkpoints, supervision, and release gates.
- [RFC-0014 signal-driven fault model](../0014-signal-driven-fault-model/README.md):
  observations, fault state, and deterministic mutation semantics.
- [RFC-0020 campaigns](../0020-crucible-campaigns/README.md): distributed
  campaign ownership, exact continuation, adaptive exploration, retained
  sources, and hot forks.
- [QEMU patch license manifest](../../../pkgs/emulation/qemu-patches/LICENSES.md):
  per-file obligations for additions and removals on the QEMU side.

## 13.2 External standards and primary technical references

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and
  [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html): requirement language
  and the uppercase convention used in this repository proposal.
- [BLAKE3 specification, version 1.0.0](https://c2sp.org/BLAKE3@v1.0.0):
  normative hash construction, default unkeyed mode, and output semantics.
  Chapter 02 fixes the 32-byte output and distinct Crucible preimages.
- [Official BLAKE3 implementations](https://github.com/BLAKE3-team/BLAKE3),
  including [C](https://github.com/BLAKE3-team/BLAKE3/tree/master/c) and
  [Rust reference code](https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs):
  independent implementation and vector-verification references. Release builds
  MUST pin reviewed source versions. GPL-side inclusion MUST select and record
  an applicable GPL-compatible upstream license.
- [Linux userfaultfd documentation](https://docs.kernel.org/admin-guide/mm/userfaultfd.html):
  feature negotiation, missing-page and write-protection mechanisms, mapping
  modes, and security restrictions. Deployment tests must target the actual
  built and running kernel.
- [Linux cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html):
  memory/swap controls, ownership, protection, accounting, and pressure.
- [Linux `userfaultfd(2)`](https://man7.org/linux/man-pages/man2/userfaultfd.2.html):
  kernel versus user-mode faults, descriptors, events, and failure behavior.
- [Linux `mmap(2)`](https://man7.org/linux/man-pages/man2/mmap.2.html): private
  and shared mappings, address space, and lifetime semantics.
- [Linux `madvise(2)`](https://man7.org/linux/man-pages/man2/madvise.2.html):
  reclamation/advice behavior, fork disposition, and host capability constraints.
- [Linux `process_madvise(2)`](https://man7.org/linux/man-pages/man2/process_madvise.2.html):
  restricted remote advice set; remote `MADV_DONTNEED` is not supplied by this interface.
- [Linux `UFFDIO_MOVE(2const)`](https://man7.org/linux/man-pages/man2/UFFDIO_MOVE.2const.html):
  move semantics and pinned/exclusive-page constraints, including fork-COW sharing.
- [Linux `mlock(2)`](https://man7.org/linux/man-pages/man2/mlock.2.html):
  residency locking, privileges/limits, and noninheritance of locks across fork.
- [Linux `ioctl_ficlone(2)`](https://man7.org/linux/man-pages/man2/ioctl_ficlone.2.html):
  filesystem-supported COW cloning; not an implicit QEMU mapping transaction.
- [QEMU memory API](https://www.qemu.org/docs/master/devel/memory.html):
  RAM regions, aliases, DMA mappings, dirty tracking, and caller ownership.
- [QEMU TCG instruction counting](https://www.qemu.org/docs/master/devel/tcg-icount.html):
  instruction-counted time and execution constraints.
- [QEMU invocation](https://www.qemu.org/docs/master/system/invocation.html):
  memory-backend and machine launch interfaces.
- [QEMU VM templating](https://www.qemu.org/docs/master/system/vm-templating.html):
  memory sharing/COW options and their limitations.

Upstream `master` documentation is an explanatory reference, not a promise of
feature availability in the patched QEMU version. The checked-in patch and
capability tests against the release build control actual behavior.

## 13.3 Source baseline

The [integration map](01-current-system-and-integration.md) and consumer
chapters link the relevant implementation. They were researched against
`9d8ab78dff67348bbb38e2eda609eca67e413561` and are informative historical
references. Particularly important evidence includes:

- [Atomic QEMU integration patch](../../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch):
  memory observers, dirty clients, pre-save ordering, restore writes, fork
  barriers, mapping disposition, and child reconstruction.
- [Guest launch](../../../crates/crucible-qemu/src/launch.rs) and
  [cgroups](../../../crates/crucible-qemu/src/linux_cgroup.rs): present anonymous
  memory setup, deterministic timing profile, and disabled attempt swap.
- [Exact checkpoint closure](../../../crates/crucible/src/exact_checkpoint.rs):
  complete machine continuation and present direct/delta layer rules.
- [CAS storage](../../../crates/crucible-cas/src/content_store.rs),
  [packing](../../../crates/crucible-cas/src/content_store/packed.rs), and
  [envelopes](../../../crates/crucible-cas/src/content_envelope.rs): existing
  canonical serialized object identity, indices, limits, and closure ownership.
- [Repository transfer](../../../crates/crucible-campaign/src/repository/transfer.rs):
  transfer planning, closure validation, and publication integration.
- [Campaign performance qualification](../../../tests/crucible/phase9-campaign-performance.nix):
  baseline approval remains blocked at this revision; no new performance result
  is asserted by this design record.

There are no IANA registrations requested by this RFC. New edition names,
protocol majors, object kinds, control opcodes, and capability identifiers
belong to the repository's implementation registry and coordinated release.
