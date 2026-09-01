# 0098 - Inactive nested TSC guard

## Purpose

Patch `0098` restores inactive-path parity for x86 SVM entry and exit. The
guest-clock discontinuity hook already returns immediately for an inactive TSC
fault source, but C evaluates its `cpu_get_tsc()` arguments first. That virtual
clock read can account the current virtualization instruction before QEMU
restores exception state, producing a negative one-instruction delta.

SVM now checks source activity before sampling either old or new TSC values.
With no configured TSC fault it performs only QEMU's native offset load or
clear. Active clock faults retain the full continuity rebase.

## Canonicality contract

Inactive guest-clock support must not sample time, mutate fault state, or alter
instruction accounting at nested entry and exit. An active TSC source continues
to preserve its modeled value across offset discontinuities.

## Files and license scope

The patch modifies GPL-side `target/i386/tcg/system/svm_helper.c`. It changes no
shared-memory or control wire format and adds no QEMU file.

## Required gates

1. The x86 nested stage-1 and stage-2 page-table cases must complete without an
   icount assertion.
2. Active and inactive guest-clock gates must remain green.
3. The complete memory-access, checkpoint/restore, ABI, provenance, and
   license-boundary gates must pass.

- **[CLOCK-SVM-INERT-1]** Inactive TSC fault support MUST NOT read the virtual
  clock during SVM entry or exit.
- **[CLOCK-SVM-INERT-2]** Active TSC faults MUST preserve continuity across the
  nested TSC-offset transition.

The live nested guest is itself architecturally complete: its saved EFER sets
SVME, its nested-page-table hierarchy permits the user-indexed translation
used by QEMU's SVM walker, and its VMCB segment attributes use AMD's packed
attribute layout. These conditions ensure that both gates enter the L2 guest
and observe the intended descriptor instead of accepting an early
`SVM_EXIT_ERR`, nested page fault, or shutdown.
