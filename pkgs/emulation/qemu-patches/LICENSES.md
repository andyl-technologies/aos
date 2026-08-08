# QEMU patch-series license inventory

QEMU is GPL-2.0-only as a combined emulator. Individual source files retain
their own licenses. QEMU 10.0's `LICENSE` states that a source file without
licensing information is GPL-2.0-or-later unless it is in one of the listed
GPL-2.0-only directories. The Crucible patch series does not change an
existing file's license.

The series currently creates these QEMU source files:

| Created file | License | Basis |
| --- | --- | --- |
| `accel/tcg/tcg-accel-ops-sim.c` | GPL-2.0-or-later | QEMU default |
| `include/system/crucible-plugin-wake.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `block/crucible-shmem.c` | GPL-2.0-or-later | Explicit file notice |
| `accel/tcg/tcg-accel-ops-sim-shmem.c` | GPL-2.0-or-later | QEMU default |
| `accel/tcg/tcg-accel-ops-sim-shmem.h` | GPL-2.0-or-later | QEMU default |
| `include/system/crucible-sim-ipi.h` | GPL-2.0-or-later | QEMU default |
| `accel/tcg/tcg-accel-ops-preemption.c` | GPL-2.0-or-later | QEMU default |
| `include/system/crucible-sim-preemption.h` | GPL-2.0-or-later | QEMU default |
| `accel/tcg/crucible-translation-prefetch.c` | GPL-2.0-or-later | QEMU default |
| `include/qemu/crucible-fault.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-process.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-memory.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-node.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-memory.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-memory-access.c` | GPL-2.0-or-later | Explicit SPDX identifier |

The separately built Rust `crucible-qemu-plugin` and C
`crucible-qemu-trace-plugin` carry explicit GPL-2.0-only notices. The generated
`crucible_shmem_abi.h` process-protocol header is `MIT OR Apache-2.0`; AOS
packages distribute and record it under the MIT option alongside QEMU.

When a patch starts creating or deleting a file, update this inventory in the
same change. Preserve an explicit file notice and use QEMU's upstream `LICENSE`
to classify an unmarked file; do not infer a blanket license from the patch
directory.
