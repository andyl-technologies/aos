# Atomic QEMU integration patch license inventory

QEMU is GPL-2.0-only as a combined emulator. Individual source files retain
their own licenses. QEMU 11.1.1's `LICENSE` states that a source file without
licensing information is GPL-2.0-or-later unless it is in one of the listed
GPL-2.0-only directories. The Crucible atomic integration patch does not change an
existing file's license.

The atomic integration patch creates these QEMU source files:

| Created file | License | Basis |
| --- | --- | --- |
| `accel/tcg/tcg-accel-ops-sim.c` | GPL-2.0-or-later | QEMU default |
| `include/system/crucible-plugin-wake.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `block/crucible-shmem.c` | GPL-2.0-or-later | Explicit file notice |
| `block/crucible-hot-fork-source.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/tcg/tcg-accel-ops-sim-shmem.c` | GPL-2.0-or-later | QEMU default |
| `accel/tcg/tcg-accel-ops-sim-shmem.h` | GPL-2.0-or-later | QEMU default |
| `include/system/crucible-sim-ipi.h` | GPL-2.0-or-later | QEMU default |
| `accel/tcg/tcg-accel-ops-preemption.c` | GPL-2.0-or-later | QEMU default |
| `include/system/crucible-sim-preemption.h` | GPL-2.0-or-later | QEMU default |
| `include/qemu/crucible-fault.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-process.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-hot-fork-child.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-hot-fork-plugin.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/system/crucible-hot-fork-plugin-child.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-hot-fork-async.h` | GPL-2.0-or-later | Explicit file notice |
| `include/qemu/crucible-idle-wait.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-memory.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-node.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-register.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-instruction.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-interrupt.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-hardware-error.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-vcpu-service.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-lifecycle.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-vmstate.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-accelerator.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-idle-wait.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `target/arm/crucible-register.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `target/i386/crucible-register.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-register.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-instruction.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-exact-tb-exit.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-memory.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-memory-access.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-memory-service-restart-probe.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-memory-dma.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-idle-wait-liveness.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/qtest/crucible-idle-wait-liveness.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/qtest/crucible-exact-tb-exit.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-hot-fork-child.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-idle-wait.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `util/crucible-hot-fork-child.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-hot-fork-plugin-child.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/system/crucible-hot-fork-coordinator.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-hot-fork-coordinator.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-hot-fork-coordinator.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/hw/virtio/virtio-crucible-accelerator.h` | GPL-2.0-or-later | Explicit file notice |
| `hw/virtio/virtio-crucible-accelerator.c` | GPL-2.0-or-later | Explicit file notice |
| `hw/virtio/virtio-crucible-accelerator-pci.c` | GPL-2.0-or-later | Explicit file notice |
| `include/system/crucible-checkpoint.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-checkpoint.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-checkpoint-restore.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `hw/ide/ich-fingerprint.h` | LGPL-2.1-or-later | Explicit SPDX identifier |
| `hw/display/vga-fingerprint.h` | MIT | Explicit SPDX identifier |
| `hw/block/fdc-fingerprint.h` | MIT | Explicit SPDX identifier |
| `hw/net/e1000-fingerprint.h` | LGPL-2.1-or-later | Explicit SPDX identifier |
| `include/hw/char/parallel-isa-fingerprint.h` | MIT | Explicit SPDX identifier |
| `include/hw/acpi/generic-event-device-fingerprint.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/hw/acpi/piix4-fingerprint.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/hw/southbridge/piix-fingerprint.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `hw/isa/lpc-ich9-fingerprint.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `target/arm/crucible-fingerprint.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `target/i386/crucible-fingerprint.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/qtest/crucible-fingerprint-projection.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/qtest/crucible-multiboot-gap.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-fingerprint-observer.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-ahci-fingerprint.c` | LGPL-2.1-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-arm-fingerprint.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-acpi-piix-fingerprint.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-x86-fingerprint.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-vga-fingerprint.c` | MIT | Explicit SPDX identifier |
| `tests/unit/test-crucible-fdc-fingerprint.c` | MIT | Explicit SPDX identifier |
| `tests/unit/test-crucible-e1000-fingerprint.c` | LGPL-2.1-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-parallel-fingerprint.c` | MIT | Explicit SPDX identifier |

The separately built Rust `crucible-qemu-plugin` and C
`crucible-qemu-trace-plugin` carry explicit GPL-2.0-only notices. The generated
`crucible_shmem_abi.h` process-protocol header is `MIT OR Apache-2.0`; AOS
packages distribute and record it under the MIT option alongside QEMU.

When the atomic integration patch starts creating or deleting a file, update this inventory in the
same change. Preserve an explicit file notice and use QEMU's upstream `LICENSE`
to classify an unmarked file; do not infer a blanket license from the artifact
directory.
