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
| `plugins/crucible-stop-context.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `target/arm/crucible-register.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `target/i386/crucible-register.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-register.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-instruction.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-exact-tb-exit.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-memory.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-memory-access.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-memory-dma.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-memory-service-restart-probe.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/plugins/crucible-idle-wait-liveness.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/qtest/crucible-idle-wait-liveness.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/qtest/crucible-exact-tb-exit.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-hot-fork-child.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-child-file-refusal.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-aio-fork-custody.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-procfd-flags.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-net-output-stop.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-net-stop-chain.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-stop-context.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-control-deferred.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-control-observer.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-control-delivery.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-stopped-control-rearm.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-template-control-drain.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-lifecycle-projection.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-icount-rate.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-vcpu-service-time.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-idle-wait.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-rr-halted-neighbor.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-mos6522-clock.c` | MIT | Explicit SPDX identifier |
| `net/slirp-time.h` | MIT | Explicit SPDX identifier |
| `target/xtensa/timer.h` | BSD-3-Clause | Explicit SPDX identifier |
| `tests/unit/test-crucible-i3c-timer.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-slirp-time.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-xtensa-timer.c` | GPL-2.0-or-later | Explicit SPDX identifier |
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
| `target/riscv/tcg/itrigger-timer.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/qtest/crucible-icount-migration.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-vfio-timer.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-vga-blink.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-rtc-calendar.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-nvme-phase.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-cxl-timestamp.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-xhci-microframe.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-hpet-phase.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-rc4030-period.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-riscv-cpc-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-mips-gic-migration.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-ptimer-wide-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-openrisc-wide-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-sparc-wide-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-mips-count-wide-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-s390-tod-wide-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `target/arm/gtimer.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-arm-timer-wide-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-hppa-timer-wide-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-loongarch-timer-wide-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-ppc-wide-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-apic-timer-wide-clock.c` | LGPL-2.1-or-later | Explicit SPDX identifier; includes the original LGPL APIC common body |
| `tests/unit/test-crucible-rtc-timer-wide-clock.c` | MIT | Explicit SPDX identifier; literal MC146818 RTC fixture preserves its MIT scope |
| `tests/unit/test-crucible-pit-timer-wide-clock.c` | MIT | Explicit SPDX identifier; literal 8254 timer fixture preserves its MIT scope |
| `tests/unit/test-crucible-serial-kbd-timer-wide-clock.c` | MIT | Explicit SPDX identifier; literal UART and keyboard timer fixtures preserve their MIT scope |
| `tests/unit/test-crucible-acpi-pm-wide-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-ich9-aux-wide-clock.c` | GPL-2.0-or-later | Explicit SPDX identifier |

The separately built Rust `crucible-qemu-plugin` and C
`crucible-qemu-trace-plugin` carry explicit GPL-2.0-only notices. The generated
`crucible_shmem_abi.h` process-protocol header is `MIT OR Apache-2.0`; AOS
packages distribute and record it under the MIT option alongside QEMU.

When the atomic integration patch starts creating or deleting a file, update this inventory in the
same change. Preserve an explicit file notice and use QEMU's upstream `LICENSE`
to classify an unmarked file; do not infer a blanket license from the artifact
directory.

## Test-only UART origin baseline

`tests/crucible/native/uart-origin-baseline.c` is GPL-2.0-only, as stated in its
SPDX header. The focused qualification builder copies it to
`tests/unit/test-crucible-uart-origin-baseline.c` in its temporary QEMU build
source. It includes the selected UART bodies and links native QEMU libraries;
it is not an Apache host component. This build-only addition does not change
the selected atomic patch inventory or install a patched emulator. The matching
complete corresponding-source artifact retains the fixture and its builder.

## Test-only plugin failed-exit unit

`tests/crucible/native/plugin-failed-exit.c` and
`tests/crucible/native/plugin-failed-exit-bodies.py` declare GPL-2.0-only.
The private builder copies the C fixture to
`tests/unit/test-crucible-plugin-failed-exit.c` and generates
`tests/unit/plugin-failed-exit-bodies.inc` from verbatim selected plugin and
runstate definitions, preserving their original QEMU file licenses. The
extractor reuses `block-wait-completion-bodies.py`, whose license is declared
below. These temporary test additions are absent from the atomic created-file
inventory. The builder retains evidence, not an emulator or Apache host library;
its complete matching corresponding-source artifact retains the fixtures,
extractor and recipe. External services are labeled, and subprocess exit checks
do not qualify a physical VM or the complete native runstate topology.

## Test-only joined block-wait unit

The private joined block-wait unit overlays these test-only files in its
temporary QEMU build tree. Each checked-in fixture declares GPL-2.0-only:

- `tests/crucible/native/block-wait-completion.c` is GPL-2.0-only and is copied
  to `tests/unit/block-wait-completion.c`.
- `tests/crucible/native/block-wait-completion.h` is GPL-2.0-only and is copied
  to `tests/unit/block-wait-completion.h`.
- `tests/crucible/native/block-wait-icount-provider.c` is GPL-2.0-only and is
  copied to `stubs/icount.c`.
- `tests/crucible/native/block-wait-completion-bodies.py` is GPL-2.0-only and
  generates `tests/unit/block-wait-completion-bodies.inc` from selected QEMU
  bodies.

The generated definitions preserve their selected QEMU source licenses.
`tests/crucible/native/block-wait-completion.nix` builds a private, non-distributable
loadable unit for the GPL-side Rust plugin tests, not a standalone emulator or
Apache host library. The unit uses explicit CPU, clock, and context providers;
it does not qualify a physical guest or the complete TCG loop. This unit is not
a publication root. Any distributed binary must retain the matching complete
corresponding-source artifact, including these fixtures and builder.
