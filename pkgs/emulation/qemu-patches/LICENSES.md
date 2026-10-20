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
| `include/hw/nvram/crucible-fwcfg-entry.h` | MIT | Preserves the original fw_cfg.c copyright/permission notice and explicit MIT identifier; native FW_CFG entry shape and ownership comparison. |
| `include/hw/nvram/crucible-fwcfg-directory.h` | GPL-2.0-or-later | Explicit SPDX notice; original native sorted-directory lineage validation. |
| `tests/unit/test-crucible-fwcfg-directory.c` | GPL-2.0-or-later | Explicit SPDX notice; ordinary unit registration exercises the production validator. |
| `plugins/whole-preparation.inc.c` | GPL-2.0-or-later | Explicit SPDX notice; original bounded stopped RR preparation. |
| `stubs/crucible-whole-early.c` | GPL-2.0-or-later | Explicit SPDX notice; refusing non-system arena/constructor providers. |
| `accel/tcg/crucible-node-preparation.c` | GPL-2.0-or-later | Explicit SPDX identifier |
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
| `include/qemu/crucible-node-service.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `hw/core/crucible-device-roots.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/hw/core/crucible-device-roots.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-node-root.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-endpoint-roots.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-endpoint-roots.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `util/crucible-endpoint-roots.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-timer-selection.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `util/crucible-timer-selection.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/kvm/crucible-construction.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-continuation.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-initialization.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-pic-handoff.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-pic-memory.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-pic-vm-setup.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-fd-original.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/kvm/crucible-q35-cpu-history.inc.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-q35-cpu-history-types.inc.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-q35-prevm-resource.inc.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-q35-prevm-resource-types.inc.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-q35-devices.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-q35-inactive-clock.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-q35-initial-routing.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-q35-memory.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-q35-vm-configuration.c` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-q35-workers.c` | GPL-2.0-only | Explicit SPDX identifier |
| `include/qemu/crucible-fd-custody.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/system/crucible-kvm-construction.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-continuation.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-initialization.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-pic-handoff.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-pic-memory.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-pic-vm-setup.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-q35-constructor-clock.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-q35-devices.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-q35-inactive-clock.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-q35-initial-routing.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-q35-launch.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-q35-memory.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-q35-vm-configuration.h` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-q35-workers.h` | GPL-2.0-only | Explicit SPDX identifier |
| `system/crucible-kvm-construction-stub.c` | GPL-2.0-only | Explicit SPDX identifier |
| `system/crucible-kvm-q35-constructor-clock.inc.c` | GPL-2.0-only | Explicit SPDX identifier |
| `system/crucible-kvm-q35-launch-codec.inc.c` | GPL-2.0-only | Explicit SPDX identifier |
| `system/crucible-kvm-q35-launch-owner.inc.c` | GPL-2.0-only | Explicit SPDX identifier |
| `system/crucible-kvm-q35-launch-stub.c` | GPL-2.0-only | Explicit SPDX identifier |
| `system/crucible-kvm-q35-launch.c` | GPL-2.0-only | Explicit SPDX identifier |
| `util/crucible-fd-custody.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/kvm/crucible-clock.c` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-clock.h` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-window.c` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-window.h` | GPL-2.0-only | Explicit SPDX identifier |
| `accel/kvm/crucible-response-bytes.c` | GPL-2.0-only | Explicit SPDX identifier |
| `include/system/crucible-kvm-response-bytes.h` | GPL-2.0-only | Explicit SPDX identifier |
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
| `tests/tcg/plugins/crucible-node-control.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/qtest/crucible-node-control.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/qtest/crucible-idle-wait-liveness.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/qtest/crucible-exact-tb-exit.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-hot-fork-child.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-child-file-refusal.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-aio-fork-custody.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-procfd-flags.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-net-output-stop.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-net-stop-chain.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-stop-context.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-tcg-fast-paths.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-mutex-owner-cache.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-mutex-waiter-counters.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-tcg-page-collection.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-tcg-crossing-membership.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-tsc-source-index.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/tcg/x86_64/system/self-modifying-code.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-snapshot-fast-path.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-settle-prepark.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-cold-fault-predicates.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-lazy-memory-identity.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-accel-classification.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-fault-rule-presence.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-rr-sim-barriers.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-control-deferred.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-control-observer.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-control-delivery.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-stopped-control-rearm.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-template-control-drain.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-lifecycle-projection.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-icount-rate.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-node-service.c` | GPL-2.0-or-later | Explicit SPDX identifier |
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
| `accel/tcg/crucible-effect-prefix.inc.c` | MIT | Explicit SPDX identifier |
| `accel/tcg/crucible-prefix-cpu-rr.inc.c` | MIT | Explicit SPDX identifier |
| `accel/tcg/crucible-prefix-policy.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/tcg/crucible-prefix-preparation-rr.inc.c` | MIT | Explicit SPDX identifier |
| `accel/tcg/crucible-prefix-quiet-rr.inc.c` | MIT | Explicit SPDX identifier |
| `accel/tcg/crucible-prefix-request-rr.inc.c` | MIT | Explicit SPDX identifier |
| `accel/tcg/crucible-prefix-request.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/tcg/crucible-prefix-root-rr.inc.c` | MIT | Explicit SPDX identifier |
| `accel/tcg/crucible-prefix-semantic.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/tcg/crucible-prefix-sim-callbacks.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/tcg/crucible-prefix-timer-rr.inc.c` | MIT | Explicit SPDX identifier |
| `accel/tcg/crucible-prefix-writer-rr.inc.c` | MIT | Explicit SPDX identifier |
| `block/crucible-prefix-block-callbacks.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `hw/9pfs/crucible-prefix-ninep-callbacks.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `hw/virtio/crucible-prefix-accelerator-callbacks.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-effect-prefix.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-prefix-active.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-prefix-callback-roots.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-prefix-cpu-ingress.h` | MIT | Explicit SPDX identifier |
| `include/qemu/crucible-prefix-plugin-core.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-prefix-policy.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-prefix-preparation.h` | MIT | Explicit SPDX identifier |
| `include/qemu/crucible-prefix-quiet.h` | MIT | Explicit SPDX identifier |
| `include/qemu/crucible-prefix-request.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-prefix-stopped.h` | MIT | Explicit SPDX identifier |
| `accel/tcg/crucible-prefix-stopped-rr.inc.c` | MIT | Explicit SPDX identifier |
| `include/qemu/crucible-prefix-semantic.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-prefix-timer.h` | MIT | Explicit SPDX identifier |
| `include/qemu/crucible-prefix-writer.h` | MIT | Explicit SPDX identifier |
| `include/qemu/crucible-utility-census-internal.h` | MIT | Explicit SPDX identifier |
| `net/crucible-prefix-net-callbacks.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-prefix-callback-roots.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-prefix-plugin-core.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-prefix-coordinator.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `util/crucible-prefix-timer.inc.c` | MIT | Explicit SPDX identifier |
| `util/crucible-utility-construction.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |

| `accel/tcg/crucible-effect-root-rr.inc.c` | MIT | Explicit SPDX identifier |
| `accel/tcg/crucible-node-effect.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/tcg/crucible-semantic-input-owner.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-active-effect.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-installed-endpoint-owner.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-memory-payload-roots.h` | MIT | Explicit SPDX identifier |
| `include/qemu/crucible-memory-roots.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-node-effect.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-semantic-input-owner.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-service-finite.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-timer-finite.h` | MIT | Explicit SPDX identifier |
| `include/qom/crucible-constructor-retirement.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qom/crucible-property-roots.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `qom/crucible-constructor-retirement.inc` | GPL-2.0-or-later | Explicit SPDX identifier |
| `qom/crucible-property-link-roots.inc` | GPL-2.0-or-later | Explicit SPDX identifier |
| `qom/crucible-property-roots.inc` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-constructor-retirement.inc` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-installed-endpoint-owner.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-memory-dispatch-roots.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-memory-payload-roots.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-memory-roots.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `util/crucible-timer-finite.inc.c` | MIT | Explicit SPDX identifier |
| `plugins/stopped-install.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/stopped-install-system.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/stopped-startup.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/tcg/whole-grant-codec.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/tcg/whole-grant-service.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/tcg/whole-service-loop.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |

| `hw/core/crucible-whole-rom.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `hw/i386/crucible-whole-linux-input.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `hw/nvram/crucible-whole-fwcfg.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/hw/i386/crucible-whole-linux-input.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-sha256.h` | LGPL-2.1-or-later | Audited GLib SHA-256 primitive with original copyright and SPDX notices |
| `include/system/crucible-whole-early.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/whole-staged-source.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-device-endpoint-walk.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-whole-argv.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-whole-control.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-whole-early.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-whole-q35.inc.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/system/crucible-whole-ram.h` | GPL-2.0-or-later | Source-native RAM birth/retention declarations; SPDX notice. |
| `system/crucible-whole-ram.inc.c` | GPL-2.0-or-later | Source-native RAMBlock, original backing and retained dirty-directory custody; SPDX notice. |
| `qom/crucible-property-release.inc` | GPL-2.0-or-later | Original QOM finalizer/property-release native dispatch custody; SPDX notice. |
| `include/qemu/crucible-whole-callback-origin.h` | GPL-2.0-or-later | Hidden original callback/controller source identity; SPDX notice. |
| `plugins/whole-callback-origin.inc.c` | GPL-2.0-or-later | Selected original four-CPU VCPU callback origin observation; SPDX notice. |
| `hw/acpi/crucible-whole-storage.inc.c` | GPL-2.0-or-later | Explicit original ACPI builder source notice. |
| `hw/i386/crucible-whole-acpi.inc.c` | GPL-2.0-or-later | Explicit original ACPI builder source notice. |
| `include/hw/acpi/crucible-whole-storage.h` | GPL-2.0-or-later | Explicit original ACPI builder source notice. |
| `system/crucible-whole-memory-storage.inc.c` | GPL-2.0-or-later | Source-local retained constructor MemoryRegion/AddressSpace/FlatView storage and lifetime journal; SPDX notice. |
| `system/crucible-whole-dispatch-storage.inc.c` | GPL-2.0-or-later | Native retained dispatch/node/section/subpage constructor storage and attempted/completed retirement; SPDX notice. |
| `qom/crucible-instance-storage.inc` | GPL-2.0-or-later | Original finite-arena QOM instance/alignment backing and literal finalizer/free retirement; SPDX notice. |
| `qom/crucible-type-storage.inc` | GPL-2.0-or-later | Original finite-arena QOM type storage and source allocation lineage; SPDX notice. |
| `qom/crucible-class-frame.inc` | GPL-2.0-or-later | Original class initialization frames and retained callback lifetime; SPDX notice. |
| `qom/crucible-class-properties.inc` | GPL-2.0-or-later | Original class property storage and retained release lineage; SPDX notice. |
| `qom/crucible-class-defaults.inc` | GPL-2.0-or-later | Original class defaults and finite constructor storage; SPDX notice. |
| `qom/crucible-instance-properties.inc` | GPL-2.0-or-later | Original instance property storage and retained lifetime events; SPDX notice. |
| `tests/unit/crucible-inactive-device-stubs.c` | GPL-2.0-or-later | Explicit SPDX identifier; inactive setup/reset observers for isolated hwcore unit fixtures only. |

The separately built Rust `crucible-qemu-plugin` and C
`crucible-qemu-trace-plugin` carry explicit GPL-2.0-only notices. The generated
`crucible_shmem_abi.h` process-protocol header is `MIT OR Apache-2.0`; AOS
packages distribute and record it under the MIT option alongside QEMU.

When the atomic integration patch starts creating or deleting a file, update this inventory in the
same change. Preserve an explicit file notice and use QEMU's upstream `LICENSE`
to classify an unmarked file; do not infer a blanket license from the artifact
directory.
