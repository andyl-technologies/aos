# Atomic QEMU integration patch license inventory

QEMU is GPL-2.0-only as a combined emulator. Individual source files retain
their own licenses. QEMU 11.1.1's `LICENSE` states that a source file without
licensing information is GPL-2.0-or-later unless it is in one of the listed
GPL-2.0-only directories. The Crucible atomic integration patch does not change an
existing file's license.

The atomic integration patch creates these QEMU source files:

| Created file | License | Basis |
| --- | --- | --- |
| `docs/devel/crucible-ram-reader-custody.rst` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-ram-reader.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-ram-reader-custody.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `docs/devel/crucible-pending-quantum-constructor-proposal.rst` | GPL-2.0-or-later | QEMU default |
| `plugins/crucible-pending-constructor.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-pending-constructor.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `docs/devel/crucible-pending-quantum-lender.rst` | GPL-2.0-or-later | QEMU default |
| `docs/devel/crucible-pending-quantum-offer.rst` | GPL-2.0-or-later | QEMU default |
| `plugins/crucible-pending-command.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-pending-offer.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-preexec-publisher-offer.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-pending-command.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-pending-offer.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `docs/devel/crucible-advance-receiver.rst` | GPL-2.0-or-later | QEMU default |
| `docs/devel/crucible-quantum-handoff-proposal.rst` | GPL-2.0-or-later | QEMU default |
| `plugins/crucible-advance-receiver.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-native-initial-read.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-preexec-publisher-recipient.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-advance-content.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-advance-post-refusal.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-advance-recipient-leaves.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-advance-registration.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-initial-native-read.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-publisher-initial-state.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `docs/devel/crucible-apic-getter.rst` | GPL-2.0-or-later | QEMU default |
| `docs/devel/crucible-fault-retirement.rst` | GPL-2.0-or-later | Explicit SPDX identifier |
| `docs/devel/crucible-publisher-construction.rst` | GPL-2.0-or-later | Explicit SPDX identifier |
| `docs/devel/crucible-publisher-subscription.rst` | GPL-2.0-or-later | Explicit SPDX identifier |
| `hw/intc/crucible-apic-getter.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-apic-getter.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-clock-custody.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-publisher-protocol.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qobject/qobject-lifetime.h` | LGPL-2.1-or-later | Explicit SPDX identifier |
| `plugins/crucible-apic-getter.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-clock-custody.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-envelope.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `qobject/qobject-lifetime.inc.h` | LGPL-2.1-or-later | Explicit SPDX identifier |
| `stubs/crucible-clock-custody.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-preexec-publisher-session.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-preexec-publisher-storage.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-action-edge-post.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-apic-getter-custody.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-apic-getter-errors.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-apic-timer-storage.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-clock-callback-custody.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-clock-canonical-rows.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-clock-storage-return.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-flatview-custody.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-memory-discard-custody.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-memory-region-custody.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-provider-metadata.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-publisher-member-return.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-publisher-protocol.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-shmem-callback-return.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-cached-writer-memory.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/extract-crucible-cached-writer.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/run-crucible-cached-writer.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-cached-writer.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-native-invocation.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-callback-child.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-callback-groups.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-callback-owner.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-callback-publication.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-command-receive.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-action-original.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-initial-cpu.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-initial-cpu-fixture.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-hardware-catalogue.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-interrupt-catalogue.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-arm-register-preflight.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/hw/core/crucible-register-helpers.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-register-description.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-register-workspace.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-initial-register.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-register-workspace.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-register-workspace.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-fault-registration.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-registration.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-pending.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-fault-storage.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-fault-storage.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-fault-node-live-fixture.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-fault-node-event-fixture.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-fault-command-restore-fixture.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-fault-manifest-live-fixture.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-fault-node-restore-fixture.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/system/crucible-quantum-execution.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-quantum-execution.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-fault-node-live-main.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-fault-node-live.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-fault-registration.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-initial-manifest-refusal.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-publisher-subscription.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-action-original-fixture.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-publisher-subscription-fixture.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-action-original.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-command-membership.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-native-invocation.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-device-workspace.h` | GPL-2.0-or-later | Explicit SPDX identifier; fixed workspace and original startup wire declarations |
| `plugins/crucible-device-workspace.c` | GPL-2.0-or-later | Explicit SPDX identifier; bounded wire and sealed descriptor decoding |
| `plugins/crucible-device-workspace.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier; Source-owned physical workspace mapping custody |
| `plugins/crucible-fingerprint-worker.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier; Source-owned worker, material and physical byte custody |
| `plugins/crucible-plugin-worker.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier; shared native worker physical lifetime |
| `plugins/crucible-required-workers.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier; required RUN and teardown worker ownership |
| `plugins/crucible-startup-source.c` | GPL-2.0-or-later | Explicit SPDX identifier; original installer deadline, cancellation, and retained custody |
| `plugins/crucible-startup-source.h` | GPL-2.0-or-later | Explicit SPDX identifier; private native startup control declarations |
| `tests/unit/extract-crucible-startup-source-controls.py` | GPL-2.0-or-later | Explicit SPDX identifier; literal production-body control extraction |
| `tests/unit/extract-crucible-x86-table-projection.py` | GPL-2.0-or-later | Explicit SPDX identifier; literal descriptor-table projection extraction |
| `tests/unit/test-crucible-device-workspace.c` | GPL-2.0-or-later | Explicit SPDX identifier; wire, sealed descriptor, and private ABI controls |
| `tests/unit/test-crucible-startup-source-layout.c` | GPL-2.0-or-later | Explicit SPDX identifier; native startup control layout measurement |
| `tests/unit/test-crucible-startup-source.c` | GPL-2.0-or-later | Explicit SPDX identifier; original startup custody and refusal controls |
| `tests/unit/test-crucible-x86-table-projection.c` | GPL-2.0-or-later | Explicit SPDX identifier; descriptor-table identity and projection purity controls |
| `include/system/crucible-kernel-swap-observation.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-kernel-swap-observation.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-ram-owner-diagnostic.c` | GPL-2.0-or-later | Explicit SPDX identifier; original native report implementation retained |
| `plugins/crucible-ram-owner-diagnostic.h` | GPL-2.0-or-later | Explicit SPDX identifier; private native report contract |
| `replay/replay-mutex.c` | GPL-2.0-or-later | Preserved GNU GPL version 2 or later notice from the extracted replay implementation |
| `tests/unit/test-crucible-replay-owner.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/tcg/tcg-accel-ops-sim.c` | GPL-2.0-or-later | QEMU default |
| `include/system/crucible-plugin-wake.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `block/crucible-shmem.c` | GPL-2.0-or-later | Explicit file notice |
| `block/crucible-hot-fork-source.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `accel/tcg/tcg-accel-ops-sim-shmem.c` | GPL-2.0-or-later | QEMU default |
| `accel/tcg/tcg-accel-ops-sim-shmem.h` | GPL-2.0-or-later | QEMU default |
| `include/system/crucible-sim-ipi.h` | GPL-2.0-or-later | QEMU default |
| `accel/tcg/tcg-accel-ops-preemption.c` | GPL-2.0-or-later | QEMU default |
| `include/system/crucible-sim-preemption.h` | GPL-2.0-or-later | QEMU default |
| `include/qemu/crucible-paged-ram.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-paged-ram.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/system/crucible-ram-quiescence.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-ram-quiescence.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/system/crucible-ram-fork.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-ram-fork.c` | GPL-2.0-or-later | Explicit SPDX identifier |
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
| `tests/unit/test-crucible-ram-arena.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-ram-worker-inventory.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-placement-registration.py` | GPL-2.0-or-later | Explicit SPDX identifier; post-grant placement/write registrar production-body component checks |
| `tests/unit/test-crucible-aio-retirement.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-dirty-iterator.rst` | GPL-2.0-or-later | Explicit SPDX identifier; mandatory launched capture lifecycle integration requirements |
| `tests/unit/test-crucible-dirty-selector.c` | GPL-2.0-or-later | Explicit SPDX identifier; literal bitmap and coordinate selector component fixture |
| `tests/unit/test-crucible-dirty-iterator.py` | GPL-2.0-or-later | Explicit SPDX identifier; literal selector differential proof and mandatory lifecycle qualification gate |
| `tests/unit/crucible-net-stop-support.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-timer-stream.h` | GPL-2.0-or-later | Explicit SPDX identifier |
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
| `tests/tcg/plugins/crucible-resident-ram.h` | GPL-2.0-or-later | Explicit SPDX identifier; bounded resident logical-RAM component fixture authority |
| `tests/unit/test-crucible-child-memory-limit.py` | GPL-2.0-or-later | Explicit SPDX identifier; real kernel child limit and cancellation component checks |
| `tests/tcg/plugins/crucible-resident-ram-observer.c` | GPL-2.0-or-later | Explicit SPDX identifier; resident logical-RAM startup fixture without paging qualification |
| `tests/unit/test-crucible-memory-service-ticket.py` | GPL-2.0-or-later | Explicit SPDX identifier; actual CPU continuation state-machine and matched predecessor controls |
| `tests/unit/test-crucible-legacy-ram-load.py` | GPL-2.0-or-later | Explicit SPDX identifier; actual full-load refusal and device-only state parser controls |

| `include/qemu/crucible-descriptor-table.h` | MIT | Explicit SPDX identifier |
| `include/qemu/crucible-metadata-partition.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-preexec-setup.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-process-purpose.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-qmp-allocation.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-shared-region-layout.h` | MIT | Explicit SPDX identifier |
| `include/qemu/crucible-socket-ingress.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qobject/qobject-source.h` | LGPL-2.1-or-later | Explicit SPDX identifier |
| `include/system/crucible-cpu-tlb-metadata.h` | LGPL-2.1-or-later | Explicit SPDX identifier |
| `include/system/crucible-observation-realization.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/system/crucible-observation-writer.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-checkpoint-finalizer.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-checkpoint-receiving.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-checkpoint-receiving.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-command-consumer.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-control-invocation.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-control-stop.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-control-stop.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-process-purpose.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-qmp-allocation.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-qmp-object.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-qmp-scope.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-qmp-string.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-qmp-visitor.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-ram-control.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-ram-record.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-setup-handshake.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-setup-mapping.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-socket-ingress.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `qobject/qobject-source.c` | LGPL-2.1-or-later | Explicit SPDX identifier |
| `scripts/extract-crucible-preexec-purpose.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `scripts/gen-crucible-shared-region-layout.py` | MIT | Explicit SPDX identifier |
| `stubs/crucible-qmp-allocation.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `stubs/crucible-qmp-monitor.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `stubs/crucible-socket-ingress.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-observation-realization.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-observation-writer.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-preexec-artifact.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-preexec-contract.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-preexec-family.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-preexec-ram.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-preexec-workspace.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier; preissued workspace role and retained alias custody |
| `system/crucible-preexec-setup.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/crucible-startup-source-fixture.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/extract-crucible-checkpoint-placement.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/extract-crucible-checkpoint-receiving.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/extract-crucible-monitor-fd-loans.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/extract-crucible-preexec-setup.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-checkpoint-placement.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-checkpoint-receiving.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-cpu-service-debt.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-metadata-partition.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-monitor-fd-loans.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-preexec-setup.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-process-purpose.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `util/crucible-descriptor-table.c` | MIT | Explicit SPDX identifier |
| `docs/devel/crucible-parent-park.rst` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-park-census.h` | LGPL-2.1-or-later | Explicit SPDX identifier |
| `include/system/crucible-native-park-request.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-parent-park-metadata.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-parent-park.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `stubs/crucible-native-park.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `system/crucible-native-park-request.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-bounded-thread.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-cpu-instance.c` | GPL-2.0-or-later | Explicit SPDX identifier |
| `include/qemu/crucible-register-read.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-initial-register-read.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-publisher-service.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `plugins/crucible-register-read.inc.h` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-initial-register-read.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-publisher-service-transfer.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-ram-mapping-journal.py` | GPL-2.0-or-later | Explicit SPDX identifier |
| `tests/unit/test-crucible-ram-mapping-qmp.py` | GPL-2.0-or-later | Explicit SPDX identifier |

The separately built Rust `crucible-qemu-plugin` and C
`crucible-qemu-trace-plugin` carry explicit GPL-2.0-only notices. The Rust
runtime resource-manifest projection in
`crates/crucible/qemu/crucible-qemu-plugin/src/runtime/resource_manifest.rs`
retains that GPL-2.0-only scope and carries its own explicit SPDX notice. The generated
`crucible_shmem_abi.h` process-protocol header is `MIT OR Apache-2.0`; AOS
packages distribute and record it under the MIT option alongside QEMU.

When the atomic integration patch starts creating or deleting a file, update this inventory in the
same change. Preserve an explicit file notice and use QEMU's upstream `LICENSE`
to classify an unmarked file; do not infer a blanket license from the artifact
directory.
