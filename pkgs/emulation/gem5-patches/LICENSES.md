# gem5 native patch license inventory

Upstream revision: `f5c5a6e390f55dd5984977815bf9d0bd05da6945`
(gem5 25.1.0.1). Every modified upstream file retains its complete original
copyright and license notice. New native probe files carry their own explicit
permissive notices; they do not relicense the simulator.

| Patch | Modified upstream files | Preserved license |
| --- | --- | --- |
| `native-lru-constructor-provenance.patch` | Modified `src/sim/crucible_native_scope.hh`, `src/sim/crucible_native_scope.cc`, `src/mem/cache/replacement_policies/lru_rp.hh`, `src/mem/cache/replacement_policies/lru_rp.cc`; new `src/sim/crucible_lru_births.hh` | Existing BSD notices retained; new fixed constructor-birth bank is BSD-3-Clause. The two host component helpers under `../_gem5/` are MIT; exact upstream declaration retains its corresponding complete source. |
| `x86-cpuid-subleaf-bounds.patch` | `src/arch/x86/cpuid.cc` | Original BSD three-clause notice and copyright holders; direct native GoogleTest fixture under `../_gem5/` is separately MIT |
| `x86-absent-fch-reset-status.patch` | Modified `src/dev/SConscript`; new `src/dev/AbsentFchResetStatus.py`, `src/dev/absent_fch_reset_status.hh`, `src/dev/absent_fch_reset_status.cc` | Original SConscript BSD three-clause notice retained; new explicitly absent optional-register model and native Packet witness are MIT |
| `aarch64-pmull64.patch` | `src/arch/arm/isa/formats/neon64.isa`, `src/arch/arm/isa/insts/neon64.isa` | Original BSD three-clause notices retained, including Arm's hardware intellectual-property scope statement; separate guest assembly and check helpers are MIT |
| `compiler-target-query.patch` | `SConstruct` | BSD three-clause notice, including upstream hardware intellectual-property scope statement |
| `reproducible-build-environment.patch` | `site_scons/gem5_scons/defaults.py` | BSD three-clause notice, including upstream hardware intellectual-property scope statement |
| `nondraining-event-boundary.patch` | `src/sim/simulate.hh`, `src/sim/simulate.cc`, `src/python/pybind11/event.cc`, `src/python/m5/simulate.py` | Each file's BSD three-clause notice and copyright holders |
| `time-buffer-value-initialization.patch` | `src/cpu/timebuf.hh` | Original BSD three-clause notice and copyright holders |
| `device-parity-modern-transport.patch` | `src/dev/virtio/base.hh`, `src/dev/virtio/base.cc`, `src/dev/virtio/pci.hh`, `src/dev/virtio/pci.cc`, `src/dev/virtio/VirtIO.py`, `src/dev/arm/vio_mmio.hh`, `src/dev/arm/vio_mmio.cc`, `src/dev/arm/VirtIOMMIO.py` | Each file's original BSD three-clause notice and copyright holders, including upstream hardware intellectual-property scope statements |
| `device-parity-native-witness.patch` | Modified `src/dev/virtio/SConscript`; new `src/dev/virtio/VirtIOQueueWitness.py`, `src/dev/virtio/queue_witness.hh`, `src/dev/virtio/queue_witness.cc` | Original `SConscript` BSD three-clause notice; new probe files have explicit MIT notices |
| `device-parity-network.patch` | Modified `src/dev/virtio/SConscript`; new `src/dev/virtio/VirtIONet.py`, `src/dev/virtio/net.hh`, `src/dev/virtio/net.cc` | Original `SConscript` BSD three-clause notice; new endpoint files have explicit MIT notices |
| `device-parity-network-witness.patch` | `src/dev/virtio/VirtIOQueueWitness.py`, `src/dev/virtio/queue_witness.hh`, `src/dev/virtio/queue_witness.cc` | Preserved MIT notices from the native mechanism probe |
| `device-parity-host-request.patch` | Modified `src/dev/virtio/SConscript`, `src/dev/virtio/base.hh`, `src/dev/virtio/base.cc`; new `src/dev/virtio/VirtIOHostRequest.py`, `src/dev/virtio/host_request.hh`, `src/dev/virtio/host_request.cc` | Preserved original BSD notices; new bounded asynchronous frontend files have explicit MIT notices |
| `device-parity-host-request-witness.patch` | `src/dev/virtio/VirtIOQueueWitness.py`, `src/dev/virtio/queue_witness.hh`, `src/dev/virtio/queue_witness.cc` | Preserved MIT notices from the native mechanism probe |
| `device-modeled-state.patch` | `src/dev/virtio/base.hh`, `src/dev/virtio/base.cc`, `src/dev/virtio/pci.hh`, `src/dev/virtio/pci.cc`, `src/dev/arm/vio_mmio.hh`, `src/dev/arm/vio_mmio.cc`, `src/dev/virtio/net.hh`, `src/dev/virtio/net.cc`, `src/dev/virtio/host_request.hh`, `src/dev/virtio/host_request.cc` | Preserved original upstream BSD notices and MIT notices on new asynchronous frontend files |
| `modeled-state-inventory.patch` | `src/base/random.hh`, `src/sim/eventq.hh`, `src/sim/eventq.cc`, `src/sim/sim_object.hh`, `src/sim/sim_object.cc`, `src/sim/simulate.hh`, `src/sim/simulate.cc`, `src/python/pybind11/event.cc`, `src/python/m5/simulate.py` | Each file's original BSD three-clause notice and copyright holders |
| `memory-modeled-state.patch` | `SConstruct`, `src/sim/sim_object.hh`, `src/sim/system.hh`, `src/sim/system.cc`, `src/python/pybind11/event.cc`, `src/mem/cache/tags/base.hh`, `src/mem/cache/tags/base.cc`, `src/mem/mem_ctrl.hh`, `src/mem/mem_ctrl.cc`, `src/mem/mem_interface.hh`, `src/mem/mem_interface.cc`, `src/mem/dram_interface.hh`, `src/mem/dram_interface.cc` | Each original BSD three-clause notice and copyright holders; added `src/sim/crucible_state.hh` is MIT |
| `cpu-modeled-state.patch` | `src/cpu/o3/cpu.hh`, `src/cpu/o3/cpu.cc`, `src/cpu/o3/dyn_inst.hh`, `src/cpu/o3/free_list.hh`, `src/cpu/o3/regfile.hh`, `src/cpu/o3/rename_map.hh`, `src/cpu/o3/scoreboard.hh`, `src/cpu/pred/bpred_unit.hh`, `src/cpu/pred/conditional.hh`, `src/cpu/pred/tournament.hh`, `src/cpu/pred/ras.hh`, `src/arch/x86/tlb.hh`, `src/arch/x86/tlb.cc`, `src/arch/arm/tlb.hh`, `src/arch/arm/tlb.cc` | Each file's original BSD three-clause notice and copyright holders, including upstream hardware intellectual-property scope statements |
| `cpu-pipeline-modeled-state.patch` | `src/arch/arm/pcstate.hh`, `src/arch/generic/pcstate.hh`, `src/arch/x86/pcstate.hh`, `src/base/circular_queue.hh`, `src/cpu/activity.hh`, `src/cpu/func_unit.hh`, `src/cpu/o3/bac.cc`, `src/cpu/o3/bac.hh`, `src/cpu/o3/comm.hh`, `src/cpu/o3/commit.cc`, `src/cpu/o3/commit.hh`, `src/cpu/o3/cpu.cc`, `src/cpu/o3/decode.cc`, `src/cpu/o3/decode.hh`, `src/cpu/o3/dep_graph.hh`, `src/cpu/o3/dyn_inst.hh`, `src/cpu/o3/fetch.cc`, `src/cpu/o3/fetch.hh`, `src/cpu/o3/ftq.cc`, `src/cpu/o3/ftq.hh`, `src/cpu/o3/fu_pool.cc`, `src/cpu/o3/fu_pool.hh`, `src/cpu/o3/iew.cc`, `src/cpu/o3/iew.hh`, `src/cpu/o3/inst_queue.cc`, `src/cpu/o3/inst_queue.hh`, `src/cpu/o3/lsq.cc`, `src/cpu/o3/lsq.hh`, `src/cpu/o3/lsq_unit.cc`, `src/cpu/o3/lsq_unit.hh`, `src/cpu/o3/mem_dep_unit.cc`, `src/cpu/o3/mem_dep_unit.hh`, `src/cpu/o3/rename.cc`, `src/cpu/o3/rename.hh`, `src/cpu/o3/rob.cc`, `src/cpu/o3/rob.hh`, `src/cpu/o3/store_set.cc`, `src/cpu/o3/store_set.hh`, `src/cpu/pred/bpred_unit.hh`, `src/cpu/pred/ras.hh`, `src/cpu/timebuf.hh` | Each file's original BSD three-clause notice and copyright holders, including upstream hardware intellectual-property scope statements |
| `cpu-isa-modeled-state.patch` | `src/arch/arm/decoder.cc`, `src/arch/arm/decoder.hh`, `src/arch/arm/isa.cc`, `src/arch/arm/isa.hh`, `src/arch/generic/decoder.hh`, `src/arch/generic/isa.hh`, `src/arch/x86/cpuid.hh`, `src/arch/x86/decoder.cc`, `src/arch/x86/decoder.hh`, `src/arch/x86/isa.cc`, `src/arch/x86/isa.hh`, `src/cpu/o3/cpu.cc`, `src/cpu/o3/thread_state.cc`, `src/cpu/o3/thread_state.hh`, `src/cpu/thread_state.hh` | Each file's original BSD three-clause notice and copyright holders, including upstream hardware intellectual-property scope statements |
| `cpu-payload-modeled-state.patch` | `src/arch/x86/pcstate.hh`, `src/base/circular_queue.hh`, `src/cpu/inst_res.hh`, `src/cpu/o3/dyn_inst.hh`, `src/cpu/o3/fetch.cc`, `src/cpu/o3/lsq.cc`, `src/cpu/o3/thread_state.cc`, `src/cpu/pc_event.hh`, `src/cpu/pred/bpred_unit.hh`, `src/cpu/pred/tournament.hh`, `src/cpu/static_inst.hh`, `src/sim/faults.hh` | Each file's original BSD three-clause notice and copyright holders, including upstream hardware intellectual-property scope statements |
| `cpu-instruction-modeled-state.patch` | `src/arch/x86/insts/static_inst.hh`, `src/arch/x86/insts/macroop.hh`, `src/arch/x86/insts/microop.hh`, `src/arch/arm/insts/static_inst.hh`, `src/arch/arm/insts/pred_inst.hh` | Each file's original BSD three-clause notice and copyright holders, including upstream hardware intellectual-property scope statements |
| `cpu-object-alias-normalization.patch` | `src/arch/arm/isa.cc`, `src/cpu/thread_state.hh`, `src/sim/crucible_state.hh` | Original upstream BSD notices retained; shared inspection header retains its MIT notice |
| `cpu-store-input-definedness.patch` | `src/cpu/o3/lsq.cc` | Original BSD three-clause notice and copyright holders retained |
| `cache-modeled-state.patch` | `src/mem/cache/base.cc`, `src/mem/cache/base.hh`, `src/mem/cache/mshr.hh`, `src/mem/cache/queue.hh`, `src/mem/cache/write_queue_entry.hh`, `src/mem/mem_ctrl.cc`, `src/mem/packet.hh`, `src/mem/request.hh`, `src/python/pybind11/event.cc`, `src/sim/eventq.cc`, `src/sim/eventq.hh`; `src/sim/crucible_state.hh` | Existing source notices unchanged (BSD three-clause and per-file upstream notices); independently authored shared inspection header remains MIT |
| `se-output-publication.patch` | `src/sim/simulate.hh`, `src/sim/simulate.cc`, `src/sim/syscall_emul.hh`, `src/sim/syscall_emul.cc`, `src/sim/SConscript`, `src/python/pybind11/event.cc`, `src/python/m5/simulate.py`; new `src/sim/crucible_output.hh`, `src/sim/crucible_output.cc` | Original notices retained; new native publication files BSD-3-Clause |
| `packet-data-definedness.patch` | `src/mem/packet.hh` | Original BSD three-clause notice and copyright holders |
| `object-state-alias.patch` | `src/python/pybind11/event.cc` | Original BSD three-clause notice and copyright holders |
| `terminal-output-publication.patch` | `src/dev/serial/Terminal.py`, `src/dev/serial/terminal.hh`, `src/dev/serial/terminal.cc` | Original BSD three-clause notices and copyright holders retained, including Arm's hardware intellectual-property scope statement |
| `terminal-output-native-witness.patch` | Modified `src/dev/serial/SConscript`; new `src/dev/serial/CrucibleTerminalWitness.py`, `src/dev/serial/crucible_terminal_witness.hh`, `src/dev/serial/crucible_terminal_witness.cc` | Original SConscript BSD three-clause notice retained; new native callback witness files carry explicit MIT notices |
| `terminal-publication-inventory.patch` | `src/dev/serial/Terminal.py`, `src/dev/serial/terminal.hh`, `src/dev/serial/terminal.cc` | Original BSD three-clause notices and copyright holders retained, including Arm's hardware intellectual-property scope statement; read-only complete FIFO observation creates no upstream source files |
| `addr-range-predicate-borrow.patch` | `src/base/addr_range_map.hh` | Original BSD three-clause notices and copyright holders retained, including Arm's hardware intellectual-property scope statement |

The installed gem5 package retains upstream `LICENSE` and bundled dependency
license/notice files. The source manifest binds the exact upstream revision,
recipe and patch digests. It does not relicense upstream or qualify a Crucible
profile. The helper Python/C/C++/assembly sources under `../_gem5/` are separately
marked MIT; Nix recipes follow the repository's applicable file license.

DMTCP remains an independently packaged LGPL-3.0-or-later component. Its pinned
`include/dmtcp.h` explicitly dedicates that public interface header to the public
domain; the implementation/library is not public domain. The MIT resource
custody helper does not change DMTCP's license. Preloading DMTCP into a
GPL-2.0-only QEMU process is not authorized by this inventory.

The source-owned closed device foundations additionally preserve the following
original notices. They add no upstream native files and retain matching ordered
patches, source witnesses and recipes. Their diagnostic coverage remains partial;
public admission and processor timing require separate qualification.

| Patch | Modified native files | License |
| --- | --- | --- |
| causal-device-inventory.patch | src/python/pybind11/event.cc; src/python/m5/simulate.py | Existing BSD-3-Clause notices retained |
| device-original-fifo-inventory.patch | src/dev/virtio/net.cc; src/dev/virtio/net.hh; src/dev/virtio/VirtIONet.py; src/dev/virtio/host_request.cc; src/dev/virtio/host_request.hh; src/dev/virtio/VirtIOHostRequest.py | Existing MIT notices retained |
| closed-block-native-boundary.patch | src/sim/crucible_output.hh; src/sim/crucible_output.cc; src/sim/simulate.cc; src/python/pybind11/event.cc; src/python/m5/simulate.py | Existing BSD-3-Clause notices retained |
| closed-block-native-boundary.patch | src/dev/virtio/host_request.hh; src/dev/virtio/host_request.cc; src/dev/virtio/VirtIOHostRequest.py | Existing MIT notices retained |
| `closed-network-native-boundary.patch` | `src/dev/virtio/net.hh`; `src/dev/virtio/net.cc`; `src/dev/virtio/VirtIONet.py` | Existing MIT source notices retained. Source-owned closed-network mechanism only; no new native files or ordinary node/device/timing authority. |

The source-owned diagnostic Atomic scope preserves the following native notices.
Ownership inspection is separate from native process, source-cut and restore authority.

| Patch | Native file | Preserved license |
| --- | --- | --- |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/decoder.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/decoder.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/interrupts.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/interrupts.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/isa.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/isa.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/isa_device.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/linux/process.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/linux/process.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/linux/se_workload.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/linux/se_workload.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/mmu.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/mmu.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/pagetable.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/pagetable.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/self_debug.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/system.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/system.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/table_walker.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/table_walker.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/tlb.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/arch/arm/tlb.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/base/uncontended_mutex.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/cpu/exetrace.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/cpu/exetrace.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/cpu/pc_event.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/cpu/simple/atomic.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/cpu/simple/atomic.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/dev/virtio/CrucibleClosedScriptBlock.py` | New explicit BSD-3-Clause notice |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/dev/virtio/SConscript` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/dev/virtio/base.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/dev/virtio/base.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/dev/virtio/crucible_closed_script_block.cc` | New explicit BSD-3-Clause notice |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/dev/virtio/crucible_closed_script_block.hh` | New explicit BSD-3-Clause notice |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/dev/virtio/host_request.hh` | Existing MIT notice retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/CrucibleAtomicFabric.py` | New explicit BSD-3-Clause notice |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/SConscript` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/backdoor.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/cache/replacement_policies/lru_rp.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/cache/replacement_policies/lru_rp.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/crucible_atomic_fabric.cc` | New explicit BSD-3-Clause notice |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/crucible_atomic_fabric.hh` | New explicit BSD-3-Clause notice |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/packet_queue.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/packet_queue.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/physical.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/physical.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/simple_mem.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/mem/simple_mem.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/python/pybind11/event.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/SConscript` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/clock_domain.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/clock_domain.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/clocked_object.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/crucible_kernel_process.hh` | New explicit BSD-3-Clause notice |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/crucible_native_cut.hh` | New explicit BSD-3-Clause notice |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/crucible_native_scope.cc` | New explicit BSD-3-Clause notice |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/crucible_native_scope.hh` | New explicit BSD-3-Clause notice |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/dvfs_handler.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/dvfs_handler.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/eventq.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/eventq.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/insttracer.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/port.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/power_state.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/power_state.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/probe/probe.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/root.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/root.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/sim_object.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/sim_object.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/system.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/system.hh` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/voltage_domain.cc` | Original upstream per-file notice and copyright holders retained unchanged |
| `native-original-scope-and-diagnostic-atomic-owners.patch` | `src/sim/voltage_domain.hh` | Original upstream per-file notice and copyright holders retained unchanged |

The independently authored `_gem5/native-original-scope-check.py` and
`_gem5/native-diagnostic-guest.py` controls are MIT. The fixed two-opcode
AArch64 guest establishes a diagnostic scope only, not general ISA, Linux
boot or device parity. The matching source output retains the complete
patched tree, original source archive, patch inventory, recipes, controls
and source-built toolchain bindings; native qualification remains separate.

The diagnostic constructor hook observes registry membership after allocation
and base initialization; it does not fence those prior effects or establish
complete native backing ownership. Callback member registration alone does
not establish mutable callable/captured-owner closure. The direct queue
helper rejects foreign custody before either inherited lock; its independently
bounded child control claims termination/reaping, not private child state
preservation after exit or whole-node execution authority.

The public diagnostic queue forwarder retains the original private walker;
it checks the actual process/thread/UID before phase validation and either
inherited lock. This is diagnostic access, not a native execution permit.

The fixed x86 Linux controller components add no upstream simulator files.
`native-controller-x86.py`, `native-controller-x86-model.py`,
`x86-linux-loader.py`, `x86-linux-loader-check.py` and
`x86-linux-loader-fixture.S` under `../_gem5/` carry explicit MIT notices. The
loader check co-retains those source inputs and its Nix recipe; the component
bundle co-retains the complete corresponding native source and required loader
check. ELF/boot-protocol component results do not qualify native process
ownership, full-system readiness, device parity, capture or CPU timing.

The native compilation/source-enrichment split adds independently authored MIT
`../_gem5/native-base.nix`, `native-compiler.nix`, `foundation.nix`,
`source-enrichment.py` and `source-enrichment-check.py`. Upstream and patched
gem5 file licenses remain unchanged. The native product retains its complete
patched and upstream source, actual patch and compiler inputs, invoked builder,
setup script and generated header context. The public source output additionally
retains host controls, recipes, this inventory and the exact native source output.
The wrapper checks native ELF byte identity and records the producer relationship;
these packaging checks confer no simulation, source-cut or restore authority.

### Selected native table-account geometry

`native-selected-table-geometry.patch` modifies the existing BSD-compatible
`src/arch/arm/tlb.cc` and `src/sim/crucible_native_scope.{cc,hh}`. It preserves
all original file notices and the normal selected 1280-entry ARM L2 table.
The source-private fixed bank declares actual table extents before entry debit;
profile version 3 binds both table and LRU constructor-bank geometry.

`_gem5/selected-table-banks-check.cc` and `_gem5/selected-table-methods.py` are
independently authored MIT host/component controls. They retain exact selected
method source and capacity data; they grant no native process, graph, capture,
restore or execution authority. Complete configured native checks stay required.

## ARM walker source state

`native-arm-walker-source-state.patch` modifies `src/arch/arm/table_walker.cc`
under its existing BSD-3-Clause license. It initializes the original cached
release and pending-statistics fields, binds the release from the actual MMU,
and checks that source relationship during the diagnostic closure walk.
The complete patched file, this patch, and the invoked recipe remain in the
matching gem5 corresponding-source output. No new native file is introduced.

The Linux device fixture PID1 is shared by the AArch64 and x86-64 packages.
`../_gem5/linux-device-init.c` replaces the ARM-only filename and retains its
MIT notice; the architecture-specific syscall and entry assembly are also MIT.
The new `linux-init-artifact-check.py` and `linux-init-artifact-tests.py` controls
are MIT. The shared fixture recipe co-retains these source inputs, the unchanged
MIT initramfs packer and socket ABI shim, the selected sanitized kernel headers,
their original source provider, the build recipes and exact binary commitments.
Linux UAPI headers retain their individual notices and applicable Linux-syscall
exception; this inventory does not relicense them. Artifact and ARM code-parity
checks do not establish Linux boot, guest device parity, native process ownership,
CPU timing, capture or restored continuation.

## Installed x86 Linux model asset preparation

`_gem5/x86-linux-bundle.py`, `_gem5/x86-linux-bundle-check.py`, and
`gem5-x86-linux-model-assets.nix` are independently authored MIT-licensed AOS
build/host utilities. They bind source-built kernel, PID1/initramfs, native
controller and configuration bytes and prepare a private resource tree without
executing a guest or emulator. They are separate from native source issuers,
checkpoint adoption, device parity and CPU timing qualification. The package
retains these utilities, its recipe and selected-artifact specification in its
source output and retains the matching native corresponding-source dependency.
Kernel/PID1/configuration inputs retain their own original licenses and notices;
the MIT utility license does not relicense those dependencies.

## Native x86 Linux PID1 boot check

`_gem5/x86-linux-native-boot-check.py` and its separate modeled-clock
`_gem5/x86-linux-native-boot-unit-check.py` controls are independently authored
MIT utilities. The check recipe retains both sources and the matching complete
native and guest source dependencies. The installed component and asset bundles
select the same deepest native foundation; no upstream file licenses change.
The actual boot phase requires both PID1 console lines from the PC UART and
retains bounded transcript and native publication digests. It does not establish
common-node source authority, capture, restored continuation, device parity or
CPU timing. Modeled-clock controls cannot stand in for that actual boot phase.

The MIT `_gem5/x86-linux-native-boot-compare.py` control compares the retained
raw console bytes, native UART birth digests and final tick/event counts from
two fresh invocations of that same fixed boot. It establishes only the recorded
workload observation, not general timing accuracy, capture or restoration.


## Concrete no-listener ARM system counter

`native-system-counter-source-state.patch` modifies existing
`src/dev/arm/generic_timer.{cc,hh}` and `src/dev/arm/GenericTimer.py` under their
original BSD-3-Clause-compatible Arm notices, which remain intact. It also
updates the existing BSD-3-Clause `src/sim/crucible_native_scope.cc` diagnostic
profile identity. No native source file is added. The complete patched files,
this patch, invoked recipe, host controls and license inventory remain in the
matching gem5 corresponding-source output.

The existing MIT `native-original-scope-check.py` and
`native-original-scope-evidence.py` controls add actual concrete counter,
pending native frequency callback and invalid-table cases. Their existing
mandatory check binds the matching native executable and source archive.
The new MIT `system-counter-observation-check.py` source control advances a
counter-only native mechanism to a stale cached value and compares repeated
observations before and after the real frequency-change callback.
The partial typed producer reads cached fields without updating the counter.
The native graph visitor rejects every listener and bounds the frequency table
and its native capacity. Complete allocator/backing-resource custody, nested
timer/listener/pin ownership, source issuance, early restore adoption, full-system
CPU/device qualification and common readiness remain separate and refused.
