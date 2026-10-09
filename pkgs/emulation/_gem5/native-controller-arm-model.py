# SPDX-License-Identifier: MIT
"""Realizes one finite ARM Linux model for unqualified shared-controller proofs.

All guest files and Python board configuration bytes are bound before model
construction. This functional Atomic model grants no timing, full device parity,
guest readiness, or complete opaque-image qualification.
"""

import importlib.util
from pathlib import Path
import sys

import m5


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


models = load("crucible_model_publications", "native-controller-models.py")
assets = load("crucible_model_asset_custody", "native-model-assets.py")


class ArmLinuxModel(models.TerminalMechanismModel):
    """Binds the existing ARM functional board to the shared UART facet."""

    schema = "crucible.gem5.arm-linux-native/1"
    bootstrap_fields = models.COMMON_BOOTSTRAP + ("model",)

    def __init__(self, bootstrap, resource_root):
        if bootstrap["guest_isa"] != "aarch64" or bootstrap["executable"] != "":
            raise ValueError("ARM full-system model has no SE executable interface")
        selection = bootstrap["model"]
        if (not isinstance(selection, dict) or set(selection) != {"schema", "assets", "configs"}
                or selection["schema"] != "crucible.gem5.arm-linux-model.v1"):
            raise ValueError("unknown ARM native model selection")
        if not isinstance(selection["assets"], dict) or set(selection["assets"]) != {
            "kernel", "initramfs", "firmware"
        }:
            raise ValueError("ARM native guest asset roles are incomplete")
        self.resource_root = resource_root
        self.terminal = None
        self.bindings = {}
        for role, name in (("kernel", "kernel.elf"), ("initramfs", "initrd.img"),
                           ("firmware", "boot_v2.arm64")):
            self.bindings[role] = assets.verify_asset(resource_root, selection["assets"][role], name)
        self.config_binding = assets.configuration_tree(resource_root / "configs")
        if self.config_binding != selection["configs"]:
            raise ValueError("ARM Python configuration body differs from its sealed binding")

    def realize(self):
        from m5.objects import ArmAtomicSimpleCPU, Root, SimpleMemory, SrcClockDomain, VoltageDomain

        m5.ticks.setGlobalFrequency("1THz")
        m5.core.disableAllListeners()
        sys.path.insert(0, str(self.resource_root / "configs"))
        from common.Benchmarks import SysConfig
        from common.FSConfig import makeArmSystem

        system = makeArmSystem(
            "atomic", "VExpress_GEM5_V2", num_cpus=1,
            mdesc=SysConfig(mem="256MiB", disks=[]),
            bootloader=[str(self.resource_root / "boot_v2.arm64")],
            cmdline="console=ttyAMA0 earlycon=pl011,0x1c090000 rdinit=/init panic=1 "
                    "lpj=1000000 init_on_alloc=0 init_on_free=0 nokaslr net.ifnames=0",
        )
        system.voltage_domain = VoltageDomain()
        system.clk_domain = SrcClockDomain(clock="100MHz", voltage_domain=system.voltage_domain)
        system.workload.object_file = str(self.resource_root / "kernel.elf")
        system.workload.initrd_filename = str(self.resource_root / "initrd.img")
        system.cpu = ArmAtomicSimpleCPU(cpu_id=0, width=16)
        system.cpu.createThreads()
        system.cpu.createInterruptController()
        system.cpu.connectBus(system.membus)
        system.memory = SimpleMemory(range=system.mem_ranges[0])
        system.memory.port = system.membus.mem_side_ports
        system.terminal.port = 0
        system.terminal.outfile = "none"
        root = Root(full_system=True, system=system)
        dtb = str(self.resource_root / "output" / "fixture.dtb")
        system.generateDtb(dtb)
        system.workload.dtb_filename = dtb
        m5.instantiate()
        self.terminal = system.terminal
        self.terminal.crucibleConfigureOutput()
        if not self.terminal.crucibleSetOutputParent(17):
            raise ValueError("ARM native serial parent was not bound before execution")
        return root

    def describe_scope(self):
        return {
            "schema": "crucible.gem5.model-scope.v1",
            "model_id": "arm-linux-vexpress-atomic-functional-v1",
            "full_system": True, "complete_process_closure_qualified": False,
            "cpu_timing_qualified": False, "guest_readiness_qualified": False,
            "guest_assets": self.bindings, "configuration_tree": self.config_binding,
        }
