# SPDX-License-Identifier: MIT
"""Realizes one fixed x86 Linux board beneath the stopped native controller.

The existing SE and ARM adapters remain independent. This adapter binds the
kernel, initramfs, complete configuration tree and fixed native loader geometry.
Its real UART publication path is system.pc.com_1.device, without a synthetic
ARM terminal alias. Full process closure, readiness, timing and device parity
remain unqualified, including after an actual early console publication.
"""

import importlib.util
from pathlib import Path
import sys

import m5


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    # dataclasses resolves annotations through the original module registry.
    if name in sys.modules:
        raise ValueError("x86 source-selected helper module is already installed")
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


models = load("crucible_fixed_x86_publications", "native-controller-models.py")
assets = load("crucible_fixed_x86_assets", "native-model-assets.py")
loader = load("crucible_fixed_x86_loader", "x86-linux-loader.py")


class X86LinuxModel(models.TerminalMechanismModel):
    """Owns the fixed PC realization and original native serial FIFO."""

    schema = "crucible.gem5.x86-linux-native/1"
    bootstrap_fields = models.COMMON_BOOTSTRAP + ("model",)
    output_basename = "x86-terminal.output"

    def __init__(self, bootstrap, resource_root):
        if bootstrap["guest_isa"] != "x86_64" or bootstrap["executable"] != "":
            raise ValueError("x86 Linux does not use the SE executable interface")
        selection = bootstrap["model"]
        if (type(selection) is not dict or set(selection) != {"schema", "assets", "configs"}
                or selection["schema"] != "crucible.gem5.x86-linux-model.v1"):
            raise ValueError("x86 native model selection has an unknown schema or field")
        if type(selection["assets"]) is not dict or set(selection["assets"]) != {"kernel", "initramfs"}:
            raise ValueError("x86 Linux immutable asset roles are incomplete")

        self.resource_root = resource_root
        self.terminal = None
        self.bindings = {}
        for role, filename in (("kernel", "kernel.elf"), ("initramfs", "initrd.img")):
            self.bindings[role] = assets.verify_asset(resource_root, selection["assets"][role], filename)
        self.config_binding = assets.configuration_tree(resource_root / "configs")
        if self.config_binding != selection["configs"]:
            raise ValueError("x86 board configuration bytes differ from the selected source")
        self.loader_plan = loader.validate_loader(resource_root / "kernel.elf", resource_root / "initrd.img")

    def realize(self):
        from m5.objects import (
            AbsentFchResetStatus, Root, SimpleMemory, SrcClockDomain,
            VoltageDomain, X86AtomicSimpleCPU,
        )

        m5.ticks.setGlobalFrequency("1THz")
        m5.core.disableAllListeners()
        configuration = self.resource_root / "configs"
        sys.path.insert(0, str(configuration))
        from common import Benchmarks, FSConfig

        for module in (Benchmarks, FSConfig):
            if not Path(module.__file__).resolve().is_relative_to(configuration):
                raise ValueError("x86 board import escaped its selected configuration tree")
        system = FSConfig.makeLinuxX86System(
            "atomic", numCPUs=1,
            mdesc=Benchmarks.SysConfig(mem="256MiB", disks=[]),
            cmdline="console=ttyS0 earlyprintk=ttyS0 rdinit=/init panic=1 "
                    "lpj=1000000 nokaslr net.ifnames=0",
        )
        system.voltage_domain = VoltageDomain()
        system.clk_domain = SrcClockDomain(clock="100MHz", voltage_domain=system.voltage_domain)
        system.workload.object_file = str(self.resource_root / "kernel.elf")
        # The data validator follows this exact native image mapping.
        system.workload.load_addr_mask = (1 << 64) - 1
        system.workload.load_addr_offset = 0
        system.cpu = X86AtomicSimpleCPU(cpu_id=0, width=16)
        system.cpu.createThreads()
        system.cpu.createInterruptController()
        system.cpu.connectBus(system.membus)
        system.memory = SimpleMemory(range=system.mem_ranges[0])
        system.memory.port = system.membus.mem_side_ports

        # Preserve the PC's native optional-register absence model without
        # suppressing the guest probe or substituting CPU identity/features.
        system.pc.absent_fch_reset_status = AbsentFchResetStatus()
        system.pc.absent_fch_reset_status.pio = system.iobus.mem_side_ports
        terminal = system.pc.com_1.device
        terminal.port = 0
        terminal.outfile = "none"
        root = Root(full_system=True, system=system)
        m5.instantiate()

        # The stock x86 kernel loader has no ARM initrd_filename parameter.
        # All regions were checked before construction; this preserves the real
        # Linux boot-parameter protocol before the first native callback.
        loader.install_initramfs(system.physProxy, self.loader_plan)
        self.terminal = terminal
        if self.terminal.path() != "system.pc.com_1.device":
            raise ValueError("x86 UART birth owner changed its native object path")
        self.terminal.crucibleConfigureOutput()
        if not self.terminal.crucibleSetOutputParent(17):
            raise ValueError("x86 native serial parent was not bound before callbacks")
        return root

    def describe_scope(self):
        return {
            "schema": "crucible.gem5.model-scope.v1",
            "model_id": "x86-linux-pc-atomic-functional-v1",
            "full_system": True,
            "complete_process_closure_qualified": False,
            "cpu_timing_qualified": False,
            "guest_readiness_qualified": False,
            "device_parity_qualified": False,
            "guest_assets": self.bindings,
            "configuration_tree": self.config_binding,
            "loader": self.loader_plan.describe(),
        }
