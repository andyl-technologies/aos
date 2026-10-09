# SPDX-License-Identifier: MIT
"""Source-owned publication adapters for the successor shared native controller.

Adapters expose genuine native birth and ACK operations. They do not select a
host execution capability or qualify an opaque process image. A production
catalog must independently authenticate the complete installed model closure.
"""

import importlib.util
from pathlib import Path

import m5


COMMON_BOOTSTRAP = (
    "schema", "owner", "incarnation", "generation", "controller_uid",
    "guest_isa", "executable", "resource_root", "control_socket",
)


class FreestandingO3Model:
    """Adapts the existing fixed SE model without changing its guest semantics."""

    schema = "crucible.gem5.native/3"
    bootstrap_fields = COMMON_BOOTSTRAP
    output_basename = "guest.output"

    def __init__(self, bootstrap, resource_root):
        self.bootstrap = bootstrap
        self.resource_root = resource_root

    def realize(self):
        spec = importlib.util.spec_from_file_location(
            "crucible_selected_se_model", Path(__file__).with_name("native-owner-model.py")
        )
        implementation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(implementation)
        root = implementation.realize(
            self.bootstrap["guest_isa"], self.bootstrap["executable"],
            str(self.resource_root / self.output_basename),
        )
        if not hasattr(m5, "crucibleConsolePublications"):
            raise ValueError("the selected SE facet has no genuine native publication hook")
        return root

    def publications(self):
        return m5.crucibleConsolePublications()

    def acknowledge(self, original_identifier):
        m5.crucibleAcknowledgeConsole(original_identifier)

    def rebind_resource_root(self, resource_root):
        self.resource_root = resource_root

    def describe_scope(self):
        return None


class TerminalMechanismModel:
    """Adapts the finite real native multi-byte UART callback mechanism."""

    schema = "crucible.gem5.terminal-native/1"
    bootstrap_fields = COMMON_BOOTSTRAP
    output_basename = "terminal.output"

    def __init__(self, bootstrap, resource_root):
        # This source-owned model has neither an ISA workload nor an executable.
        if bootstrap["guest_isa"] != "none" or bootstrap["executable"] != "":
            raise ValueError("terminal mechanism does not admit a guest executable")
        self.resource_root = resource_root
        self.terminal = None

    def realize(self):
        from m5.objects import (
            AddrRange, CrucibleTerminalWitness, Root, SimpleMemory, SrcClockDomain,
            System, SystemXBar, Terminal, VoltageDomain,
        )

        m5.ticks.setGlobalFrequency("1THz")
        m5.core.disableAllListeners()
        system = System(mem_mode="atomic")
        system.clk_domain = SrcClockDomain(clock="100MHz", voltage_domain=VoltageDomain())
        system.mem_ranges = [AddrRange("128KiB")]
        system.bus = SystemXBar()
        system.memory = SimpleMemory(range=system.mem_ranges[0])
        system.memory.port = system.bus.mem_side_ports
        system.system_port = system.bus.cpu_side_ports
        system.terminal = Terminal(port=0, outfile="none")
        system.first = CrucibleTerminalWitness(terminal=system.terminal)
        system.second = CrucibleTerminalWitness(terminal=system.terminal)
        root = Root(full_system=False, system=system)
        m5.instantiate()
        self.terminal = system.terminal
        self.terminal.crucibleConfigureOutput()
        if not self.terminal.crucibleSetOutputParent(17):
            raise ValueError("original terminal parent was not admitted before events")
        if not system.first.scheduleWrites(11) or not system.second.scheduleWrites(12):
            raise ValueError("original finite terminal callbacks were not scheduled")
        return root

    def publications(self):
        records = [list(record) for record in self.terminal.crucibleOutputInventory()]
        if len(records) > 65536:
            raise ValueError("native terminal inventory exceeds finite publication credit")
        publications = []
        for record in records:
            if len(record) != 6 or any(type(value) is not int or value < 0 for value in record):
                raise ValueError("native terminal publication has invalid typed fields")
            identifier, tick, ordinal, tie, parent, byte = record
            if not identifier or not ordinal or not tie or byte > 255:
                raise ValueError("native terminal publication has no original birth or byte")
            publications.append({
                "output_id": str(identifier), "tick": str(tick),
                "event_ordinal": str(ordinal), "tick_ordinal": str(tie),
                "causal_parent": str(parent), "facet": "serial",
                "terminal": self.terminal.path(), "payload": [byte],
            })
        return publications

    def acknowledge(self, original_identifier):
        if not self.terminal.crucibleAcknowledgeOutput(original_identifier):
            raise ValueError("terminal ACK does not name its original FIFO head")

    def rebind_resource_root(self, resource_root):
        self.resource_root = resource_root

    def describe_scope(self):
        return {
            "schema": "crucible.gem5.model-scope.v1",
            "model_id": "finite-terminal-callbacks-v1",
            "full_system": False, "complete_process_closure_qualified": False,
            "cpu_timing_qualified": False, "guest_readiness_qualified": False,
        }
