# SPDX-License-Identifier: MIT
"""Realizes the fixed Linux 9p probe board under a distinct source selection.

The selected diagnostic surface is partial. Opaque process images retain all
modeled bytes; this adapter grants neither common execution nor CPU timing
qualification. Device input commands are source-owned closed records.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import m5


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mechanism = load('crucible_device_board_assets', 'native-controller-arm-model.py')
projection = load('crucible_device_diagnostic_projection', 'causal-device-projection.py')

MAX_CONTROL_OPERATIONS = 128
MAX_CONTROL_BYTES = 16 * 1024 * 1024
MAX_CONTROL_RESPONSE = 256 * 1024
MAX_PUBLICATIONS = 16384
MAX_TERMINAL_ROWS = 32768
MAX_MONITOR_CALLBACKS = 16000000
MAX_MONITOR_TICK = 1000000000000
MAX_PAYLOAD = 4096
U64_MAX = (1 << 64) - 1


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def integer(value):
    if (not isinstance(value, str) or not value.isascii() or not value.isdecimal()
            or (len(value) > 1 and value[0] == '0') or int(value) > U64_MAX):
        raise ValueError('device control integer is not a canonical u64')
    return int(value)


class ArmLinuxNinepBoard(mechanism.ArmLinuxModel):
    """Realizes the board's two real modern MMIO transports before callbacks."""

    schema = 'crucible.gem5.arm-linux-ninep-board-native/1'
    output_basename = 'device.output'
    selection_schema = 'crucible.gem5.arm-linux-ninep-block-model.v1'
    model_id = 'arm-linux-vexpress-atomic-closed-ninep-functional-v1'

    def __init__(self, bootstrap, resource_root):
        selection = bootstrap.get('model')
        if not isinstance(selection, dict) or selection.get('schema') != self.selection_schema:
            raise ValueError('device model selection differs from its installed source')
        delegated = dict(bootstrap)
        delegated['model'] = dict(selection, schema='crucible.gem5.arm-linux-model.v1')
        super().__init__(delegated, resource_root)
        self.publication_bindings = {}
        self.publication_order = []
        self.acknowledged = set()
        self.control_operations = {}
        self.control_bytes = 0
        self.unresolved_control = None
        self.system = None
        self.input_phase_started = False

    def realize(self):
        from m5.objects import (
            ArmAtomicSimpleCPU, Root, SimpleMemory, SrcClockDomain,
            VirtIOHostRequest, VoltageDomain,
        )

        m5.ticks.setGlobalFrequency('1THz')
        m5.core.disableAllListeners()
        sys.path.insert(0, str(self.resource_root / 'configs'))
        from common.Benchmarks import SysConfig
        from common.FSConfig import makeArmSystem

        system = makeArmSystem(
            'atomic', 'VExpress_GEM5_V2', num_cpus=1,
            mdesc=SysConfig(mem='256MiB', disks=[]),
            bootloader=[str(self.resource_root / 'boot_v2.arm64')],
            cmdline='console=ttyAMA0 earlycon=pl011,0x1c090000 rdinit=/init panic=1 '
                    'lpj=1000000 init_on_alloc=0 init_on_free=0 nokaslr '
                    'net.ifnames=0 gem5_probe=9p',
        )
        system.voltage_domain = VoltageDomain()
        system.clk_domain = SrcClockDomain(clock='100MHz', voltage_domain=system.voltage_domain)
        system.workload.object_file = str(self.resource_root / 'kernel.elf')
        system.workload.initrd_filename = str(self.resource_root / 'initrd.img')
        system.cpu = ArmAtomicSimpleCPU(cpu_id=0, width=16)
        system.cpu.createThreads()
        system.cpu.createInterruptController()
        system.cpu.connectBus(system.membus)
        system.memory = SimpleMemory(range=system.mem_ranges[0])
        system.memory.port = system.membus.mem_side_ports
        system.terminal.port = 0
        system.terminal.outfile = 'none'
        system.ninep = VirtIOHostRequest(
            kind='9p', queue_size=256, request_capacity=16,
            maximum_payload_bytes=4096, mount_tag='crucible',
        )
        system.block = VirtIOHostRequest(
            kind='block', queue_size=256, request_capacity=16,
            maximum_payload_bytes=4096, capacity_sectors=2048,
        )
        if len(system.realview.vio) != 2:
            raise ValueError('source-owned VExpress transport census differs')
        # Preserve the native board-owned addresses, IRQs, port wiring and DT.
        system.realview.vio[0].vio = system.ninep
        system.realview.vio[0].modern = True
        system.realview.vio[1].vio = system.block
        system.realview.vio[1].modern = True
        root = Root(full_system=True, system=system)
        dtb = str(self.resource_root / 'output' / 'fixture.dtb')
        system.generateDtb(dtb)
        system.workload.dtb_filename = dtb
        m5.instantiate()
        self.system = system
        self.terminal = system.terminal
        self.terminal.crucibleConfigureOutput()
        if (not self.terminal.crucibleSetOutputParent(0)
                or not system.ninep.setExecutionParent(17)
                or not system.block.setExecutionParent(17)):
            raise ValueError('source-owned device lineage was not bound before callbacks')
        return root

    def native_inventory(self):
        inventory = m5.crucibleDeviceStateInventory([
            self.system.ninep.path(), self.system.block.path(), self.terminal.path(),
            self.system.realview.vio[0].path(), self.system.realview.vio[1].path(),
        ])
        rows = [list(row) for row in self.terminal.crucibleOutputInventory()]
        if len(rows) > MAX_TERMINAL_ROWS:
            raise ValueError('closed terminal monitor exceeds original FIFO custody')
        for row in rows:
            if (len(row) != 6 or any(type(value) is not int or value < 0 for value in row)
                    or not 0 < row[0] <= MAX_TERMINAL_ROWS
                    or row[1] > MAX_MONITOR_TICK
                    or not 0 < row[2] <= MAX_MONITOR_CALLBACKS
                    or not 0 < row[3] <= 1000000 or row[4] != 0 or row[5] > 255):
                raise ValueError('closed terminal monitor has unknown original birth geometry')
        return projection.project(inventory, self.terminal.path(), rows)

    def _publication(self, key, body):
        if (not integer(body['native_id']) or not integer(body['event_ordinal'])
                or not integer(body['tick_ordinal']) or integer(body['tick_ordinal']) > U64_MAX // 2):
            raise ValueError('native device publication has no finite original birth')
        integer(body['tick'])
        integer(body['causal_parent'])
        payload = body['payload']
        if (not isinstance(payload, list) or len(payload) > MAX_PAYLOAD
                or any(type(byte) is not int or not 0 <= byte <= 255 for byte in payload)):
            raise ValueError('native original publication exceeds its fixed byte extent')
        original = self.publication_bindings.get(key)
        if original is not None:
            if {key: value for key, value in original.items() if key != 'output_id'} != body:
                raise ValueError('original native publication body changed')
            return
        if len(self.publication_bindings) >= MAX_PUBLICATIONS:
            raise ValueError('original device publication binding credit exhausted')
        identifier = len(self.publication_bindings) + 1
        self.publication_bindings[key] = dict(body, output_id=str(identifier))
        self.publication_order.append(key)

    def reserve_callback_credit(self):
        # One fixed Atomic callback executes at most sixteen guest instructions.
        # Each native endpoint also admits at most sixteen frames/requests. The
        # larger batch reservation excludes binding exhaustion before callbacks.
        if len(self.publication_bindings) + 128 > MAX_PUBLICATIONS:
            raise ValueError('device publication binding credit exhausted before callback')

    def validate_run(self, request):
        if integer(request['exclusive_tick']) > MAX_MONITOR_TICK:
            raise ValueError('device monitor grant exceeds its source-owned clock extent')
        if request['exact_range'] is not None:
            raise ValueError('device monitor cannot acquire common full-position admission')

    def maximum_native_step_events(self, remaining, exact_range):
        if exact_range is not None:
            raise ValueError('closed boot monitor has no common full-position admission')
        rows = self.terminal.crucibleOutputInventory()
        position = m5.crucibleEventPosition()
        ordinal = integer(position['ordinal'])
        if m5.curTick() >= MAX_MONITOR_TICK or ordinal >= MAX_MONITOR_CALLBACKS:
            raise ValueError('closed boot monitor native event/time credit exhausted before callback')
        # Atomic width sixteen services at most sixteen instruction/micro-op
        # stores per tick. Each PL011 data-register write publishes one byte.
        # This worst-case reservation precedes the entire bounded native batch.
        available = (MAX_TERMINAL_ROWS - len(rows)) // 16
        if available <= 0:
            raise ValueError('closed terminal FIFO credit exhausted before callbacks')
        if getattr(self, 'input_phase_started', False):
            return 1
        return min(remaining, available, 4096, MAX_MONITOR_CALLBACKS - ordinal)

    def control_retry(self, request):
        retained = self.control_operations.get(request['operation'])
        return None if retained is None else retained[1]

    def describe_scope(self):
        scope = super().describe_scope()
        scope.update({
            'model_id': self.model_id, 'device_parity_qualified': False,
            'device_slots': ['ninep:0x1c130000', 'block:0x1c140000'],
            'closed_terminal_monitor': True, 'external_serial_route': False,
            'native_device_execution_parent': '17', 'native_terminal_parent': '0',
            'maximum_terminal_rows': str(MAX_TERMINAL_ROWS),
            'maximum_native_callbacks': str(MAX_MONITOR_CALLBACKS),
            'maximum_native_tick': str(MAX_MONITOR_TICK),
            'diagnostic_scope': projection.PROJECTION_SCOPE,
            'diagnostic_maximum_object_bytes': str(4 * 1024 * 1024),
            'diagnostic_omissions': ['cpu', 'ram', 'cache', 'unselected-devices',
                                    'complete-polymorphic-payloads', 'descriptor-and-ring-cache-fields',
                                    'frozen-request-dma-span-fields', 'full-alias-ledger-and-rng-bodies'],
        })
        return scope
