# SPDX-License-Identifier: MIT
"""Owns a fixed ARM Linux Net/block model and original finite device custody.

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


class ArmLinuxDeviceModel(mechanism.ArmLinuxModel):
    """Realizes the board's two real modern MMIO transports before callbacks."""

    schema = 'crucible.gem5.arm-linux-devices-native/1'
    output_basename = 'device.output'
    selection_schema = 'crucible.gem5.arm-linux-net-block-model.v1'
    model_id = 'arm-linux-vexpress-atomic-net-block-functional-v1'

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
            VirtIOHostRequest, VirtIONet, VoltageDomain,
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
                    'net.ifnames=0 gem5_probe=block',
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
        system.net = VirtIONet(queue_size=256, frame_capacity=16, maximum_frame_bytes=4096)
        system.block = VirtIOHostRequest(
            kind='block', queue_size=256, request_capacity=16,
            maximum_payload_bytes=4096, capacity_sectors=2048,
        )
        if len(system.realview.vio) != 2:
            raise ValueError('source-owned VExpress transport census differs')
        # Preserve the native board-owned addresses, IRQs, port wiring and DT.
        system.realview.vio[0].vio = system.net
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
                or not system.net.setExecutionParent(17)
                or not system.block.setExecutionParent(17)):
            raise ValueError('source-owned device lineage was not bound before callbacks')
        return root

    def native_inventory(self):
        inventory = m5.crucibleDeviceStateInventory([
            self.system.net.path(), self.system.block.path(), self.terminal.path(),
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

    def publications(self):
        # Serial has no external route in this closed boot-monitor profile.
        # Every original native FIFO birth and byte remains retained separately;
        # no serial record is rewritten as a device/public coordinator receipt.
        for record in self.system.net.crucibleTxPublicationInventory():
            identifier, tick, parent, ordinal, tie = record
            self._publication(('network', identifier), {
                'native_id': str(identifier), 'facet': 'network',
                'endpoint': self.system.net.path(), 'tick': str(tick),
                'event_ordinal': str(ordinal), 'tick_ordinal': str(tie),
                'causal_parent': str(parent),
                'payload': list(self.system.net.crucibleTxPublicationBytes(identifier)),
            })
        for record in self.system.block.crucibleRequestPublicationInventory():
            identifier, tick, parent, opcode, sector, tag, count, ordinal, tie = record
            self._publication(('block_request', identifier), {
                'native_id': str(identifier), 'facet': 'block_request',
                'endpoint': self.system.block.path(), 'tick': str(tick),
                'event_ordinal': str(ordinal), 'tick_ordinal': str(tie),
                'causal_parent': str(parent), 'opcode': str(opcode),
                'sector': str(sector), 'tag': str(tag), 'count': str(count),
                'payload': list(self.system.block.crucibleRequestPublicationBytes(identifier)),
            })
        completions = list(self.system.block.pendingCompletionMetadata())
        if len(completions) % 9:
            raise ValueError('native block completion has unknown geometry')
        for offset in range(0, len(completions), 9):
            identifier, tick, ordinal, tie, status, count, execution, parent, incarnation = completions[offset:offset + 9]
            self._publication(('block_completion', identifier), {
                'native_id': str(identifier), 'facet': 'block_completion',
                'endpoint': self.system.block.path(), 'tick': str(tick),
                'event_ordinal': str(ordinal), 'tick_ordinal': str(tie),
                'causal_parent': str(parent), 'execution_parent': str(execution),
                'queue_incarnation': str(incarnation), 'status': str(status),
                'count': str(count), 'payload': [],
            })
        return [self.publication_bindings[key] for key in self.publication_order
                if key not in self.acknowledged]

    def acknowledge(self, original_identifier):
        if not 0 < original_identifier <= len(self.publication_order):
            raise ValueError('device ACK is outside the original binding roster')
        key = self.publication_order[original_identifier - 1]
        if key in self.acknowledged:
            return
        facet, native_id = key
        if facet == 'serial':
            accepted = self.terminal.crucibleAcknowledgeOutput(native_id)
        elif facet == 'network':
            accepted = self.system.net.acknowledgeTx(native_id)
        elif facet == 'block_request':
            accepted = self.system.block.acknowledgeRequest(native_id)
        else:
            accepted = self.system.block.retireCompleted(native_id)
        if not accepted:
            raise ValueError('device ACK differs from its original native FIFO head')
        self.acknowledged.add(key)

    def validate_control(self, request):
        if not isinstance(request, dict) or set(request) != {
            'kind', 'operation', 'action', 'native_id', 'tick', 'causal_parent', 'status', 'payload'
        } or request['kind'] != 'device_control':
            raise ValueError('unknown native device input body')
        if request['action'] not in ('network_rx', 'block_reply'):
            raise ValueError('unknown native device input action')
        operation = request['operation']
        if not isinstance(operation, str) or not 0 < len(operation) <= 256:
            raise ValueError('native device input lacks an original operation identity')
        for key in ('native_id', 'tick', 'causal_parent', 'status'):
            integer(request[key])
        if not integer(request['native_id']) or integer(request['status']) > 2:
            raise ValueError('native device input identity/status is outside source scope')
        payload = request['payload']
        if (not isinstance(payload, list) or len(payload) > MAX_PAYLOAD
                or any(type(byte) is not int or not 0 <= byte <= 255 for byte in payload)):
            raise ValueError('native device input exceeds its source-owned byte extent')
        if request['action'] == 'network_rx' and (not 14 <= len(payload) <= MAX_PAYLOAD or integer(request['status'])):
            raise ValueError('native network input has invalid frame/status geometry')
        if operation in self.control_operations:
            if self.control_operations[operation][0] != request:
                raise ValueError('original native device input body changed')
            return
        if (self.unresolved_control is not None or len(self.control_operations) >= MAX_CONTROL_OPERATIONS
                or self.control_bytes + len(canonical(request)) + MAX_CONTROL_RESPONSE > MAX_CONTROL_BYTES):
            raise ValueError('original device input receipt credit remains held')
        if integer(request['tick']) >= MAX_MONITOR_TICK:
            raise ValueError('sealed device input exceeds its source-owned clock extent')
        if integer(request['tick']) <= m5.curTick():
            raise ValueError('sealed device input must occur strictly after the current native cut')

    def control(self, request):
        operation = request['operation']
        if operation in self.control_operations:
            return self.control_operations[operation][1]
        self.unresolved_control = dict(request)
        self.control_bytes += len(canonical(request))
        native_id = integer(request['native_id'])
        tick = integer(request['tick'])
        parent = integer(request['causal_parent'])
        if request['action'] == 'network_rx':
            accepted = self.system.net.stageRx(native_id, tick, parent, request['payload'])
        else:
            accepted = self.system.block.stageReply(native_id, tick, parent,
                                                    integer(request['status']), request['payload'])
        if accepted:
            self.input_phase_started = True
        return {'accepted': bool(accepted)}

    def retain_control_response(self, request, response, before, after):
        operation = request['operation']
        if operation in self.control_operations:
            return self.control_operations[operation][1]
        result = {'kind': 'device_controlled', 'operation': operation, 'original': request,
                  'accepted': response['accepted'], 'before': before, 'after': after}
        body = canonical(result)
        if len(body) > MAX_CONTROL_RESPONSE:
            raise ValueError('original device control response exceeds its reservation')
        self.control_bytes += len(body)
        self.control_operations[operation] = (dict(request), result)
        self.unresolved_control = None
        return result

    def refuse_control(self, request, boundary, credit):
        # No native input has been staged. Retain this original refusal separately
        # from successful device responses and from execution/output ACK custody.
        operation = request['operation']
        if operation in self.control_operations:
            return self.control_operations[operation][1]
        result = {'kind': 'device_control_refused', 'operation': operation, 'original': request,
                  'boundary': boundary, 'reason': 'diagnostic_credit', 'credit': credit}
        self.control_operations[operation] = (dict(request), result)
        self.control_bytes += len(canonical(request)) + len(canonical(result))
        return result

    def describe_scope(self):
        scope = super().describe_scope()
        scope.update({
            'model_id': self.model_id, 'device_parity_qualified': False,
            'device_slots': ['net:0x1c130000', 'block:0x1c140000'],
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
