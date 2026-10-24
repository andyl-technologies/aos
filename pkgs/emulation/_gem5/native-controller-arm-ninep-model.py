# SPDX-License-Identifier: MIT
"""Owns a finite Linux 9p tree and the original native request/reply history.

The source-selected server negotiates 4096-byte messages before file traffic.
File bytes, FIDs, replies and strong future events stay inside the native process
image. There is no host filesystem, external input route or common authority.
"""

import copy
import importlib.util
from pathlib import Path

import m5
import m5.event


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


board = load('crucible_fixed_ninep_board', 'native-controller-arm-ninep-board.py')
block_model = load('crucible_fixed_ninep_boot_disk', 'native-controller-arm-block-model.py')
backend = load('crucible_fixed_owned_ninep', 'closed-memory-ninep-bounded.py')
DIAGNOSTIC_SCOPE = 'native-event-device-terminal-and-closed-ninep-block-metadata-v1'


class NinepReaction(m5.event.Event):
    """Retains a sealed original request until its genuine future tree operation."""

    def __init__(self, owner, identifier):
        super().__init__()
        self.owner = owner
        self.identifier = identifier

    def __call__(self):
        command = self.owner.ninep.commands[self.identifier]
        reply = self.owner.ninep.react(self.identifier, m5.crucibleEventPosition())
        if not self.owner.system.ninep.stageReply(
            self.identifier, command['completion_tick'], backend.BACKEND_PARENT, 0, list(reply)
        ):
            raise ValueError('closed 9p reply differs from its original native writable custody')


class NinepRequestHandler(m5.event.Event):
    """Binds immutable server commands inside the actual native request birth."""

    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def __call__(self):
        current = backend.positions.event_position(m5.crucibleEventPosition(), True)
        for record in self.owner.system.ninep.crucibleRequestPublicationInventory():
            metadata = list(record)
            payload = bytes(self.owner.system.ninep.crucibleRequestPublicationBytes(metadata[0]))
            command, accepted = self.owner.ninep.accept_original(metadata, payload)
            if not accepted:
                continue
            if current != (metadata[1], metadata[7], metadata[8]):
                raise ValueError('closed 9p request differs from its actual native callback')
            event = NinepReaction(self.owner, metadata[0])
            self.owner.ninep_events[metadata[0]] = event
            m5.event.getEventQueue(0).schedule(event, command['reaction_tick'])


class ArmLinuxNinepModel(board.ArmLinuxNinepBoard):
    """Realizes one distinct closed server alongside the native-owned boot disk."""

    schema = 'crucible.gem5.arm-linux-closed-ninep-native/1'
    output_basename = 'ninep-lifecycle.output'
    selection_schema = 'crucible.gem5.arm-linux-closed-ninep-model.v1'
    model_id = 'arm-linux-vexpress-atomic-closed-ninep-functional-v1'

    def __init__(self, bootstrap, resource_root):
        super().__init__(bootstrap, resource_root)
        self.disk = block_model.backend.ClosedMemoryBlock()
        self.backend_events = {}
        self.birth_handler = block_model.RequestBirthHandler(self)
        self.ninep = backend.ClosedMemoryNinep()
        self.ninep_events = {}
        self.ninep_handler = NinepRequestHandler(self)

    def realize(self):
        root = super().realize()
        if (not m5.crucibleConfigureDeviceBoundaries()
                or not self.system.block.bindRequestHandler(self.birth_handler)
                or not self.system.ninep.bindRequestHandler(self.ninep_handler)):
            raise ValueError('closed native server birth hooks were not bound before callbacks')
        return root

    def reserve_callback_credit(self):
        super().reserve_callback_credit()
        self.disk.reserve_callback()
        self.ninep.reserve_callback()

    def publications(self):
        for device, facet, owner in (
            (self.system.ninep, 'ninep', self.ninep),
            (self.system.block, 'block', self.disk),
        ):
            for record in device.crucibleRequestPublicationInventory():
                identifier, tick, parent, opcode, sector, tag, count, ordinal, tie = record
                if identifier not in owner.commands:
                    raise ValueError('native request has no original owned future command')
                self._publication((facet + '_request', identifier), {
                    'native_id': str(identifier), 'facet': facet + '_request',
                    'endpoint': device.path(), 'tick': str(tick),
                    'event_ordinal': str(ordinal), 'tick_ordinal': str(tie),
                    'causal_parent': str(parent), 'opcode': str(opcode),
                    'sector': str(sector), 'tag': str(tag), 'count': str(count),
                    'payload': list(device.crucibleRequestPublicationBytes(identifier)),
                })
            for record in device.crucibleCompletionInventory():
                metadata = list(record)
                owner.observe_completion(metadata)
                identifier, tick, ordinal, tie, status, count, execution, parent, incarnation, head = metadata
                self._publication((facet + '_completion', identifier), {
                    'native_id': str(identifier), 'facet': facet + '_completion',
                    'endpoint': device.path(), 'tick': str(tick),
                    'event_ordinal': str(ordinal), 'tick_ordinal': str(tie),
                    'causal_parent': str(parent), 'execution_parent': str(execution),
                    'queue_incarnation': str(incarnation), 'status': str(status),
                    'descriptor_head': str(head), 'count': str(count), 'payload': [],
                })
        return [self.publication_bindings[key] for key in self.publication_order
                if key not in self.acknowledged]

    def acknowledge(self, original_identifier):
        if not 0 < original_identifier <= len(self.publication_order):
            raise ValueError('closed server ACK is outside original publication custody')
        facet, native_id = key = self.publication_order[original_identifier - 1]
        if facet.startswith('ninep_'):
            device, owner = self.system.ninep, self.ninep
        elif facet.startswith('block_'):
            device, owner = self.system.block, self.disk
        else:
            raise ValueError('closed server ACK has an unknown administration facet')
        # Both pinned backends borrow command state read-only here; validation
        # mutates only their finite administration dictionary.
        candidate = copy.copy(owner)
        candidate.acknowledgements = owner.acknowledgements.copy()
        candidate.acknowledge(facet, native_id, m5.crucibleEventPosition())
        if key in self.acknowledged:
            return
        accepted = (device.acknowledgeRequest(native_id) if facet.endswith('_request')
                    else device.retireCompleted(native_id))
        if not accepted:
            raise ValueError('closed server administration differs from original native custody')
        owner.acknowledgements = candidate.acknowledgements
        self.acknowledged.add(key)

    def validate_control(self, request):
        raise ValueError('closed native server admits no external filesystem or disk input')

    def native_inventory(self):
        inventory = super().native_inventory()
        for name, owner, events in (
            ('closed_block_backend', self.disk, self.backend_events),
            ('closed_ninep_backend', self.ninep, self.ninep_events),
        ):
            domain = owner.inventory()
            domain['pending_event_rows'] = [
                [identifier, bool(event.scheduled()), str(event.when()) if event.scheduled() else None]
                for identifier, event in events.items()
            ]
            if len(board.canonical(domain)) > backend.MAX_DIAGNOSTIC_BYTES:
                raise ValueError('closed server observation exceeds its source-selected reservation')
            inventory[name] = domain
        inventory['diagnostic_scope'] = DIAGNOSTIC_SCOPE
        inventory['native_publication_boundary'] = m5.crucibleDeviceBoundaryState()
        inventory['unsupported_domains'] += [
            'closed-file-fid-and-disk-bytes-commitment-only',
            'closed-managed-python-events-and-handler-payloads-opaque-only',
            'closed-original-server-command-reply-and-ack-bodies-opaque-only',
        ]
        return inventory

    def describe_scope(self):
        scope = super().describe_scope()
        scope.update({
            'model_id': self.model_id, 'diagnostic_scope': DIAGNOSTIC_SCOPE,
            'closed_block_backend': {
                'schema': 'crucible.gem5.closed-block-backend-policy.v1',
                'backing_bytes': str(block_model.backend.DISK_BYTES), 'initial_bytes': 'zero',
                'maximum_original_commands': str(block_model.backend.MAX_OPERATIONS),
                'maximum_payload_bytes': str(block_model.backend.MAX_PAYLOAD),
                'reaction_delay_ps': str(block_model.backend.REACTION_DELAY),
                'completion_delay_ps': str(block_model.backend.COMPLETION_DELAY),
                'execution_parent': '17', 'backend_parent': '23',
                'diagnostic_maximum_bytes': str(block_model.backend.MAX_DIAGNOSTIC_BYTES),
                'external_inputs_admitted': False,
            },
            'closed_ninep_backend': {
                'schema': 'crucible.gem5.closed-ninep-backend-policy.v1',
                'mount_tag': 'crucible', 'protocol': '9P2000.L',
                'maximum_original_commands': str(backend.MAX_OPERATIONS),
                'maximum_message_bytes': str(backend.MAX_PAYLOAD),
                'maximum_file_bytes': '65536', 'maximum_fids': '64',
                'reaction_delay_ps': str(backend.REACTION_DELAY),
                'completion_delay_ps': str(backend.COMPLETION_DELAY),
                'execution_parent': '17', 'backend_parent': '23',
                'diagnostic_maximum_bytes': str(backend.MAX_DIAGNOSTIC_BYTES),
                'external_inputs_admitted': False,
            },
        })
        return scope
