# SPDX-License-Identifier: MIT
"""Owns one closed Linux block lifecycle and its disk/native event custody.

The fixed disk, original commands, pending managed PyEvents, native replies and
administrative ACK positions remain inside the opaque process image. No host
backing, input socket or external reply driver supplies hidden disk state.
"""

import importlib.util
from pathlib import Path

import m5
import m5.event


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


base = load('crucible_fixed_arm_device_model', 'native-controller-arm-devices-model.py')
backend = load('crucible_owned_closed_block', 'closed-memory-block.py')
DIAGNOSTIC_SCOPE = 'native-event-device-terminal-and-closed-block-metadata-v1'


class BlockReaction(m5.event.Event):
    """Retains one original backend command until its genuine native callback."""

    def __init__(self, owner, identifier):
        super().__init__()
        self.owner = owner
        self.identifier = identifier

    def __call__(self):
        command = self.owner.disk.commands[self.identifier]
        reply = self.owner.disk.react(self.identifier, m5.crucibleEventPosition())
        if not self.owner.system.block.stageReply(
            self.identifier, command['completion_tick'], backend.BACKEND_PARENT, 0, list(reply)
        ):
            raise ValueError('original closed backend reply no longer matches native frontend custody')


class RequestBirthHandler(m5.event.Event):
    """Binds exact backend commands synchronously inside genuine request birth."""

    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def __call__(self):
        position = m5.crucibleEventPosition()
        current = backend.event_position(position, True)
        for record in self.owner.system.block.crucibleRequestPublicationInventory():
            metadata = list(record)
            payload = bytes(self.owner.system.block.crucibleRequestPublicationBytes(metadata[0]))
            command, accepted = self.owner.disk.accept_original(metadata, payload)
            if not accepted:
                continue
            if current != (metadata[1], metadata[7], metadata[8]):
                raise ValueError('new closed backend command differs from the actual request callback')
            event = BlockReaction(self.owner, metadata[0])
            self.owner.backend_events[metadata[0]] = event
            m5.event.getEventQueue(0).schedule(event, command['reaction_tick'])


class ArmLinuxBlockModel(base.ArmLinuxDeviceModel):
    """Realizes fixed application/disk assets under a distinct closed dialect."""

    schema = 'crucible.gem5.arm-linux-closed-block-native/1'
    output_basename = 'block-lifecycle.output'
    selection_schema = 'crucible.gem5.arm-linux-closed-block-model.v1'
    model_id = 'arm-linux-vexpress-atomic-closed-block-functional-v1'

    def __init__(self, bootstrap, resource_root):
        super().__init__(bootstrap, resource_root)
        self.disk = backend.ClosedMemoryBlock()
        self.backend_events = {}
        self.birth_handler = RequestBirthHandler(self)

    def realize(self):
        root = super().realize()
        if (not m5.crucibleConfigureDeviceBoundaries()
                or not self.system.block.bindRequestHandler(self.birth_handler)):
            raise ValueError('source-owned block boundary/birth hook was not bound before callbacks')
        return root

    def reserve_callback_credit(self):
        super().reserve_callback_credit()
        self.disk.reserve_callback()

    def publications(self):
        if self.system.net.crucibleTxPublicationInventory():
            raise ValueError('closed block fixture produced an unadmitted network publication')
        for record in self.system.block.crucibleRequestPublicationInventory():
            identifier, tick, parent, opcode, sector, tag, count, ordinal, tie = record
            if identifier not in self.disk.commands:
                raise ValueError('native block request has no original owned backend command')
            self._publication(('block_request', identifier), {
                'native_id': str(identifier), 'facet': 'block_request',
                'endpoint': self.system.block.path(), 'tick': str(tick),
                'event_ordinal': str(ordinal), 'tick_ordinal': str(tie),
                'causal_parent': str(parent), 'opcode': str(opcode),
                'sector': str(sector), 'tag': str(tag), 'count': str(count),
                'payload': list(self.system.block.crucibleRequestPublicationBytes(identifier)),
            })
        for record in self.system.block.crucibleCompletionInventory():
            metadata = list(record)
            self.disk.observe_completion(metadata)
            identifier, tick, ordinal, tie, status, count, execution, parent, incarnation, head = metadata
            self._publication(('block_completion', identifier), {
                'native_id': str(identifier), 'facet': 'block_completion',
                'endpoint': self.system.block.path(), 'tick': str(tick),
                'event_ordinal': str(ordinal), 'tick_ordinal': str(tie),
                'causal_parent': str(parent), 'execution_parent': str(execution),
                'queue_incarnation': str(incarnation), 'status': str(status),
                'descriptor_head': str(head), 'count': str(count), 'payload': [],
            })
        return [self.publication_bindings[key] for key in self.publication_order
                if key not in self.acknowledged]

    def acknowledge(self, original_identifier):
        if not 0 < original_identifier <= len(self.publication_order):
            raise ValueError('closed disk ACK is outside original publication custody')
        facet, native_id = self.publication_order[original_identifier - 1]
        self.disk.acknowledge(facet, native_id, m5.crucibleEventPosition())
        super().acknowledge(original_identifier)

    def validate_control(self, request):
        # Internal fixed disk reactions are sealed at actual request birth.
        # This profile has no independent/exogenous RX or reply input surface.
        raise ValueError('closed block model admits no external device control input')

    def native_inventory(self):
        inventory = super().native_inventory()
        disk = self.disk.inventory()
        disk['native_publication_boundary'] = m5.crucibleDeviceBoundaryState()
        disk['pending_event_rows'] = [
            [identifier, bool(event.scheduled()), str(event.when()) if event.scheduled() else None]
            for identifier, event in self.backend_events.items()
        ]
        if len(base.canonical(disk)) > backend.MAX_DIAGNOSTIC_BYTES:
            raise ValueError('closed backend observation exceeds its source-selected reservation')
        inventory['diagnostic_scope'] = DIAGNOSTIC_SCOPE
        inventory['closed_block_backend'] = disk
        inventory['unsupported_domains'] += [
            'closed-disk-backing-and-original-command-bodies-commitment-only',
            'closed-python-handler-and-managed-reaction-event-payloads-opaque-only',
        ]
        return inventory

    def describe_scope(self):
        scope = super().describe_scope()
        scope.update({
            'model_id': self.model_id, 'diagnostic_scope': DIAGNOSTIC_SCOPE,
            'closed_block_backend': {
                'schema': 'crucible.gem5.closed-block-backend-policy.v1',
                'backing_bytes': str(backend.DISK_BYTES), 'initial_bytes': 'zero',
                'maximum_original_commands': str(backend.MAX_OPERATIONS),
                'maximum_payload_bytes': str(backend.MAX_PAYLOAD),
                'reaction_delay_ps': str(backend.REACTION_DELAY),
                'completion_delay_ps': str(backend.COMPLETION_DELAY),
                'execution_parent': str(backend.DEVICE_PARENT),
                'backend_parent': str(backend.BACKEND_PARENT),
                'diagnostic_maximum_bytes': str(backend.MAX_DIAGNOSTIC_BYTES),
                'external_inputs_admitted': False,
            },
        })
        return scope
