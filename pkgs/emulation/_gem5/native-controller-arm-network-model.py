# SPDX-License-Identifier: MIT
"""Owns fixed Linux TX/RX, zero-disk effects and all original native custody.

The fixed endogenous loopback has no host networking or external input surface.
Partial typed diagnostics remain distinct from opaque process-image preservation.
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


board = load('crucible_fixed_network_board', 'native-controller-arm-network-board.py')
block_model = load('crucible_fixed_owned_disk_callbacks', 'native-controller-arm-block-model.py')
network_backend = load('crucible_fixed_owned_loopback', 'closed-network-loopback.py')
DIAGNOSTIC_SCOPE = 'native-event-device-terminal-and-closed-network-block-metadata-v1'


class NetworkReaction(m5.event.Event):
    """Retains one actual frame until its ordered endogenous receive reaction."""

    def __init__(self, owner, identifier):
        super().__init__()
        self.owner = owner
        self.identifier = identifier

    def __call__(self):
        command, accepted = self.owner.network.react(self.identifier, m5.crucibleEventPosition())
        if accepted and not self.owner.system.net.stageRx(
            self.identifier, command['delivery_tick'], network_backend.BACKEND_PARENT,
            list(command['payload']),
        ):
            raise ValueError('closed network original RX no longer matches native input custody')


class NetworkTransmitHandler(m5.event.Event):
    """Owns future input commands synchronously inside actual TX publication."""

    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def __call__(self):
        position = network_backend.event_position(m5.crucibleEventPosition(), True)
        for record in self.owner.system.net.crucibleTxPublicationInventory():
            metadata = list(record)
            payload = bytes(self.owner.system.net.crucibleTxPublicationBytes(metadata[0]))
            command, accepted = self.owner.network.accept_original(metadata, payload)
            if not accepted:
                continue
            if position != (metadata[1], metadata[3], metadata[4]):
                raise ValueError('new closed loopback command differs from actual TX birth')
            event = NetworkReaction(self.owner, metadata[0])
            self.owner.network_events[metadata[0]] = event
            m5.event.getEventQueue(0).schedule(event, command['reaction_tick'])


class ArmLinuxNetworkModel(board.ArmLinuxNetworkBoard):
    """Realizes a distinct closed Ethernet lifecycle with owned boot disk state."""

    schema = 'crucible.gem5.arm-linux-closed-network-native/1'
    output_basename = 'network-lifecycle.output'
    selection_schema = 'crucible.gem5.arm-linux-closed-network-model.v1'
    model_id = 'arm-linux-vexpress-atomic-closed-network-functional-v1'

    def __init__(self, bootstrap, resource_root):
        super().__init__(bootstrap, resource_root)
        self.disk = block_model.backend.ClosedMemoryBlock()
        self.backend_events = {}
        self.birth_handler = block_model.RequestBirthHandler(self)
        self.network = network_backend.ClosedNetworkLoopback()
        self.network_events = {}
        self.transmit_handler = NetworkTransmitHandler(self)

    def realize(self):
        root = super().realize()
        if (not m5.crucibleConfigureDeviceBoundaries()
                or not self.system.block.bindRequestHandler(self.birth_handler)
                or not self.system.net.bindTransmitHandler(self.transmit_handler)):
            raise ValueError('closed native device birth hooks were not bound before callbacks')
        return root

    def reserve_callback_credit(self):
        super().reserve_callback_credit()
        self.disk.reserve_callback()
        self.network.reserve_callback()

    def publications(self):
        for record in self.system.net.crucibleTxPublicationInventory():
            identifier, tick, parent, ordinal, tie = record
            if identifier not in self.network.commands:
                raise ValueError('native TX has no original owned future receive command')
            self._publication(('network_tx', identifier), {
                'native_id': str(identifier), 'facet': 'network_tx',
                'endpoint': self.system.net.path(), 'tick': str(tick),
                'event_ordinal': str(ordinal), 'tick_ordinal': str(tie),
                'causal_parent': str(parent),
                'payload': list(self.system.net.crucibleTxPublicationBytes(identifier)),
            })
        completions = list(self.system.net.pendingRxCompletionMetadata())
        if len(completions) % 7:
            raise ValueError('closed native receive completion has unknown geometry')
        for offset in range(0, len(completions), 7):
            metadata = completions[offset:offset + 7]
            self.network.observe_completion(metadata)
            identifier, tick, ordinal, tie, execution, parent, count = metadata
            self._publication(('network_rx', identifier), {
                'native_id': str(identifier), 'facet': 'network_rx',
                'endpoint': self.system.net.path(), 'tick': str(tick),
                'event_ordinal': str(ordinal), 'tick_ordinal': str(tie),
                'causal_parent': str(parent), 'execution_parent': str(execution),
                'count': str(count), 'payload': list(self.network.commands[identifier]['payload']),
            })
        for record in self.system.block.crucibleRequestPublicationInventory():
            identifier, tick, parent, opcode, sector, tag, count, ordinal, tie = record
            if identifier not in self.disk.commands:
                raise ValueError('native disk request has no original owned backend command')
            self._publication(('block_request', identifier), {
                'native_id': str(identifier), 'facet': 'block_request',
                'endpoint': self.system.block.path(), 'tick': str(tick),
                'event_ordinal': str(ordinal), 'tick_ordinal': str(tie),
                'causal_parent': str(parent), 'opcode': str(opcode), 'sector': str(sector),
                'tag': str(tag), 'count': str(count),
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
            raise ValueError('closed network ACK is outside original publication custody')
        facet, native_id = key = self.publication_order[original_identifier - 1]
        backend = self.network if facet in ('network_tx', 'network_rx') else self.disk
        # Both pinned backends borrow command state read-only here; validation
        # mutates only their finite administration dictionary.
        candidate = copy.copy(backend)
        candidate.acknowledgements = backend.acknowledgements.copy()
        candidate.acknowledge(facet, native_id, m5.crucibleEventPosition())
        if key in self.acknowledged:
            return
        if facet == 'network_tx':
            accepted = self.system.net.acknowledgeTx(native_id)
        elif facet == 'network_rx':
            accepted = self.system.net.retireRx(native_id)
        elif facet == 'block_request':
            accepted = self.system.block.acknowledgeRequest(native_id)
        elif facet == 'block_completion':
            accepted = self.system.block.retireCompleted(native_id)
        else:
            raise ValueError('closed network ACK has an unknown native facet')
        if not accepted:
            raise ValueError('closed device administration differs from its original native FIFO head')
        # Validate and allocate the finite original ACK ledger before native
        # administration. A rejected FIFO ACK cannot mark it as accepted.
        backend.acknowledgements = candidate.acknowledgements
        self.acknowledged.add(key)

    def validate_control(self, request):
        raise ValueError('closed native loopback admits no external frame or disk input')

    def native_inventory(self):
        inventory = super().native_inventory()
        disk = self.disk.inventory()
        disk['pending_event_rows'] = [
            [identifier, bool(event.scheduled()), str(event.when()) if event.scheduled() else None]
            for identifier, event in self.backend_events.items()
        ]
        network = self.network.inventory()
        network['pending_event_rows'] = [
            [identifier, bool(event.scheduled()), str(event.when()) if event.scheduled() else None]
            for identifier, event in self.network_events.items()
        ]
        for domain in (disk, network):
            if len(board.canonical(domain)) > network_backend.MAX_DIAGNOSTIC_BYTES:
                raise ValueError('closed device observation exceeds its source-selected reservation')
        inventory['diagnostic_scope'] = DIAGNOSTIC_SCOPE
        inventory['closed_block_backend'] = disk
        inventory['closed_network_backend'] = network
        inventory['native_publication_boundary'] = m5.crucibleDeviceBoundaryState()
        inventory['unsupported_domains'] += [
            'closed-disk-and-network-original-bytes-commitment-only',
            'closed-managed-python-events-and-handler-payloads-opaque-only',
        ]
        return inventory

    def describe_scope(self):
        scope = super().describe_scope()
        scope.update({'model_id': self.model_id, 'diagnostic_scope': DIAGNOSTIC_SCOPE,
                      'closed_block_backend': {
                          'schema': 'crucible.gem5.closed-block-backend-policy.v1',
                          'backing_bytes': str(block_model.backend.DISK_BYTES),
                          'initial_bytes': 'zero',
                          'maximum_original_commands': str(block_model.backend.MAX_OPERATIONS),
                          'maximum_payload_bytes': str(block_model.backend.MAX_PAYLOAD),
                          'reaction_delay_ps': str(block_model.backend.REACTION_DELAY),
                          'completion_delay_ps': str(block_model.backend.COMPLETION_DELAY),
                          'execution_parent': str(block_model.backend.DEVICE_PARENT),
                          'backend_parent': str(block_model.backend.BACKEND_PARENT),
                          'diagnostic_maximum_bytes': str(block_model.backend.MAX_DIAGNOSTIC_BYTES),
                          'external_inputs_admitted': False,
                      },
                      'closed_network_backend': {
                          'schema': 'crucible.gem5.closed-loopback-policy.v1',
                          'maximum_original_frames': str(network_backend.MAX_OPERATIONS),
                          'maximum_payload_bytes': str(network_backend.MAX_PAYLOAD),
                          'reaction_delay_ps': str(network_backend.REACTION_DELAY),
                          'minimum_delivery_delay_ps': str(network_backend.DELIVERY_DELAY),
                          'execution_parent': str(network_backend.DEVICE_PARENT),
                          'backend_parent': str(network_backend.BACKEND_PARENT),
                          'external_inputs_admitted': False,
                      }})
        return scope
