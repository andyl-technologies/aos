# SPDX-License-Identifier: MIT
"""Owns finite original TX frames and their closed future RX reactions.

This object lives inside the emulator process image. It is not a host network
bridge, input authority, checkpoint serializer, or public readiness certificate.
Every original frame, reaction, completion and first ACK position is retained.
"""

import hashlib
import json


MAX_OPERATIONS = 64
MAX_PAYLOAD = 4096
MAX_DIAGNOSTIC_BYTES = 65536
MAX_DIAGNOSTIC_ROW = 384
MAX_CALLBACKS = 16000000
MAX_TICK = 1000000000000
REACTION_DELAY = 10000
DELIVERY_DELAY = 1
DEVICE_PARENT = 17
BACKEND_PARENT = 23


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def integer(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('closed network original has invalid integer geometry')
    return value


def event_position(value, active):
    if (not isinstance(value, dict) or set(value) != {'tick', 'ordinal', 'tick_ordinal', 'active'}
            or value['active'] is not active):
        raise ValueError('closed network event lacks its genuine native execution state')
    result = []
    for name, maximum in (('tick', MAX_TICK), ('ordinal', MAX_CALLBACKS), ('tick_ordinal', 1000000)):
        number = value[name]
        if (not isinstance(number, str) or not number.isascii() or not number.isdecimal()
                or (len(number) > 1 and number[0] == '0')):
            raise ValueError('closed network native position is not canonical')
        result.append(integer(int(number), maximum))
    if active and (not result[1] or not result[2]):
        raise ValueError('closed network reaction has no actual callback identity')
    return tuple(result)


class ClosedNetworkLoopback:
    """Retains each original Ethernet frame and ordered native loopback effect."""

    def __init__(self):
        self.commands = {}
        self.last_delivery_tick = 0
        self.acknowledgements = {}

    def reserve_callback(self):
        # Native TX has sixteen finite slots. A publication stop ends the whole
        # first callback, whose original frames must all have reserved custody.
        if len(self.commands) + 16 > MAX_OPERATIONS:
            raise ValueError('closed network original credit exhausted before callback')

    def accept_original(self, metadata, payload):
        if not isinstance(metadata, (list, tuple)) or len(metadata) != 5:
            raise ValueError('closed network TX lacks exact original birth fields')
        limits = (MAX_OPERATIONS, MAX_TICK, (1 << 64) - 1, MAX_CALLBACKS, 1000000)
        original = tuple(integer(value, maximum) for value, maximum in zip(metadata, limits))
        identifier, tick, parent, ordinal, tie = original
        if (not identifier or parent != DEVICE_PARENT or not ordinal or not tie
                or not isinstance(payload, bytes) or not 14 <= len(payload) <= MAX_PAYLOAD):
            raise ValueError('closed network TX differs from its source-owned endpoint')
        known = self.commands.get(identifier)
        if known is not None:
            if known['metadata'] != original or known['payload'] != payload:
                raise ValueError('closed network original TX body changed')
            return known, False
        if identifier != len(self.commands) + 1 or len(self.commands) >= MAX_OPERATIONS:
            raise ValueError('closed network original ID or custody credit is invalid')
        # Strict future times preserve frame order independently of equal-time
        # native event queue insertion order and completion buffer availability.
        reaction_tick = max(tick + REACTION_DELAY, self.last_delivery_tick + REACTION_DELAY)
        delivery_tick = reaction_tick + DELIVERY_DELAY
        if delivery_tick >= MAX_TICK:
            raise ValueError('closed network future clock credit exhausted before ownership')
        command = {'metadata': original, 'payload': payload, 'reaction_tick': reaction_tick,
                   'delivery_tick': delivery_tick, 'reaction_position': None, 'completion': None}
        self.commands[identifier] = command
        self.last_delivery_tick = delivery_tick
        return command, True

    def react(self, identifier, position):
        point = event_position(position, True)
        command = self.commands.get(identifier)
        if command is None or point[0] != command['reaction_tick']:
            raise ValueError('closed network reaction differs from its sealed original event')
        known = command['reaction_position']
        if known is not None:
            if known != point:
                raise ValueError('closed network original reaction changed')
            return command, False
        if point[1] <= command['metadata'][3]:
            raise ValueError('closed network reaction precedes actual TX birth')
        if identifier > 1:
            previous = self.commands[identifier - 1]['reaction_position']
            if previous is None or point[1] <= previous[1]:
                raise ValueError('closed network reactions are out of original order')
        command['reaction_position'] = point
        return command, True

    def observe_completion(self, metadata):
        if not isinstance(metadata, (list, tuple)) or len(metadata) != 7:
            raise ValueError('closed network RX lacks its actual original completion')
        limits = (MAX_OPERATIONS, MAX_TICK, MAX_CALLBACKS, 1000000,
                  (1 << 64) - 1, (1 << 64) - 1, MAX_PAYLOAD)
        original = tuple(integer(value, maximum) for value, maximum in zip(metadata, limits))
        identifier, tick, ordinal, tie, execution, parent, count = original
        command = self.commands.get(identifier)
        # RX can wait for a guest buffer. Its sealed earliest delivery time is
        # retained, while its actual DMA event birth is independently observed.
        if (command is None or command['reaction_position'] is None
                or tick < command['delivery_tick'] or ordinal <= command['reaction_position'][1]
                or not tie or execution != DEVICE_PARENT or parent != BACKEND_PARENT
                or count != len(command['payload'])):
            raise ValueError('closed network RX differs from its original frame/reaction')
        if command['completion'] is not None and command['completion'] != original:
            raise ValueError('closed network original RX completion changed')
        command['completion'] = original

    def acknowledge(self, facet, identifier, position):
        if facet not in ('network_tx', 'network_rx'):
            raise ValueError('closed network administration has an unknown facet')
        command = self.commands.get(identifier)
        if command is None or (facet == 'network_rx' and command['completion'] is None):
            raise ValueError('closed network administration lacks an actual original birth')
        point = event_position(position, False)
        original = command['metadata']
        birth = (original[1], original[3], original[4])
        if facet == 'network_rx':
            birth = command['completion'][1:4]
        if point[0] < birth[0] or point[1] < birth[1] or (point[0] == birth[0] and point[2] < birth[2]):
            raise ValueError('closed network administration precedes its native publication')
        key = (facet, identifier)
        if key not in self.acknowledgements:
            self.acknowledgements[key] = point
        return self.acknowledgements[key]

    def inventory(self):
        rows = []
        for identifier, command in self.commands.items():
            original = command['metadata']
            reaction = command['reaction_position'] or (0, 0, 0)
            completion = command['completion'] or (0, 0, 0, 0, 0, 0, 0)
            row = [identifier, original[1], original[3], original[4], len(command['payload']),
                   command['reaction_tick'], command['delivery_tick'], reaction[1], reaction[2],
                   completion[1], completion[2], completion[3],
                   hashlib.sha256(canonical(list(original)) + command['payload']).hexdigest(),
                   hashlib.sha256(command['payload']).hexdigest(),
                   int(('network_tx', identifier) in self.acknowledgements),
                   int(('network_rx', identifier) in self.acknowledgements)]
            if len(canonical(row)) > MAX_DIAGNOSTIC_ROW:
                raise ValueError('closed network diagnostic row exceeds its reserved extent')
            rows.append(row)
        result = {'schema': 'crucible.gem5.closed-network-loopback-state.v1',
                  'complete': False, 'command_count': str(len(rows)), 'rows': rows,
                  'omitted': ['raw-original-frame-bytes', 'complete-python-event-payloads',
                              'raw-original-administration-position-bodies']}
        if len(canonical(result)) > MAX_DIAGNOSTIC_BYTES:
            raise ValueError('closed network diagnostic extent exceeds its pre-callback reservation')
        return result
