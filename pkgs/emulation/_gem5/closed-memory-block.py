# SPDX-License-Identifier: MIT
"""Owns fixed disk bytes and every original finite backend reaction and ACK.

This object lives inside the native process image. It does not authorize a
caller, serialize a checkpoint, or supply a host-backed disk. Its methods are
invoked only by the installed native birth handler, native queued reaction and
actual completion/ACK observers of the selected closed functional profile.
"""

import hashlib
import json


DISK_BYTES = 2048 * 512
MAX_OPERATIONS = 128
MAX_PAYLOAD = 4096
MAX_DIAGNOSTIC_BYTES = 65536
MAX_DIAGNOSTIC_ROW = 384
MAX_CALLBACKS = 16000000
MAX_TICK = 1000000000000
REACTION_DELAY = 10000
COMPLETION_DELAY = 1
DEVICE_PARENT = 17
BACKEND_PARENT = 23


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def bounded_integer(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('closed block original has invalid integer geometry')
    return value


def event_position(value, active):
    if (not isinstance(value, dict) or set(value) != {'tick', 'ordinal', 'tick_ordinal', 'active'}
            or value['active'] is not active):
        raise ValueError('closed block event lacks the genuine native execution state')
    numbers = []
    for name, maximum in (('tick', MAX_TICK), ('ordinal', MAX_CALLBACKS), ('tick_ordinal', 1000000)):
        number = value[name]
        if (not isinstance(number, str) or not number.isascii() or not number.isdecimal()
                or (len(number) > 1 and number[0] == '0')):
            raise ValueError('closed block native position is not canonical')
        numbers.append(bounded_integer(int(number), maximum))
    if active and (not numbers[1] or not numbers[2]):
        raise ValueError('closed block reaction has no native callback identity')
    return tuple(numbers)


class ClosedMemoryBlock:
    """Retains ordered immutable commands and effects over one fixed owned disk."""

    def __init__(self):
        self.backing = bytearray(DISK_BYTES)
        self.commands = {}
        self.last_completion_tick = 0
        self.acknowledgements = {}

    def reserve_callback(self):
        # The fixed frontend retains at most sixteen originals per callback.
        # The ledger never retires earlier entries to manufacture new capacity.
        if len(self.commands) + 16 > MAX_OPERATIONS:
            raise ValueError('closed block command credit exhausted before callback')

    def accept_original(self, metadata, payload):
        if not isinstance(metadata, (list, tuple)) or len(metadata) != 9:
            raise ValueError('closed block request lacks exact native metadata')
        limits = (MAX_OPERATIONS, MAX_TICK, (1 << 64) - 1, 4, 2048, 65535,
                  MAX_PAYLOAD, MAX_CALLBACKS, 1000000)
        original = tuple(bounded_integer(value, maximum)
                         for value, maximum in zip(metadata, limits))
        identifier, tick, parent, opcode, sector, tag, count, ordinal, tie = original
        if (not identifier or parent != DEVICE_PARENT or tag or not ordinal or not tie
                or opcode not in (0, 1, 4) or tick >= MAX_TICK):
            raise ValueError('closed block request differs from the fixed source device')
        if not isinstance(payload, bytes):
            raise ValueError('closed block payload must be original owned bytes')
        if (count % 512 or count > DISK_BYTES - sector * 512
                or (opcode == 4 and (count or payload))
                or (opcode in (0, 1) and not count)
                or (opcode == 0 and payload)
                or (opcode == 1 and len(payload) != count)):
            raise ValueError('closed block original opcode, extent or bytes are invalid')
        known = self.commands.get(identifier)
        if known is not None:
            if known['metadata'] != original or known['payload'] != payload:
                raise ValueError('closed block original request changed')
            return known, False
        if identifier != len(self.commands) + 1 or len(self.commands) >= MAX_OPERATIONS:
            raise ValueError('closed block original ID or operation credit is invalid')
        # A fixed serial device schedules strictly ordered backend reactions.
        # Equal-time native LIFO order cannot reorder disk visibility.
        reaction_tick = max(tick + REACTION_DELAY, self.last_completion_tick + REACTION_DELAY)
        completion_tick = reaction_tick + COMPLETION_DELAY
        if completion_tick >= MAX_TICK:
            raise ValueError('closed block native clock credit exhausted before scheduling')
        command = {
            'metadata': original, 'payload': payload,
            'reaction_tick': reaction_tick, 'completion_tick': completion_tick,
            'reaction_position': None, 'reply': None, 'completion': None,
        }
        self.commands[identifier] = command
        self.last_completion_tick = completion_tick
        return command, True

    def react(self, identifier, position):
        point = event_position(position, True)
        command = self.commands.get(identifier)
        if command is None or point[0] != command['reaction_tick']:
            raise ValueError('closed block reaction differs from its original native event')
        if command['reaction_position'] is not None:
            if command['reaction_position'] != point:
                raise ValueError('closed block reaction repeated at a different native position')
            return command['reply']
        if point[1] <= command['metadata'][7]:
            raise ValueError('closed block backend precedes original request birth')
        if identifier > 1:
            previous = self.commands[identifier - 1]['reaction_position']
            if previous is None or point[1] <= previous[1]:
                raise ValueError('closed block serial backend reaction is out of order')
        opcode, sector, count = (command['metadata'][index] for index in (3, 4, 6))
        start = sector * 512
        if opcode == 0:
            reply = bytes(self.backing[start:start + count])
        elif opcode == 1:
            self.backing[start:start + count] = command['payload']
            reply = b''
        else:
            reply = b''
        command['reaction_position'] = point
        command['reply'] = reply
        return reply

    def observe_completion(self, metadata):
        if not isinstance(metadata, (list, tuple)) or len(metadata) != 10:
            raise ValueError('closed block completion lacks distinct status and head')
        limits = (MAX_OPERATIONS, MAX_TICK, MAX_CALLBACKS, 1000000, 2,
                  MAX_PAYLOAD + 1, (1 << 64) - 1, (1 << 64) - 1, (1 << 64) - 1, 255)
        original = tuple(bounded_integer(value, maximum)
                         for value, maximum in zip(metadata, limits))
        identifier, tick, ordinal, tie, status, written, execution, parent, incarnation, head = original
        command = self.commands.get(identifier)
        if (command is None or command['reaction_position'] is None
                or tick != command['completion_tick'] or status != 0
                or ordinal <= command['reaction_position'][1] or not tie
                or written != len(command['reply']) + 1
                or execution != DEVICE_PARENT or parent != BACKEND_PARENT or not incarnation):
            raise ValueError('closed block completion differs from its original reaction/reply')
        if command['completion'] is not None and command['completion'] != original:
            raise ValueError('closed block original completion changed')
        command['completion'] = original

    def acknowledge(self, facet, identifier, position):
        if facet not in ('block_request', 'block_completion'):
            raise ValueError('closed block acknowledgement has an unknown facet')
        command = self.commands.get(identifier)
        if command is None or (facet == 'block_completion' and command['completion'] is None):
            raise ValueError('closed block acknowledgement lacks its original effect')
        point = event_position(position, False)
        original = command['metadata']
        birth = (original[1], original[7], original[8])
        if facet == 'block_completion':
            completion = command['completion']
            birth = (completion[1], completion[2], completion[3])
        if point[0] < birth[0] or point[1] < birth[1] or (point[0] == birth[0] and point[2] < birth[2]):
            raise ValueError('closed block ACK precedes its original native publication')
        key = (facet, identifier)
        # The first original administration position remains authoritative.
        # A retry does not replace it with the caller's newer observation time.
        if key not in self.acknowledgements:
            self.acknowledgements[key] = point
        return self.acknowledgements[key]

    def inventory(self):
        rows = []
        for identifier, command in self.commands.items():
            metadata = command['metadata']
            reaction = command['reaction_position'] or (0, 0, 0)
            completion = command['completion']
            row = [identifier, metadata[3], metadata[4], metadata[6],
                   metadata[1], metadata[7], metadata[8],
                   command['reaction_tick'], command['completion_tick'],
                   reaction[1], reaction[2],
                   completion[2] if completion is not None else 0,
                   completion[3] if completion is not None else 0,
                   hashlib.sha256(canonical(list(metadata)) + command['payload']).hexdigest(),
                   hashlib.sha256(command['payload']).hexdigest(),
                   hashlib.sha256(command['reply']).hexdigest() if command['reply'] is not None else None,
                   int(('block_request', identifier) in self.acknowledgements),
                   int(('block_completion', identifier) in self.acknowledgements)]
            if len(canonical(row)) > MAX_DIAGNOSTIC_ROW:
                raise ValueError('closed block original diagnostic row exceeds reserved extent')
            rows.append(row)
        result = {
            'schema': 'crucible.gem5.closed-memory-block-state.v1',
            'complete': False, 'backing_bytes': str(len(self.backing)),
            'backing_sha256': hashlib.sha256(self.backing).hexdigest(),
            'command_count': str(len(rows)), 'rows': rows,
            'omitted': ['raw-backing-bytes', 'raw-original-command-and-reply-bodies',
                        'complete-python-event-and-native-callback-payloads', 'raw-ack-position-bodies'],
        }
        if len(canonical(result)) > MAX_DIAGNOSTIC_BYTES:
            raise ValueError('closed block diagnostic metadata exceeds pre-callback reservation')
        return result
