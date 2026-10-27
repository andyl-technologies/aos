# SPDX-License-Identifier: MIT
"""Retains a fixed 9p tree and every original native request/reply/ACK body.

This finite functional backend lives wholly in the native process image. It
has no host filesystem or authentication authority. Actual native callbacks
must supply the admitted original geometry and event coordinates.
"""

import copy
import hashlib
import importlib.util
from pathlib import Path
import struct


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


positions = load('crucible_ninep_positions', 'closed-memory-block.py')
fixture = load('crucible_ninep_fixed_tree', 'finite-ninep-bounded-fixture.py')
MAX_OPERATIONS = 128
MAX_PAYLOAD = 4096
MAX_DIAGNOSTIC_BYTES = 65536
MAX_DIAGNOSTIC_ROW = 384
REACTION_DELAY = 10000
COMPLETION_DELAY = 1
DEVICE_PARENT = 17
BACKEND_PARENT = 23


class ClosedMemoryNinep:
    """Retains ordered native commands over one fixed root/probe tree."""

    def __init__(self):
        self.tree = fixture.FiniteNinepFixture()
        self.commands = {}
        self.last_completion_tick = 0
        self.acknowledgements = {}

    def reserve_callback(self):
        if len(self.commands) + 16 > MAX_OPERATIONS:
            raise ValueError('closed 9p command credit exhausted before callback')

    def accept_original(self, metadata, payload):
        if not isinstance(metadata, (list, tuple)) or len(metadata) != 9:
            raise ValueError('closed 9p request lacks native metadata')
        limits = (MAX_OPERATIONS, positions.MAX_TICK, (1 << 64) - 1, 254, 0,
                  65535, MAX_PAYLOAD, positions.MAX_CALLBACKS, 1000000)
        original = tuple(positions.bounded_integer(value, maximum)
                         for value, maximum in zip(metadata, limits))
        identifier, tick, parent, opcode, sector, tag, capacity, ordinal, tie = original
        if (not identifier or parent != DEVICE_PARENT or sector or opcode & 1
                or not ordinal or not tie or not 7 <= capacity <= MAX_PAYLOAD
                or tick >= positions.MAX_TICK or not isinstance(payload, bytes)
                or not 7 <= len(payload) <= MAX_PAYLOAD):
            raise ValueError('closed 9p request differs from the fixed source device')
        length, message_opcode, message_tag = struct.unpack_from('<IBH', payload)
        if length != len(payload) or message_opcode != opcode or message_tag != tag:
            raise ValueError('closed 9p metadata differs from its original message')
        known = self.commands.get(identifier)
        if known is not None:
            if known['metadata'] != original or known['payload'] != payload:
                raise ValueError('closed 9p original request changed')
            return known, False
        if identifier != len(self.commands) + 1 or len(self.commands) >= MAX_OPERATIONS:
            raise ValueError('closed 9p original identity or finite credit is invalid')
        if any(command['metadata'][5] == tag and command['completion'] is None
               for command in self.commands.values()):
            raise ValueError('closed 9p reused an outstanding original tag')
        reaction_tick = max(tick + REACTION_DELAY, self.last_completion_tick + REACTION_DELAY)
        completion_tick = reaction_tick + COMPLETION_DELAY
        if completion_tick >= positions.MAX_TICK:
            raise ValueError('closed 9p clock credit exhausted before scheduling')
        command = {
            'metadata': original, 'payload': payload,
            'reaction_tick': reaction_tick, 'completion_tick': completion_tick,
            'reaction_position': None, 'reply': None, 'completion': None,
        }
        self.commands[identifier] = command
        self.last_completion_tick = completion_tick
        return command, True

    def react(self, identifier, position):
        point = positions.event_position(position, True)
        command = self.commands.get(identifier)
        if command is None or point[0] != command['reaction_tick']:
            raise ValueError('closed 9p reaction differs from its retained native event')
        if command['reaction_position'] is not None:
            if command['reaction_position'] != point:
                raise ValueError('closed 9p reaction repeated at another native position')
            return command['reply']
        if point[1] <= command['metadata'][7]:
            raise ValueError('closed 9p reaction precedes its actual request birth')
        if identifier > 1:
            previous = self.commands[identifier - 1]['reaction_position']
            if previous is None or point[1] <= previous[1]:
                raise ValueError('closed 9p serial state transition is out of order')
        # The tree changes only in this genuine future callback. No host poll
        # computes a reply or advances FIDs/file bytes ahead of the native cut.
        candidate = copy.deepcopy(self.tree)
        reply = candidate.reply(command['payload'])
        if len(reply) > command['metadata'][6]:
            raise ValueError('closed 9p reply exceeds original native writable custody')
        length, opcode, tag = struct.unpack_from('<IBH', reply)
        if length != len(reply) or tag != command['metadata'][5] or not opcode & 1:
            raise ValueError('closed 9p tree produced an invalid original response')
        self.tree = candidate
        command['reaction_position'] = point
        command['reply'] = reply
        return reply

    def observe_completion(self, metadata):
        if not isinstance(metadata, (list, tuple)) or len(metadata) != 10:
            raise ValueError('closed 9p completion lacks distinct status/head fields')
        limits = (MAX_OPERATIONS, positions.MAX_TICK, positions.MAX_CALLBACKS,
                  1000000, 2, MAX_PAYLOAD, (1 << 64) - 1,
                  (1 << 64) - 1, (1 << 64) - 1, 255)
        original = tuple(positions.bounded_integer(value, maximum)
                         for value, maximum in zip(metadata, limits))
        identifier, tick, ordinal, tie, status, written, execution, parent, incarnation, head = original
        command = self.commands.get(identifier)
        if (command is None or command['reaction_position'] is None
                or tick != command['completion_tick'] or ordinal <= command['reaction_position'][1]
                or not tie or status != 0 or written != len(command['reply'])
                or execution != DEVICE_PARENT or parent != BACKEND_PARENT or not incarnation):
            raise ValueError('closed 9p completion differs from its original exact reply')
        if command['completion'] is not None and command['completion'] != original:
            raise ValueError('closed 9p original completion changed')
        command['completion'] = original

    def acknowledge(self, facet, identifier, position):
        if facet not in ('ninep_request', 'ninep_completion'):
            raise ValueError('closed 9p ACK has an unknown administration facet')
        command = self.commands.get(identifier)
        if command is None or (facet == 'ninep_completion' and command['completion'] is None):
            raise ValueError('closed 9p ACK has no original native effect')
        point = positions.event_position(position, False)
        metadata = command['metadata']
        birth = (metadata[1], metadata[7], metadata[8])
        if facet == 'ninep_completion':
            birth = tuple(command['completion'][index] for index in (1, 2, 3))
        if (point[0] < birth[0] or point[1] < birth[1]
                or (point[0] == birth[0] and point[2] < birth[2])):
            raise ValueError('closed 9p ACK precedes its original native publication')
        key = (facet, identifier)
        if key not in self.acknowledgements:
            self.acknowledgements[key] = point
        return self.acknowledgements[key]

    def inventory(self):
        rows = []
        for identifier, command in self.commands.items():
            metadata = command['metadata']
            reaction = command['reaction_position'] or (0, 0, 0)
            completion = command['completion']
            row = [identifier, metadata[3], metadata[5], metadata[6],
                   metadata[1], metadata[7], metadata[8],
                   command['reaction_tick'], command['completion_tick'],
                   reaction[1], reaction[2],
                   completion[2] if completion is not None else 0,
                   completion[3] if completion is not None else 0,
                   hashlib.sha256(positions.canonical(list(metadata)) + command['payload']).hexdigest(),
                   hashlib.sha256(command['payload']).hexdigest(),
                   hashlib.sha256(command['reply']).hexdigest() if command['reply'] is not None else None,
                   int(('ninep_request', identifier) in self.acknowledgements),
                   int(('ninep_completion', identifier) in self.acknowledgements)]
            if len(positions.canonical(row)) > MAX_DIAGNOSTIC_ROW:
                raise ValueError('closed 9p diagnostic row exceeds its reserved extent')
            rows.append(row)
        state = {
            'schema': 'crucible.gem5.closed-memory-ninep-bounded-state.v1',
            'complete': False, 'command_count': str(len(rows)), 'rows': rows,
            'negotiated_message_bytes': (str(self.tree.negotiated_message_bytes)
                                         if self.tree.negotiated_message_bytes is not None else None),
            'file_created': self.tree.created, 'file_bytes': str(len(self.tree.data)),
            'file_sha256': hashlib.sha256(self.tree.data).hexdigest(),
            'fid_count': str(len(self.tree.fids)),
            'fids_sha256': hashlib.sha256(positions.canonical(
                [[fid, name.hex()] for fid, name in self.tree.fids.items()])).hexdigest(),
            'flushed_sha256': (hashlib.sha256(self.tree.flushed_bytes).hexdigest()
                               if self.tree.flushed_bytes is not None else None),
            'omitted': ['raw-file-and-fid-bytes', 'raw-original-request-and-reply-bodies',
                        'complete-python-event-and-native-callback-payloads', 'raw-ack-position-bodies'],
        }
        if len(positions.canonical(state)) > MAX_DIAGNOSTIC_BYTES:
            raise ValueError('closed 9p diagnostic exceeds its pre-callback extent')
        return state
