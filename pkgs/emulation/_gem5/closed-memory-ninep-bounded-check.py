# SPDX-License-Identifier: MIT
"""Checks finite 9p original bodies and ordered owned reactions as data only."""

import copy
import importlib.util
from pathlib import Path
import struct
import unittest

specification = importlib.util.spec_from_file_location(
    'closed_ninep_under_test', Path(__file__).with_name('closed-memory-ninep-bounded.py'))
backend = importlib.util.module_from_spec(specification)
specification.loader.exec_module(backend)


def message(opcode, tag, body=b''):
    return struct.pack('<IBH', len(body) + 7, opcode, tag) + body


def string(value):
    return struct.pack('<H', len(value)) + value


def point(tick, ordinal, active=True, tie=1):
    return {'tick': str(tick), 'ordinal': str(ordinal), 'tick_ordinal': str(tie), 'active': active}


class OwnedNinepTests(unittest.TestCase):
    def setUp(self):
        self.owner = backend.ClosedMemoryNinep()
        self.next_ordinal = 10
        self.last_tick = 0

    def accept(self, opcode, body=b'', tag=None, capacity=4096):
        identifier = len(self.owner.commands) + 1
        tag = identifier if tag is None else tag
        raw = message(opcode, tag, body)
        metadata = [identifier, self.last_tick, 17, opcode, 0, tag, capacity, self.next_ordinal, 1]
        self.next_ordinal += 10
        command, new = self.owner.accept_original(metadata, raw)
        self.assertTrue(new)
        return identifier, command

    def complete(self, identifier, command, head=7):
        self.last_tick = command['completion_tick']
        reaction = point(command['reaction_tick'], self.next_ordinal)
        self.next_ordinal += 10
        reply = self.owner.react(identifier, reaction)
        completion = [identifier, self.last_tick, self.next_ordinal, 1, 0,
                      len(reply), 17, 23, 1, head]
        self.next_ordinal += 10
        self.owner.observe_completion(completion)
        administration = point(self.last_tick, self.next_ordinal, False)
        self.owner.acknowledge('ninep_request', identifier, administration)
        self.owner.acknowledge('ninep_completion', identifier, administration)
        return reply

    def create_tree(self):
        self.complete(*self.accept(100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535))
        self.complete(*self.accept(104, struct.pack('<II', 1, 0xffffffff) + string(b'root')
                                  + string(b'') + struct.pack('<I', 0)))
        self.complete(*self.accept(14, struct.pack('<I', 1) + string(b'probe')
                                  + struct.pack('<III', 0x202, 0o600, 0)))

    def test_actual_protocol_future_write_then_flush_readback(self):
        self.create_tree()
        raw = b'crucible native 9p ownership\n\0'
        identifier, command = self.accept(118, struct.pack('<IQI', 1, 0, len(raw)) + raw)
        self.assertEqual(self.owner.tree.data, b'')
        self.assertIsNone(command['reply'])
        self.assertIsNone(command['reaction_position'])
        saved = copy.deepcopy(self.owner)
        reply = self.complete(identifier, command)
        twin = copy.deepcopy(saved)
        self.assertEqual(twin.tree.data, b'')
        original = twin.commands[identifier]
        twin_reply = twin.react(identifier, point(original['reaction_tick'], command['reaction_position'][1]))
        self.assertEqual(twin_reply, reply)
        self.assertEqual(bytes(twin.tree.data), raw)
        self.complete(*self.accept(50, struct.pack('<II', 1, 0)))
        self.assertEqual(self.owner.tree.flushed_bytes, raw)
        reply = self.complete(*self.accept(116, struct.pack('<IQI', 1, 0, len(raw))))
        self.assertEqual(reply[11:], raw)
        self.assertFalse(self.owner.inventory()['complete'])

    def test_exact_original_retry_has_no_new_command(self):
        identifier, command = self.accept(100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535)
        observed, new = self.owner.accept_original(command['metadata'], command['payload'])
        self.assertIs(observed, command)
        self.assertFalse(new)
        self.assertEqual(len(self.owner.commands), 1)

    def test_changed_original_message_refused(self):
        identifier, command = self.accept(100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535)
        with self.assertRaises(ValueError):
            self.owner.accept_original(command['metadata'], command['payload'][:-1] + b'X')

    def test_header_tag_mismatch_refused(self):
        raw = message(100, 8, struct.pack('<I', 65536) + string(b'9P2000.L'))
        with self.assertRaises(ValueError):
            self.owner.accept_original([1, 0, 17, 100, 0, 7, 4096, 1, 1], raw)
        self.assertEqual(self.owner.commands, {})

    def test_outstanding_tag_cannot_be_reused(self):
        self.accept(100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535)
        with self.assertRaises(ValueError):
            self.accept(100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535)

    def test_nonconsecutive_id_refused(self):
        raw = message(100, 1, struct.pack('<I', 65536) + string(b'9P2000.L'))
        with self.assertRaises(ValueError):
            self.owner.accept_original([2, 0, 17, 100, 0, 1, 4096, 1, 1], raw)

    def test_reply_credit_refusal_preserves_tree(self):
        self.create_tree()
        raw = b'abc'
        identifier, command = self.accept(118, struct.pack('<IQI', 1, 0, len(raw)) + raw, capacity=7)
        before = copy.deepcopy(self.owner.tree.__dict__)
        with self.assertRaises(ValueError):
            self.owner.react(identifier, point(command['reaction_tick'], self.next_ordinal))
        self.assertEqual(self.owner.tree.__dict__, before)
        self.assertIsNone(command['reaction_position'])

    def test_completion_bytes_exclude_block_status_octet(self):
        identifier, command = self.accept(100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535)
        reply = self.owner.react(identifier, point(command['reaction_tick'], self.next_ordinal))
        metadata = [identifier, command['completion_tick'], self.next_ordinal + 1, 1,
                    0, len(reply) + 1, 17, 23, 1, 7]
        with self.assertRaises(ValueError):
            self.owner.observe_completion(metadata)
        metadata[5] = len(reply)
        self.owner.observe_completion(metadata)
        self.assertEqual(command['completion'][4], 0)
        self.assertEqual(command['completion'][9], 7)

    def test_status_never_reinterpreted_as_head(self):
        identifier, command = self.accept(100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535)
        reply = self.owner.react(identifier, point(command['reaction_tick'], self.next_ordinal))
        with self.assertRaises(ValueError):
            self.owner.observe_completion([identifier, command['completion_tick'], self.next_ordinal + 1,
                                           1, 2, len(reply), 17, 23, 1, 0])

    def test_reaction_retry_keeps_original_reply_and_position(self):
        identifier, command = self.accept(100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535)
        position = point(command['reaction_tick'], self.next_ordinal)
        reply = self.owner.react(identifier, position)
        self.assertEqual(self.owner.react(identifier, position), reply)
        self.assertEqual(self.owner.tree.operations, {100: 1})
        with self.assertRaises(ValueError):
            self.owner.react(identifier, point(command['reaction_tick'], self.next_ordinal + 1))

    def test_wrong_reaction_time_refused_before_tree_change(self):
        identifier, command = self.accept(100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535)
        with self.assertRaises(ValueError):
            self.owner.react(identifier, point(command['reaction_tick'] - 1, self.next_ordinal))
        self.assertEqual(self.owner.tree.operations, {})

    def test_ack_facets_and_first_position_remain_distinct(self):
        identifier, command = self.accept(100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535)
        with self.assertRaises(ValueError):
            self.owner.acknowledge('ninep_completion', identifier, point(0, 10, False))
        original = self.owner.acknowledge('ninep_request', identifier, point(0, 10, False))
        self.assertEqual(self.owner.acknowledge('ninep_request', identifier, point(1, 20, False)), original)
        with self.assertRaises(ValueError):
            self.owner.acknowledge('block_request', identifier, point(1, 20, False))

    def test_ack_cannot_move_backwards_in_event_order(self):
        identifier, command = self.accept(100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535)
        with self.assertRaises(ValueError):
            self.owner.acknowledge('ninep_request', identifier, point(1, 1, False))

    def test_callback_reserves_whole_native_frontend_burst(self):
        self.owner.commands = {identifier: {} for identifier in range(113)}
        with self.assertRaises(ValueError):
            self.owner.reserve_callback()

    def test_noncanonical_position_refused(self):
        identifier, command = self.accept(100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535)
        position = point(command['reaction_tick'], self.next_ordinal)
        position['ordinal'] = '010'
        with self.assertRaises(ValueError):
            self.owner.react(identifier, position)

    def test_clock_overflow_refused_before_original_is_retained(self):
        raw = message(100, 1, struct.pack('<I', 65536) + string(b'9P2000.L'))
        with self.assertRaises(ValueError):
            self.owner.accept_original([1, backend.positions.MAX_TICK - 1, 17, 100, 0, 1, 4096, 1, 1], raw)
        self.assertEqual(self.owner.commands, {})


    def test_version_negotiates_source_selected_message_cap(self):
        reply = self.complete(*self.accept(
            100, struct.pack('<I', 65536) + string(b'9P2000.L'), 65535))
        self.assertEqual(struct.unpack_from('<I', reply, 7)[0], 4096)

    def test_large_native_writable_custody_is_refused_before_retention(self):
        raw = message(100, 65535, struct.pack('<I', 65536) + string(b'9P2000.L'))
        with self.assertRaises(ValueError):
            self.owner.accept_original([1, 0, 17, 100, 0, 65535, 4097, 1, 1], raw)
        self.assertEqual(self.owner.commands, {})

    def test_open_iounit_matches_negotiated_message_cap(self):
        self.create_tree()
        reply = self.complete(*self.accept(12, struct.pack('<II', 1, 0)))
        self.assertEqual(struct.unpack_from('<I', reply, 20)[0], 4072)

    def test_oversized_message_cannot_change_file_state(self):
        self.create_tree()
        raw = message(118, 7, struct.pack('<IQI', 1, 0, 4096) + bytes(4096))
        with self.assertRaises(ValueError):
            self.owner.accept_original([4, self.last_tick, 17, 118, 0, 7,
                                        4096, self.next_ordinal, 1], raw)
        self.assertEqual(self.owner.tree.data, b'')

    def test_lower_negotiated_message_size_is_retained(self):
        reply = self.complete(*self.accept(
            100, struct.pack('<I', 256) + string(b'9P2000.L'), 65535))
        self.assertEqual(struct.unpack_from('<I', reply, 7)[0], 256)
        self.assertEqual(self.owner.inventory()['negotiated_message_bytes'], '256')
        self.complete(*self.accept(104, struct.pack('<II', 1, 0xffffffff) + string(b'root')
                                  + string(b'') + struct.pack('<I', 0)))
        reply = self.complete(*self.accept(14, struct.pack('<I', 1) + string(b'probe')
                                          + struct.pack('<III', 0x202, 0o600, 0)))
        self.assertEqual(struct.unpack_from('<I', reply, 20)[0], 232)

    def test_oversized_negotiated_write_does_not_change_owned_tree(self):
        self.complete(*self.accept(100, struct.pack('<I', 256) + string(b'9P2000.L'), 65535))
        self.complete(*self.accept(104, struct.pack('<II', 1, 0xffffffff) + string(b'root')
                                  + string(b'') + struct.pack('<I', 0)))
        self.complete(*self.accept(14, struct.pack('<I', 1) + string(b'probe')
                                  + struct.pack('<III', 0x202, 0o600, 0)))
        raw = bytes(233)
        identifier, command = self.accept(118, struct.pack('<IQI', 1, 0, len(raw)) + raw)
        before = copy.deepcopy(self.owner.tree.__dict__)
        with self.assertRaises(RuntimeError):
            self.owner.react(identifier, point(command['reaction_tick'], self.next_ordinal))
        self.assertEqual(self.owner.tree.__dict__, before)
        self.assertIsNone(command['reply'])

    def test_nonversion_request_before_negotiation_has_no_tree_effect(self):
        identifier, command = self.accept(104, struct.pack('<II', 1, 0xffffffff) + string(b'root')
                                          + string(b'') + struct.pack('<I', 0))
        before = copy.deepcopy(self.owner.tree.__dict__)
        with self.assertRaises(RuntimeError):
            self.owner.react(identifier, point(command['reaction_tick'], self.next_ordinal))
        self.assertEqual(self.owner.tree.__dict__, before)

if __name__ == '__main__':
    unittest.main()
