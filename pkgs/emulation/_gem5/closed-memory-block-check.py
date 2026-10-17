# SPDX-License-Identifier: MIT
"""Checks native-owned finite disk effects, ordering and original custody.

These are pure data models. They neither run a guest nor qualify a checkpoint.
"""

import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('closed_memory_block', Path(__file__).with_name('closed-memory-block.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def request(identifier=1, opcode=0, sector=0, count=512, tick=100):
    return [identifier, tick, 17, opcode, sector, 0, count, identifier, 1]


def position(tick, ordinal=2, active=True):
    return {'tick': str(tick), 'ordinal': str(ordinal), 'tick_ordinal': '1', 'active': active}


class DiskTests(unittest.TestCase):
    def test_backing_and_original_bytes_are_owned_before_reaction(self):
        disk = module.ClosedMemoryBlock()
        pattern = bytes(range(256)) * 2
        command, accepted = disk.accept_original(request(opcode=1, sector=1), pattern)
        self.assertTrue(accepted)
        self.assertEqual(bytes(disk.backing[512:1024]), bytes(512))
        self.assertEqual(command['payload'], pattern)
        self.assertEqual(command['reaction_tick'], 10100)
        self.assertEqual(command['completion_tick'], 10101)
        self.assertEqual(disk.react(1, position(10100)), b'')
        self.assertEqual(bytes(disk.backing[512:1024]), pattern)
        self.assertEqual(disk.react(1, position(10100)), b'')

    def test_read_write_flush_preserve_exact_originals_and_replies(self):
        disk = module.ClosedMemoryBlock()
        pattern = bytes(range(256)) * 2
        for identifier, opcode, count, payload in ((1, 1, 512, pattern), (2, 4, 0, b''), (3, 0, 512, b'')):
            command, accepted = disk.accept_original(request(identifier, opcode, 1, count), payload)
            self.assertTrue(accepted)
            reaction_ordinal = identifier * 3
            reply = disk.react(identifier, position(command['reaction_tick'], reaction_ordinal))
            self.assertEqual(reply, pattern if opcode == 0 else b'')
            completion = [identifier, command['completion_tick'], reaction_ordinal + 1, 1, 0,
                          len(reply) + 1, 17, 23, 1, 7]
            disk.observe_completion(completion)
            self.assertEqual(disk.commands[identifier]['completion'][-1], 7)
            disk.acknowledge('block_request', identifier, position(command['completion_tick'], reaction_ordinal + 1, False))
            disk.acknowledge('block_completion', identifier, position(command['completion_tick'], reaction_ordinal + 1, False))
        self.assertEqual(len(disk.commands), 3)
        self.assertEqual(len(disk.acknowledgements), 6)
        self.assertFalse(disk.inventory()['complete'])

    def test_duplicate_original_does_not_schedule_again(self):
        disk = module.ClosedMemoryBlock()
        original = request()
        command, _ = disk.accept_original(original, b'')
        retry, accepted = disk.accept_original(original, b'')
        self.assertIs(retry, command)
        self.assertFalse(accepted)
        changed = request(sector=1)
        with self.assertRaises(ValueError):
            disk.accept_original(changed, b'')
        self.assertEqual(len(disk.commands), 1)

    def test_serial_reactions_do_not_depend_on_native_equal_tick_lifo(self):
        disk = module.ClosedMemoryBlock()
        first, _ = disk.accept_original(request(1), b'')
        second, _ = disk.accept_original(request(2), b'')
        self.assertGreater(second['reaction_tick'], first['completion_tick'])
        with self.assertRaises(ValueError):
            disk.react(2, position(second['reaction_tick'], 4))
        self.assertIsNone(second['reaction_position'])

    def test_changed_payload_has_no_write_effect(self):
        disk = module.ClosedMemoryBlock()
        disk.accept_original(request(opcode=1), bytes(512))
        with self.assertRaises(ValueError):
            disk.accept_original(request(opcode=1), bytes([1]) * 512)
        self.assertEqual(disk.backing, bytearray(module.DISK_BYTES))

    def test_malformed_originals_refused_before_ownership(self):
        variants = [request(identifier=0), request(identifier=2), request(opcode=2),
                    request(sector=2048), request(count=511), request(count=8192),
                    request(opcode=4, count=512), request(opcode=1), request(count=0)]
        variants += [[True] + request()[1:], request()[:-1]]
        for metadata in variants:
            disk = module.ClosedMemoryBlock()
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                disk.accept_original(metadata, b'')
            self.assertFalse(disk.commands)

    def test_native_reaction_requires_actual_future_tick_and_active_identity(self):
        disk = module.ClosedMemoryBlock()
        command, _ = disk.accept_original(request(), b'')
        for point in (position(10099), position(10100, 1), position(10100, active=False)):
            with self.assertRaises(ValueError):
                disk.react(1, point)
        self.assertIsNone(command['reaction_position'])

    def test_same_original_cannot_react_again_at_another_birth(self):
        disk = module.ClosedMemoryBlock()
        disk.accept_original(request(), b'')
        disk.react(1, position(10100))
        with self.assertRaises(ValueError):
            disk.react(1, position(10100, 3))

    def test_finite_callback_reservation_precedes_any_new_commands(self):
        disk = module.ClosedMemoryBlock()
        disk.commands = dict.fromkeys(range(module.MAX_OPERATIONS - 15))
        with self.assertRaises(ValueError):
            disk.reserve_callback()

    def test_command_clock_extent_precedes_scheduling_or_disk_effect(self):
        disk = module.ClosedMemoryBlock()
        with self.assertRaises(ValueError):
            disk.accept_original(request(tick=module.MAX_TICK - module.REACTION_DELAY), b'')
        self.assertFalse(disk.commands)

    def test_real_status_is_validated_independently_from_descriptor_head(self):
        disk = module.ClosedMemoryBlock()
        command, _ = disk.accept_original(request(), b'')
        disk.react(1, position(command['reaction_tick']))
        wrong = [1, command['completion_tick'], 3, 1, 2, 513, 17, 23, 1, 0]
        with self.assertRaises(ValueError):
            disk.observe_completion(wrong)
        correct = list(wrong)
        correct[4] = 0
        correct[9] = 9
        disk.observe_completion(correct)
        self.assertEqual(command['completion'][4], 0)
        self.assertEqual(command['completion'][9], 9)

    def test_unknown_premature_and_changed_completion_are_refused(self):
        disk = module.ClosedMemoryBlock()
        command, _ = disk.accept_original(request(), b'')
        value = [1, command['completion_tick'], 3, 1, 0, 513, 17, 23, 1, 0]
        with self.assertRaises(ValueError):
            disk.observe_completion(value)
        disk.react(1, position(command['reaction_tick']))
        disk.observe_completion(value)
        for index, bad in ((0, 2), (1, command['completion_tick'] + 1), (2, 2),
                           (5, 512), (6, 99), (7, 99), (8, 0), (9, 1)):
            changed = list(value)
            changed[index] = bad
            with self.subTest(index=index), self.assertRaises(ValueError):
                disk.observe_completion(changed)

    def test_ack_retry_retains_original_administration_body(self):
        disk = module.ClosedMemoryBlock()
        disk.accept_original(request(), b'')
        original = disk.acknowledge('block_request', 1, position(100, 1, False))
        retry = disk.acknowledge('block_request', 1, position(200, 10, False))
        self.assertEqual(original, retry)
        with self.assertRaises(ValueError):
            disk.acknowledge('block_completion', 1, position(200, 10, False))

    def test_ack_cannot_precede_original_native_publication(self):
        disk = module.ClosedMemoryBlock()
        disk.accept_original(request(), b'')
        for point in (position(99, 1, False), position(100, 0, False)):
            with self.assertRaises(ValueError):
                disk.acknowledge('block_request', 1, point)
        self.assertFalse(disk.acknowledgements)

    def test_reaction_ordinals_are_monotonic(self):
        disk = module.ClosedMemoryBlock()
        first, _ = disk.accept_original(request(1), b'')
        second, _ = disk.accept_original(request(2), b'')
        disk.react(1, position(first['reaction_tick'], 10))
        with self.assertRaises(ValueError):
            disk.react(2, position(second['reaction_tick'], 9))
        self.assertIsNone(second['reaction_position'])

    def test_inventory_is_read_only_and_commits_owned_bytes(self):
        disk = module.ClosedMemoryBlock()
        disk.accept_original(request(opcode=1), bytes([1]) * 512)
        before = copy.deepcopy(disk.__dict__)
        observed = disk.inventory()
        self.assertEqual(observed, disk.inventory())
        self.assertEqual(before, disk.__dict__)
        disk.react(1, position(10100))
        self.assertNotEqual(observed['backing_sha256'], disk.inventory()['backing_sha256'])

    def test_maximum_metadata_fits_fixed_pre_callback_credit(self):
        disk = module.ClosedMemoryBlock()
        for identifier in range(1, module.MAX_OPERATIONS + 1):
            command, _ = disk.accept_original(request(identifier, tick=module.MAX_TICK - 10000000), b'')
            disk.react(identifier, position(command['reaction_tick'], module.MAX_CALLBACKS - 1000 + identifier * 3))
            disk.observe_completion([identifier, command['completion_tick'], module.MAX_CALLBACKS - 999 + identifier * 3,
                                     1000000, 0, 513, 17, 23, (1 << 64) - 1, 255])
        body = module.canonical(disk.inventory())
        self.assertLessEqual(len(body), module.MAX_DIAGNOSTIC_BYTES)
        for row in disk.inventory()['rows']:
            self.assertLessEqual(len(module.canonical(row)), module.MAX_DIAGNOSTIC_ROW)


if __name__ == '__main__':
    unittest.main()
