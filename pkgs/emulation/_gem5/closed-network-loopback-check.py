# SPDX-License-Identifier: MIT
"""Checks finite closed-frame ordering and original administration custody.

These bounded data tests do not qualify a native guest or image capture.
"""

import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('closed_loopback', Path(__file__).with_name('closed-network-loopback.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def original(identifier=1, tick=100):
    return [identifier, tick, 17, identifier, 1]


def position(tick, ordinal=2, active=True):
    return {'tick': str(tick), 'ordinal': str(ordinal), 'tick_ordinal': '1', 'active': active}


def packet(length=64):
    return bytes(index % 256 for index in range(length))


class LoopbackTests(unittest.TestCase):
    def test_frame_and_future_event_owned_before_any_rx_effect(self):
        network = module.ClosedNetworkLoopback()
        command, accepted = network.accept_original(original(), packet())
        self.assertTrue(accepted)
        self.assertEqual(command['payload'], packet())
        self.assertEqual(command['reaction_tick'], 10100)
        self.assertEqual(command['delivery_tick'], 10101)
        self.assertIsNone(command['reaction_position'])
        self.assertIsNone(command['completion'])

    def test_duplicate_original_never_creates_another_reaction(self):
        network = module.ClosedNetworkLoopback()
        command, _ = network.accept_original(original(), packet())
        retry, accepted = network.accept_original(original(), packet())
        self.assertIs(retry, command)
        self.assertFalse(accepted)
        self.assertEqual(len(network.commands), 1)

    def test_original_metadata_and_bytes_cannot_change(self):
        network = module.ClosedNetworkLoopback()
        network.accept_original(original(), packet())
        for metadata, payload in ((original(tick=101), packet()), (original(), bytes(64))):
            with self.assertRaises(ValueError):
                network.accept_original(metadata, payload)
        self.assertEqual(network.commands[1]['payload'], packet())

    def test_native_reaction_is_exact_and_idempotent(self):
        network = module.ClosedNetworkLoopback()
        command, _ = network.accept_original(original(), packet())
        reacted, accepted = network.react(1, position(10100))
        self.assertIs(reacted, command)
        self.assertTrue(accepted)
        self.assertFalse(network.react(1, position(10100))[1])
        with self.assertRaises(ValueError):
            network.react(1, position(10100, 3))
        self.assertEqual(command['reaction_position'], (10100, 2, 1))

    def test_wrong_time_or_prebirth_reaction_has_no_effect(self):
        for point in (position(10099), position(10101), position(10100, 1), position(10100, 2, False)):
            network = module.ClosedNetworkLoopback()
            command, _ = network.accept_original(original(), packet())
            with self.assertRaises(ValueError):
                network.react(1, point)
            self.assertIsNone(command['reaction_position'])

    def test_equal_birth_ticks_have_distinct_ordered_future_events(self):
        network = module.ClosedNetworkLoopback()
        first, _ = network.accept_original(original(1), packet())
        second, _ = network.accept_original(original(2), packet())
        self.assertGreater(second['reaction_tick'], first['delivery_tick'])
        with self.assertRaises(ValueError):
            network.react(2, position(second['reaction_tick'], 4))
        self.assertIsNone(second['reaction_position'])
        network.react(1, position(first['reaction_tick'], 3))
        self.assertTrue(network.react(2, position(second['reaction_tick'], 4))[1])

    def test_actual_rx_may_wait_for_guest_buffer(self):
        network = module.ClosedNetworkLoopback()
        network.accept_original(original(), packet())
        network.react(1, position(10100))
        completion = [1, 10200, 3, 1, 17, 23, 64]
        network.observe_completion(completion)
        network.observe_completion(completion)
        self.assertEqual(network.commands[1]['completion'], tuple(completion))
        self.assertEqual(network.commands[1]['delivery_tick'], 10101)

    def test_completion_without_original_reaction_refuses(self):
        network = module.ClosedNetworkLoopback()
        network.accept_original(original(), packet())
        with self.assertRaises(ValueError):
            network.observe_completion([1, 10101, 3, 1, 17, 23, 64])
        self.assertIsNone(network.commands[1]['completion'])

    def test_changed_rx_birth_refuses_without_overwriting_original(self):
        network = module.ClosedNetworkLoopback()
        network.accept_original(original(), packet())
        network.react(1, position(10100))
        completion = [1, 10101, 3, 1, 17, 23, 64]
        network.observe_completion(completion)
        changed = completion.copy()
        changed[1] += 1
        with self.assertRaises(ValueError):
            network.observe_completion(changed)
        self.assertEqual(network.commands[1]['completion'], tuple(completion))

    def test_completion_wrong_identity_extent_parent_or_order_refuses(self):
        variants = [[2, 10101, 3, 1, 17, 23, 64], [1, 10100, 3, 1, 17, 23, 64],
                    [1, 10101, 2, 1, 17, 23, 64], [1, 10101, 3, 0, 17, 23, 64],
                    [1, 10101, 3, 1, 18, 23, 64], [1, 10101, 3, 1, 17, 24, 64],
                    [1, 10101, 3, 1, 17, 23, 63]]
        for completion in variants:
            network = module.ClosedNetworkLoopback()
            network.accept_original(original(), packet())
            network.react(1, position(10100))
            with self.assertRaises(ValueError):
                network.observe_completion(completion)
            self.assertIsNone(network.commands[1]['completion'])

    def test_first_tx_ack_position_remains_authoritative(self):
        network = module.ClosedNetworkLoopback()
        network.accept_original(original(), packet())
        first = network.acknowledge('network_tx', 1, position(100, 1, False))
        retry = network.acknowledge('network_tx', 1, position(12000, 7, False))
        self.assertEqual(first, retry)
        self.assertEqual(first, (100, 1, 1))
        self.assertEqual(len(network.commands), 1)

    def test_rx_retirement_distinct_from_tx_ack(self):
        network = module.ClosedNetworkLoopback()
        network.accept_original(original(), packet())
        with self.assertRaises(ValueError):
            network.acknowledge('network_rx', 1, position(100, 1, False))
        network.react(1, position(10100))
        network.observe_completion([1, 10101, 3, 1, 17, 23, 64])
        network.acknowledge('network_rx', 1, position(10101, 3, False))
        self.assertNotIn(('network_tx', 1), network.acknowledgements)

    def test_unknown_or_prebirth_admin_has_no_effect(self):
        for facet, identifier, point in (('serial', 1, position(100, 1, False)),
                                         ('network_tx', 2, position(100, 1, False)),
                                         ('network_tx', 1, position(99, 1, False)),
                                         ('network_tx', 1, position(100, 0, False)),
                                         ('network_tx', 1, position(100, 1, True))):
            network = module.ClosedNetworkLoopback()
            network.accept_original(original(), packet())
            with self.assertRaises(ValueError):
                network.acknowledge(facet, identifier, point)
            self.assertEqual(network.acknowledgements, {})

    def test_malformed_metadata_or_payload_refuses_before_ownership(self):
        variants = [(original(0), packet()), (original(2), packet()),
                    ([True, 100, 17, 1, 1], packet()), ([1, 100, 18, 1, 1], packet()),
                    ([1, 100, 17, 0, 1], packet()), ([1, 100, 17, 1, 0], packet()),
                    (original()[:-1], packet()), (original(), packet(13)),
                    (original(), packet(4097)), (original(), bytearray(packet()))]
        for metadata, payload in variants:
            network = module.ClosedNetworkLoopback()
            with self.assertRaises(ValueError):
                network.accept_original(metadata, payload)
            self.assertEqual(network.commands, {})

    def test_clock_overflow_refuses_before_original_ownership(self):
        network = module.ClosedNetworkLoopback()
        with self.assertRaises(ValueError):
            network.accept_original(original(tick=module.MAX_TICK - module.REACTION_DELAY), packet())
        self.assertEqual(network.commands, {})

    def test_whole_callback_credit_reserved_before_next_original(self):
        network = module.ClosedNetworkLoopback()
        for identifier in range(1, 50):
            network.accept_original(original(identifier), packet())
        before = copy.deepcopy(network.commands)
        with self.assertRaises(ValueError):
            network.reserve_callback()
        self.assertEqual(network.commands, before)

    def test_full_ledger_never_discards_originals_to_admit_more(self):
        network = module.ClosedNetworkLoopback()
        for identifier in range(1, 65):
            network.accept_original(original(identifier), packet(4096))
        with self.assertRaises(ValueError):
            network.accept_original(original(65), packet())
        self.assertEqual(len(network.commands), 64)
        self.assertEqual(network.commands[1]['payload'], packet(4096))
        self.assertLess(len(module.canonical(network.inventory())), module.MAX_DIAGNOSTIC_BYTES)
        self.assertFalse(network.inventory()['complete'])

    def test_noncanonical_native_position_refuses(self):
        for name, value in (('tick', '010100'), ('ordinal', '-1'), ('tick_ordinal', '١'), ('active', 1)):
            point = position(10100)
            point[name] = value
            with self.assertRaises(ValueError):
                module.event_position(point, True)


if __name__ == '__main__':
    unittest.main()
