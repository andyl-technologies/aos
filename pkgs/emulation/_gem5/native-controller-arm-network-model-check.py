# SPDX-License-Identifier: MIT
"""Checks bounded network callback wiring without creating native authority."""

import copy
import importlib.util
from pathlib import Path
import types
import unittest


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


fixtures = load('closed_block_test_fixtures', 'native-controller-arm-block-model-check.py')
native = fixtures.native
module = load('closed_network_model', 'native-controller-arm-network-model.py')


class Network:
    def __init__(self):
        self.frames = [[1, 100, 17, 1, 1]]
        self.payload = bytes(range(64))
        self.completions = []
        self.staged = []
        self.acknowledged = []

    def path(self):
        return 'system.net'

    def crucibleTxPublicationInventory(self):
        return copy.deepcopy(self.frames)

    def crucibleTxPublicationBytes(self, identifier):
        return list(self.payload)

    def pendingRxCompletionMetadata(self):
        return list(self.completions)

    def stageRx(self, *arguments):
        self.staged.append(arguments)
        return True

    def acknowledgeTx(self, identifier):
        self.acknowledged.append(('tx', identifier))
        return True

    def retireRx(self, identifier):
        self.acknowledged.append(('rx', identifier))
        return True


def model():
    owner = module.ArmLinuxNetworkModel.__new__(module.ArmLinuxNetworkModel)
    owner.disk = module.block_model.backend.ClosedMemoryBlock()
    owner.backend_events = {}
    owner.network = module.network_backend.ClosedNetworkLoopback()
    owner.network_events = {}
    owner.publication_bindings = {}
    owner.publication_order = []
    owner.acknowledged = set()
    disk = fixtures.Endpoint()
    disk.requests = []
    owner.system = types.SimpleNamespace(net=Network(), block=disk)
    return owner


class ModelTests(unittest.TestCase):
    def setUp(self):
        native.queue = fixtures.Queue()
        native.position = {'tick': '100', 'ordinal': '1', 'tick_ordinal': '1', 'active': True}

    def test_original_tx_birth_owns_future_event_before_rx_effect(self):
        owner = model()
        module.NetworkTransmitHandler(owner)()
        self.assertEqual(len(native.queue.events), 1)
        event, tick = native.queue.events[0]
        self.assertIs(event, owner.network_events[1])
        self.assertIs(event.owner, owner)
        self.assertEqual(tick, 10100)
        self.assertEqual(owner.network.commands[1]['payload'], owner.system.net.payload)
        self.assertEqual(owner.system.net.staged, [])

    def test_original_handler_retry_never_schedules_another_event(self):
        owner = model()
        handler = module.NetworkTransmitHandler(owner)
        handler()
        handler()
        self.assertEqual(len(native.queue.events), 1)

    def test_changed_native_original_does_not_replace_owned_frame(self):
        owner = model()
        handler = module.NetworkTransmitHandler(owner)
        handler()
        owner.system.net.payload = bytes(64)
        with self.assertRaises(ValueError):
            handler()
        self.assertEqual(owner.network.commands[1]['payload'], bytes(range(64)))
        self.assertEqual(len(native.queue.events), 1)

    def test_reaction_stages_exact_original_bytes_parent_and_future_time_once(self):
        owner = model()
        module.NetworkTransmitHandler(owner)()
        event = owner.network_events[1]
        with self.assertRaises(ValueError):
            event()
        native.position = {'tick': '10100', 'ordinal': '2', 'tick_ordinal': '1', 'active': True}
        event()
        event()
        self.assertEqual(owner.system.net.staged, [(1, 10101, 23, list(range(64)))])

    def test_completion_retains_distinct_original_native_birth_and_bytes(self):
        owner = model()
        module.NetworkTransmitHandler(owner)()
        native.position = {'tick': '10100', 'ordinal': '2', 'tick_ordinal': '1', 'active': True}
        owner.network_events[1]()
        owner.system.net.completions = [1, 10101, 3, 1, 17, 23, 64]
        output = owner.publications()
        self.assertEqual([row['facet'] for row in output], ['network_tx', 'network_rx'])
        self.assertEqual(output[0]['event_ordinal'], '1')
        self.assertEqual(output[1]['event_ordinal'], '3')
        self.assertEqual(output[1]['execution_parent'], '17')
        self.assertEqual(output[1]['causal_parent'], '23')
        self.assertEqual(output[1]['payload'], list(range(64)))
        self.assertEqual(output, owner.publications())

    def test_tx_ack_and_rx_retirement_keep_first_positions_and_effect_once(self):
        owner = model()
        module.NetworkTransmitHandler(owner)()
        native.position = {'tick': '10100', 'ordinal': '2', 'tick_ordinal': '1', 'active': True}
        owner.network_events[1]()
        owner.system.net.completions = [1, 10101, 3, 1, 17, 23, 64]
        owner.publications()
        native.position = {'tick': '10101', 'ordinal': '3', 'tick_ordinal': '1', 'active': False}
        owner.acknowledge(1)
        owner.acknowledge(2)
        native.position.update(tick='12000', ordinal='5')
        owner.acknowledge(1)
        owner.acknowledge(2)
        self.assertEqual(owner.system.net.acknowledged, [('tx', 1), ('rx', 1)])
        self.assertEqual(owner.network.acknowledgements[('network_tx', 1)], (10101, 3, 1))
        self.assertEqual(owner.network.acknowledgements[('network_rx', 1)], (10101, 3, 1))

    def test_rejected_native_tx_ack_does_not_mark_backend_administration(self):
        owner = model()
        module.NetworkTransmitHandler(owner)()
        owner.publications()
        native.position['active'] = False
        owner.system.net.acknowledgeTx = lambda identifier: False
        before = owner.network.inventory()

        with self.assertRaises(ValueError):
            owner.acknowledge(1)

        self.assertEqual(owner.network.inventory(), before)
        self.assertEqual(owner.network.acknowledgements, {})
        self.assertEqual(owner.acknowledged, set())
        self.assertEqual(len(owner.publications()), 1)

    def test_rejected_native_rx_retirement_keeps_original_tx_ack(self):
        owner = model()
        module.NetworkTransmitHandler(owner)()
        native.position = {'tick': '10100', 'ordinal': '2', 'tick_ordinal': '1', 'active': True}
        owner.network_events[1]()
        owner.system.net.completions = [1, 10101, 3, 1, 17, 23, 64]
        owner.publications()
        native.position = {'tick': '10101', 'ordinal': '3', 'tick_ordinal': '1', 'active': False}
        owner.acknowledge(1)
        before = owner.network.inventory()
        owner.system.net.retireRx = lambda identifier: False

        with self.assertRaises(ValueError):
            owner.acknowledge(2)

        self.assertEqual(owner.network.inventory(), before)
        self.assertEqual(owner.acknowledged, {('network_tx', 1)})
        self.assertNotIn(('network_rx', 1), owner.network.acknowledgements)

    def test_raised_native_tx_ack_does_not_commit_candidate_backend_ledger(self):
        owner = model()
        module.NetworkTransmitHandler(owner)()
        owner.publications()
        native.position['active'] = False
        before = owner.network.inventory()

        def reject(identifier):
            raise RuntimeError('native administration is uncertain')

        owner.system.net.acknowledgeTx = reject
        with self.assertRaises(RuntimeError):
            owner.acknowledge(1)

        self.assertEqual(owner.network.inventory(), before)
        self.assertEqual(owner.acknowledged, set())

    def test_rejected_native_disk_request_ack_preserves_owned_backend(self):
        owner = model()
        owner.system.net.frames = []
        owner.system.block.requests = [[1, 100, 17, 1, 1, 0, 512, 1, 1]]
        module.block_model.RequestBirthHandler(owner)()
        owner.publications()
        native.position['active'] = False
        owner.system.block.acknowledgeRequest = lambda identifier: False
        before = owner.disk.inventory()

        with self.assertRaises(ValueError):
            owner.acknowledge(1)

        self.assertEqual(owner.disk.inventory(), before)
        self.assertEqual(owner.disk.acknowledgements, {})
        self.assertEqual(owner.acknowledged, set())

    def test_rejected_native_disk_completion_preserves_original_request_ack(self):
        owner = model()
        owner.system.net.frames = []
        owner.system.block.requests = [[1, 100, 17, 1, 1, 0, 512, 1, 1]]
        module.block_model.RequestBirthHandler(owner)()
        native.position = {'tick': '10100', 'ordinal': '2', 'tick_ordinal': '1', 'active': True}
        owner.backend_events[1]()
        owner.system.block.completions = [[1, 10101, 3, 1, 0, 1, 17, 23, 1, 7]]
        owner.publications()
        native.position = {'tick': '10101', 'ordinal': '3', 'tick_ordinal': '1', 'active': False}
        owner.acknowledge(1)
        before = owner.disk.inventory()
        owner.system.block.retireCompleted = lambda identifier: False

        with self.assertRaises(ValueError):
            owner.acknowledge(2)

        self.assertEqual(owner.disk.inventory(), before)
        self.assertEqual(owner.acknowledged, {('block_request', 1)})
        self.assertNotIn(('block_completion', 1), owner.disk.acknowledgements)

    def test_external_inputs_are_refused_before_any_staging(self):
        owner = model()
        with self.assertRaises(ValueError):
            owner.validate_control({'kind': 'device_control'})
        self.assertEqual(owner.network.commands, {})
        self.assertEqual(owner.system.net.staged, [])
        self.assertEqual(owner.system.block.staged, [])

    def test_finite_whole_callback_reservation_precedes_native_effects(self):
        owner = model()
        owner.network.commands = dict.fromkeys(range(module.network_backend.MAX_OPERATIONS - 15))
        with self.assertRaises(ValueError):
            owner.reserve_callback_credit()
        self.assertEqual(native.queue.events, [])
        self.assertEqual(owner.system.net.staged, [])

    def test_boot_disk_has_its_own_owned_handler_and_future_state(self):
        owner = model()
        owner.system.block.requests = [[1, 100, 17, 0, 0, 0, 512, 1, 1]]
        owner.system.block.payload = b''
        module.block_model.RequestBirthHandler(owner)()
        self.assertIs(native.queue.events[0][0], owner.backend_events[1])
        self.assertEqual(owner.disk.backing, bytearray(1048576))
        self.assertEqual(owner.network.commands, {})

    def test_new_model_is_not_the_old_block_or_root_dialect(self):
        self.assertNotEqual(module.ArmLinuxNetworkModel.schema, module.block_model.ArmLinuxBlockModel.schema)
        self.assertNotEqual(module.ArmLinuxNetworkModel.model_id, module.block_model.ArmLinuxBlockModel.model_id)
        self.assertNotEqual(module.ArmLinuxNetworkModel.selection_schema, module.block_model.ArmLinuxBlockModel.selection_schema)


if __name__ == '__main__':
    unittest.main()
