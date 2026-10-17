# SPDX-License-Identifier: MIT
"""Checks owned 9p callback wiring as data without native capture authority."""

import importlib.util
from pathlib import Path
import struct
import types
import unittest


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


fixtures = load('ninep_wiring_native_stubs', 'native-controller-arm-block-model-check.py')
native = fixtures.native
module = load('ninep_wiring_model', 'native-controller-arm-ninep-model.py')


class Endpoint(fixtures.Endpoint):
    def __init__(self):
        super().__init__()
        version = b'9P2000.L'
        body = struct.pack('<IH', 65536, len(version)) + version
        self.payload = struct.pack('<IBH', 7 + len(body), 100, 65535) + body
        self.requests = [[1, 100, 17, 100, 0, 65535, 4096, 1, 1]]

    def path(self):
        return 'system.ninep'


def model():
    owner = module.ArmLinuxNinepModel.__new__(module.ArmLinuxNinepModel)
    owner.disk = module.block_model.backend.ClosedMemoryBlock()
    owner.backend_events = {}
    owner.ninep = module.backend.ClosedMemoryNinep()
    owner.ninep_events = {}
    owner.publication_bindings = {}
    owner.publication_order = []
    owner.acknowledged = set()
    disk = fixtures.Endpoint()
    disk.requests = []
    owner.system = types.SimpleNamespace(ninep=Endpoint(), block=disk)
    return owner


def react(owner):
    module.NinepRequestHandler(owner)()
    native.position = {'tick': '10100', 'ordinal': '2', 'tick_ordinal': '1', 'active': True}
    owner.ninep_events[1]()
    return owner.ninep.commands[1]['reply']


class ModelTests(unittest.TestCase):
    def setUp(self):
        native.queue = fixtures.Queue()
        native.position = {'tick': '100', 'ordinal': '1', 'tick_ordinal': '1', 'active': True}

    def test_birth_retains_raw_request_and_strong_future_reaction(self):
        owner = model()
        module.NinepRequestHandler(owner)()
        event, tick = native.queue.events[0]
        self.assertIs(event, owner.ninep_events[1])
        self.assertIs(event.owner, owner)
        self.assertEqual(tick, 10100)
        self.assertEqual(owner.ninep.commands[1]['payload'], owner.system.ninep.payload)
        self.assertEqual(owner.ninep.tree.operations, {})
        self.assertEqual(owner.system.ninep.staged, [])

    def test_original_birth_retry_does_not_schedule_twice(self):
        owner = model()
        handler = module.NinepRequestHandler(owner)
        handler()
        handler()
        self.assertEqual(len(native.queue.events), 1)

    def test_changed_original_refused_without_replacing_command(self):
        owner = model()
        handler = module.NinepRequestHandler(owner)
        handler()
        original = owner.system.ninep.payload
        owner.system.ninep.payload = original[:-1] + b'X'
        with self.assertRaises(ValueError):
            handler()
        self.assertEqual(owner.ninep.commands[1]['payload'], original)
        self.assertEqual(len(native.queue.events), 1)

    def test_reaction_negotiates_bounded_reply_and_stages_original_parent(self):
        owner = model()
        reply = react(owner)
        self.assertEqual(struct.unpack_from('<I', reply, 7)[0], 4096)
        self.assertEqual(owner.system.ninep.staged, [(1, 10101, 23, 0, list(reply))])
        self.assertEqual(owner.ninep.tree.operations, {100: 1})

    def test_wrong_reaction_cut_does_not_mutate_tree_or_stage_reply(self):
        owner = model()
        module.NinepRequestHandler(owner)()
        with self.assertRaises(ValueError):
            owner.ninep_events[1]()
        self.assertEqual(owner.ninep.tree.operations, {})
        self.assertEqual(owner.system.ninep.staged, [])

    def test_completion_retains_status_head_and_exact_reply_count(self):
        owner = model()
        reply = react(owner)
        owner.system.ninep.completions = [[1, 10101, 3, 1, 0, len(reply), 17, 23, 1, 7]]
        output = owner.publications()
        self.assertEqual([row['facet'] for row in output], ['ninep_request', 'ninep_completion'])
        self.assertEqual(output[0]['payload'], list(owner.system.ninep.payload))
        self.assertEqual(output[0]['tag'], '65535')
        self.assertEqual(output[1]['count'], str(len(reply)))
        self.assertEqual(output[1]['status'], '0')
        self.assertEqual(output[1]['descriptor_head'], '7')
        self.assertEqual(output, owner.publications())

    def test_request_ack_and_completion_retirement_keep_first_positions(self):
        owner = model()
        reply = react(owner)
        owner.system.ninep.completions = [[1, 10101, 3, 1, 0, len(reply), 17, 23, 1, 7]]
        owner.publications()
        native.position = {'tick': '10101', 'ordinal': '3', 'tick_ordinal': '1', 'active': False}
        owner.acknowledge(1)
        owner.acknowledge(2)
        native.position.update(tick='20000', ordinal='7')
        owner.acknowledge(1)
        owner.acknowledge(2)
        self.assertEqual(owner.system.ninep.acknowledged, [('request', 1), ('completion', 1)])
        self.assertEqual(owner.ninep.acknowledgements[('ninep_request', 1)], (10101, 3, 1))
        self.assertEqual(owner.ninep.acknowledgements[('ninep_completion', 1)], (10101, 3, 1))

    def test_external_filesystem_inputs_are_refused_before_effects(self):
        owner = model()
        with self.assertRaises(ValueError):
            owner.validate_control({'kind': 'device_control'})
        self.assertEqual(owner.ninep.commands, {})
        self.assertEqual(owner.system.ninep.staged, [])
        self.assertEqual(owner.system.block.staged, [])

    def test_rejected_native_request_ack_does_not_mark_owned_server(self):
        owner = model()
        module.NinepRequestHandler(owner)()
        owner.publications()
        native.position['active'] = False
        before = owner.ninep.inventory()
        owner.system.ninep.acknowledgeRequest = lambda identifier: False

        with self.assertRaises(ValueError):
            owner.acknowledge(1)

        self.assertEqual(owner.ninep.inventory(), before)
        self.assertEqual(owner.ninep.acknowledgements, {})
        self.assertEqual(owner.acknowledged, set())

    def test_rejected_native_completion_keeps_original_request_ack(self):
        owner = model()
        reply = react(owner)
        owner.system.ninep.completions = [[1, 10101, 3, 1, 0, len(reply), 17, 23, 1, 7]]
        owner.publications()
        native.position = {'tick': '10101', 'ordinal': '3', 'tick_ordinal': '1', 'active': False}
        owner.acknowledge(1)
        before = owner.ninep.inventory()
        owner.system.ninep.retireCompleted = lambda identifier: False

        with self.assertRaises(ValueError):
            owner.acknowledge(2)

        self.assertEqual(owner.ninep.inventory(), before)
        self.assertEqual(owner.acknowledged, {('ninep_request', 1)})
        self.assertNotIn(('ninep_completion', 1), owner.ninep.acknowledgements)

    def test_raised_native_request_ack_does_not_commit_candidate_ledger(self):
        owner = model()
        module.NinepRequestHandler(owner)()
        owner.publications()
        native.position['active'] = False
        before = owner.ninep.inventory()

        def reject(identifier):
            raise RuntimeError('native administration is uncertain')

        owner.system.ninep.acknowledgeRequest = reject
        with self.assertRaises(RuntimeError):
            owner.acknowledge(1)

        self.assertEqual(owner.ninep.inventory(), before)
        self.assertEqual(owner.acknowledged, set())

    def test_source_command_credit_precedes_whole_callback(self):
        owner = model()
        owner.ninep.commands = dict.fromkeys(range(module.backend.MAX_OPERATIONS - 15))
        with self.assertRaises(ValueError):
            owner.reserve_callback_credit()
        self.assertEqual(native.queue.events, [])
        self.assertEqual(owner.system.ninep.staged, [])

    def test_boot_disk_retains_separate_command_ownership(self):
        owner = model()
        owner.system.block.requests = [[1, 100, 17, 0, 0, 0, 512, 1, 1]]
        owner.system.block.payload = b''
        module.block_model.RequestBirthHandler(owner)()
        self.assertIs(native.queue.events[0][0], owner.backend_events[1])
        self.assertEqual(owner.ninep.commands, {})
        self.assertEqual(owner.disk.backing, bytearray(1048576))

    def test_model_is_distinct_from_existing_root_and_block(self):
        self.assertNotEqual(module.ArmLinuxNinepModel.schema, module.block_model.ArmLinuxBlockModel.schema)
        self.assertNotEqual(module.ArmLinuxNinepModel.model_id, module.block_model.ArmLinuxBlockModel.model_id)
        self.assertNotEqual(module.ArmLinuxNinepModel.selection_schema,
                            module.block_model.ArmLinuxBlockModel.selection_schema)


if __name__ == '__main__':
    unittest.main()
