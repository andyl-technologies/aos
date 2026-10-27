# SPDX-License-Identifier: MIT
"""Checks closed block model wiring as pure data, without native authority."""

import copy
import importlib.util
from pathlib import Path
import sys
import types
import unittest


class Event:
    def __init__(self):
        self.scheduled_tick = None

    def scheduled(self):
        return self.scheduled_tick is not None

    def when(self):
        return self.scheduled_tick


class Queue:
    def __init__(self):
        self.events = []

    def schedule(self, event, tick):
        self.events.append((event, tick))
        event.scheduled_tick = tick


native = types.ModuleType('m5')
native.event = types.ModuleType('m5.event')
native.event.Event = Event
native.queue = Queue()
native.event.getEventQueue = lambda index: native.queue
native.position = {'tick': '100', 'ordinal': '1', 'tick_ordinal': '1', 'active': True}
native.crucibleEventPosition = lambda: dict(native.position)
native.curTick = lambda: int(native.position['tick'])
native.crucibleDeviceBoundaryState = lambda: {'enabled': True, 'publication_epoch': '1'}
sys.modules['m5'] = native
sys.modules['m5.event'] = native.event
specification = importlib.util.spec_from_file_location(
    'closed_block_model', Path(__file__).with_name('native-controller-arm-block-model.py'))
module = importlib.util.module_from_spec(specification)
specification.loader.exec_module(module)


class Endpoint:
    def __init__(self):
        self.requests = [[1, 100, 17, 1, 1, 0, 512, 1, 1]]
        self.payload = bytes(range(256)) * 2
        self.completions = []
        self.staged = []
        self.acknowledged = []

    def path(self):
        return 'system.block'

    def crucibleRequestPublicationInventory(self):
        return copy.deepcopy(self.requests)

    def crucibleRequestPublicationBytes(self, identifier):
        return list(self.payload)

    def crucibleCompletionInventory(self):
        return copy.deepcopy(self.completions)

    def stageReply(self, *arguments):
        self.staged.append(arguments)
        return True

    def acknowledgeRequest(self, identifier):
        self.acknowledged.append(('request', identifier))
        return True

    def retireCompleted(self, identifier):
        self.acknowledged.append(('completion', identifier))
        return True


class Network:
    def crucibleTxPublicationInventory(self):
        return []


def model():
    result = module.ArmLinuxBlockModel.__new__(module.ArmLinuxBlockModel)
    result.disk = module.backend.ClosedMemoryBlock()
    result.backend_events = {}
    result.publication_bindings = {}
    result.publication_order = []
    result.acknowledged = set()
    result.system = types.SimpleNamespace(block=Endpoint(), net=Network())
    return result


class ModelTests(unittest.TestCase):
    def setUp(self):
        native.queue = Queue()
        native.position = {'tick': '100', 'ordinal': '1', 'tick_ordinal': '1', 'active': True}

    def test_request_birth_seals_future_owned_event_before_disk_effect(self):
        owner = model()
        module.RequestBirthHandler(owner)()
        self.assertEqual(len(native.queue.events), 1)
        event, tick = native.queue.events[0]
        self.assertIs(event, owner.backend_events[1])
        self.assertIs(event.owner, owner)
        self.assertEqual(tick, 10100)
        self.assertEqual(owner.disk.backing, bytearray(module.backend.DISK_BYTES))
        self.assertEqual(owner.disk.commands[1]['payload'], owner.system.block.payload)

    def test_original_birth_retry_does_not_mint_another_event(self):
        owner = model()
        handler = module.RequestBirthHandler(owner)
        handler()
        handler()
        self.assertEqual(len(native.queue.events), 1)

    def test_changed_original_refused_without_replacing_event(self):
        owner = model()
        handler = module.RequestBirthHandler(owner)
        handler()
        owner.system.block.payload = bytes(512)
        with self.assertRaises(ValueError):
            handler()
        self.assertEqual(len(native.queue.events), 1)
        self.assertEqual(owner.disk.backing, bytearray(module.backend.DISK_BYTES))

    def test_reaction_is_genuine_future_callback_and_reply_preserves_parent(self):
        owner = model()
        module.RequestBirthHandler(owner)()
        event = owner.backend_events[1]
        with self.assertRaises(ValueError):
            event()
        native.position = {'tick': '10100', 'ordinal': '2', 'tick_ordinal': '1', 'active': True}
        event()
        self.assertEqual(bytes(owner.disk.backing[512:1024]), owner.system.block.payload)
        self.assertEqual(owner.system.block.staged, [(1, 10101, 23, 0, [])])

    def test_completion_preserves_actual_status_separately_from_head(self):
        owner = model()
        module.RequestBirthHandler(owner)()
        native.position = {'tick': '10100', 'ordinal': '2', 'tick_ordinal': '1', 'active': True}
        owner.backend_events[1]()
        owner.system.block.completions = [[1, 10101, 3, 1, 0, 1, 17, 23, 1, 9]]
        observed = owner.publications()
        self.assertEqual(observed[1]['status'], '0')
        self.assertEqual(observed[1]['descriptor_head'], '9')
        self.assertEqual(observed[1]['causal_parent'], '23')
        self.assertEqual(observed, owner.publications())

    def test_actual_admin_ack_retains_original_position_and_native_effect_once(self):
        owner = model()
        module.RequestBirthHandler(owner)()
        owner.publications()
        native.position['active'] = False
        owner.acknowledge(1)
        native.position.update(tick='200', ordinal='10')
        owner.acknowledge(1)
        self.assertEqual(owner.system.block.acknowledged, [('request', 1)])
        self.assertEqual(owner.disk.acknowledgements[('block_request', 1)], (100, 1, 1))

    def test_exogenous_device_controls_are_refused_before_any_effect(self):
        owner = model()
        with self.assertRaises(ValueError):
            owner.validate_control({'kind': 'device_control'})
        self.assertFalse(owner.disk.commands)
        self.assertFalse(owner.system.block.staged)

    def test_finite_backend_reservation_precedes_native_reactions(self):
        owner = model()
        owner.disk.commands = dict.fromkeys(range(module.backend.MAX_OPERATIONS - 15))
        with self.assertRaises(ValueError):
            owner.reserve_callback_credit()
        self.assertFalse(native.queue.events)
        self.assertFalse(owner.system.block.staged)

    def test_new_profile_is_distinct_from_frozen_first_read_scope(self):
        self.assertNotEqual(module.ArmLinuxBlockModel.schema, module.base.ArmLinuxDeviceModel.schema)
        self.assertNotEqual(module.ArmLinuxBlockModel.model_id, module.base.ArmLinuxDeviceModel.model_id)
        self.assertNotEqual(module.ArmLinuxBlockModel.selection_schema, module.base.ArmLinuxDeviceModel.selection_schema)


if __name__ == '__main__':
    unittest.main()
