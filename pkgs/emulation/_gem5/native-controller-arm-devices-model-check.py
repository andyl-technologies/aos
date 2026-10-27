# SPDX-License-Identifier: MIT
"""Checks bounded original model custody before actual native qualification."""

import copy
import importlib.util
from pathlib import Path
import sys
import types
import unittest


native = types.ModuleType('m5')
native.curTick = lambda: 10
sys.modules['m5'] = native
spec = importlib.util.spec_from_file_location(
    'crucible_arm_device_model', Path(__file__).with_name('native-controller-arm-devices-model.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Endpoint:
    def __init__(self):
        self.staged = []
        self.acknowledgements = []

    def stageReply(self, *body):
        self.staged.append(body)
        return True

    def stageRx(self, *body):
        self.staged.append(body)
        return True

    def acknowledgeRequest(self, identifier):
        self.acknowledgements.append(identifier)
        return True

    def retireCompleted(self, identifier):
        self.acknowledgements.append(identifier)
        return True

    def acknowledgeTx(self, identifier):
        self.acknowledgements.append(identifier)
        return True

    def crucibleAcknowledgeOutput(self, identifier):
        self.acknowledgements.append(identifier)
        return True


def model():
    value = module.ArmLinuxDeviceModel.__new__(module.ArmLinuxDeviceModel)
    value.publication_bindings = {}
    value.publication_order = []
    value.acknowledged = set()
    value.control_operations = {}
    value.control_bytes = 0
    value.unresolved_control = None
    value.system = types.SimpleNamespace(net=Endpoint(), block=Endpoint())
    value.terminal = Endpoint()
    return value


def command():
    return {'kind': 'device_control', 'operation': 'original-1', 'action': 'block_reply',
            'native_id': '1', 'tick': '11', 'causal_parent': '23', 'status': '0',
            'payload': [0, 1, 2]}


def publication(facet='serial'):
    return {'native_id': '1', 'facet': facet, 'tick': '10', 'event_ordinal': '5',
            'tick_ordinal': '1', 'causal_parent': '0', 'payload': [91]}


class DeviceModelTests(unittest.TestCase):
    def test_original_body_is_staged_once_and_retry_is_identical(self):
        value = model()
        request = command()
        value.validate_control(request)
        response = value.control(request)
        self.assertEqual(value.unresolved_control, request)
        receipt = value.retain_control_response(request, response, {'cut': '1'}, {'cut': '1'})
        value.validate_control(request)
        self.assertEqual(value.control_retry(request), receipt)
        self.assertEqual(len(value.system.block.staged), 1)
        self.assertIsNone(value.unresolved_control)

    def test_changed_original_refused_before_staging(self):
        value = model()
        request = command()
        value.control_operations['original-1'] = (request, {'original': request})
        changed = dict(request, payload=[2])
        with self.assertRaises(ValueError):
            value.validate_control(changed)
        self.assertFalse(value.system.block.staged)

    def test_unresolved_original_blocks_new_input(self):
        value = model()
        value.unresolved_control = command()
        with self.assertRaises(ValueError):
            value.validate_control(command())
        self.assertFalse(value.system.block.staged)

    def test_control_count_credit_precedes_staging(self):
        value = model()
        value.control_operations = {str(index): (None, None)
                                    for index in range(module.MAX_CONTROL_OPERATIONS)}
        with self.assertRaises(ValueError):
            value.validate_control(command())
        self.assertFalse(value.system.block.staged)

    def test_control_bytes_credit_precedes_staging(self):
        value = model()
        value.control_bytes = module.MAX_CONTROL_BYTES - module.MAX_CONTROL_RESPONSE
        with self.assertRaises(ValueError):
            value.validate_control(command())
        self.assertFalse(value.system.block.staged)

    def test_unknown_missing_and_duplicate_interface_keys_refused(self):
        for field in command():
            request = command()
            del request[field]
            with self.assertRaises(ValueError):
                model().validate_control(request)
        with self.assertRaises(ValueError):
            model().validate_control(dict(command(), extra=1))

    def test_input_must_be_strictly_future(self):
        for tick in ('0', '9', '10'):
            with self.assertRaises(ValueError):
                model().validate_control(dict(command(), tick=tick))
        model().validate_control(dict(command(), tick='11'))

    def test_canonical_numeric_contract(self):
        for invalid in ('00', '01', '-1', '1.0', '١', str(1 << 64), 1, True):
            with self.assertRaises(ValueError):
                model().validate_control(dict(command(), native_id=invalid))

    def test_status_and_original_id_have_finite_domains(self):
        for key, invalid in (('native_id', '0'), ('status', '3')):
            with self.assertRaises(ValueError):
                model().validate_control(dict(command(), **{key: invalid}))

    def test_original_payload_octets_and_extent(self):
        for payload in ([True], [-1], [256], bytes([1]), [0] * (module.MAX_PAYLOAD + 1)):
            with self.assertRaises(ValueError):
                model().validate_control(dict(command(), payload=payload))

    def test_network_has_real_frame_minimum_and_zero_status(self):
        for payload, status in (([0] * 13, '0'), ([0] * 14, '1')):
            with self.assertRaises(ValueError):
                model().validate_control(dict(command(), action='network_rx', payload=payload, status=status))
        model().validate_control(dict(command(), action='network_rx', payload=[0] * 14))

    def test_publication_aliases_preserve_independent_native_ids(self):
        value = model()
        serial = publication()
        block = dict(publication('block_request'), payload=[])
        value._publication(('serial', 1), serial)
        value._publication(('block_request', 1), block)
        value._publication(('serial', 1), serial)
        self.assertEqual(value.publication_bindings[('serial', 1)]['output_id'], '1')
        self.assertEqual(value.publication_bindings[('block_request', 1)]['output_id'], '2')
        self.assertEqual(value.publication_bindings[('block_request', 1)]['native_id'], '1')

    def test_publication_bytes_cannot_change(self):
        value = model()
        value._publication(('serial', 1), publication())
        with self.assertRaises(ValueError):
            value._publication(('serial', 1), dict(publication(), payload=[90]))

    def test_missing_original_birth_refused(self):
        for key in ('native_id', 'event_ordinal', 'tick_ordinal'):
            with self.assertRaises(ValueError):
                model()._publication(('serial', 1), dict(publication(), **{key: '0'}))

    def test_callback_batch_binding_credit_checked_before_callbacks(self):
        value = model()
        value.publication_bindings = {index: None for index in range(module.MAX_PUBLICATIONS - 128)}
        value.reserve_callback_credit()
        value.publication_bindings[module.MAX_PUBLICATIONS] = None
        with self.assertRaises(ValueError):
            value.reserve_callback_credit()

    def test_duplicate_ack_does_not_repeat_native_effect(self):
        value = model()
        value._publication(('block_request', 1), publication('block_request'))
        value.acknowledge(1)
        value.acknowledge(1)
        self.assertEqual(value.system.block.acknowledgements, [1])
        with self.assertRaises(ValueError):
            value.acknowledge(2)

    def test_refusal_retains_original_without_staging(self):
        value = model()
        request = command()
        value.validate_control(request)
        receipt = value.refuse_control(request, {'ordinal': '5'}, {'available_bytes': '0'})
        self.assertEqual(receipt['original'], request)
        self.assertFalse(value.system.block.staged)
        self.assertEqual(value.control_retry(request), receipt)

    def test_closed_monitor_batch_reserves_terminal_rows_before_callbacks(self):
        value = model()
        value.terminal.crucibleOutputInventory = lambda: [[0] * 6] * (module.MAX_TERMINAL_ROWS - 32)
        native.crucibleEventPosition = lambda: {'ordinal': '1'}
        self.assertEqual(value.maximum_native_step_events(1000, None), 2)

    def test_closed_monitor_terminal_credit_refuses_before_callback(self):
        value = model()
        value.terminal.crucibleOutputInventory = lambda: [[0] * 6] * (module.MAX_TERMINAL_ROWS - 15)
        native.crucibleEventPosition = lambda: {'ordinal': '1'}
        with self.assertRaises(ValueError):
            value.maximum_native_step_events(1000, None)

    def test_closed_monitor_callback_credit_refuses_before_callback(self):
        value = model()
        value.terminal.crucibleOutputInventory = lambda: []
        native.crucibleEventPosition = lambda: {'ordinal': str(module.MAX_MONITOR_CALLBACKS)}
        with self.assertRaises(ValueError):
            value.maximum_native_step_events(1000, None)

    def test_closed_monitor_does_not_claim_common_full_position_execution(self):
        with self.assertRaises(ValueError):
            model().maximum_native_step_events(1000, {'start': 'common'})

    def test_original_sealed_input_switches_to_single_callback_observation(self):
        value = model()
        value.input_phase_started = True
        value.terminal.crucibleOutputInventory = lambda: []
        native.crucibleEventPosition = lambda: {'ordinal': '1'}
        self.assertEqual(value.maximum_native_step_events(1000, None), 1)

    def test_sealed_input_does_not_bypass_original_terminal_credit(self):
        value = model()
        value.input_phase_started = True
        value.terminal.crucibleOutputInventory = lambda: [[0] * 6] * (module.MAX_TERMINAL_ROWS - 15)
        native.crucibleEventPosition = lambda: {'ordinal': '1'}
        with self.assertRaises(ValueError):
            value.maximum_native_step_events(1000, None)

    def test_original_input_changes_native_mode_only_after_acceptance(self):
        value = model()
        value.validate_control(command())
        self.assertTrue(value.control(command())['accepted'])
        self.assertTrue(value.input_phase_started)

    def test_future_input_upper_bound_precedes_staging(self):
        for tick in (str(module.MAX_MONITOR_TICK), str(module.MAX_MONITOR_TICK + 1)):
            with self.assertRaises(ValueError):
                model().validate_control(dict(command(), tick=tick))

    def test_run_declared_clock_bound_is_enforced(self):
        with self.assertRaises(ValueError):
            model().validate_run({'exclusive_tick': str(module.MAX_MONITOR_TICK + 1), 'exact_range': None})
        model().validate_run({'exclusive_tick': str(module.MAX_MONITOR_TICK), 'exact_range': None})

    def test_source_selected_diagnostic_contract_is_separate(self):
        self.assertEqual(module.ArmLinuxDeviceModel.schema, 'crucible.gem5.arm-linux-devices-native/1')
        self.assertEqual(module.ArmLinuxDeviceModel.selection_schema,
                         'crucible.gem5.arm-linux-net-block-model.v1')
        self.assertNotEqual(module.ArmLinuxDeviceModel.schema, mechanism_schema())


def mechanism_schema():
    return module.mechanism.ArmLinuxModel.schema


if __name__ == '__main__':
    unittest.main()
