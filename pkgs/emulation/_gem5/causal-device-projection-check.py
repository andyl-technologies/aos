# SPDX-License-Identifier: MIT
"""Checks partial coverage, original commitments and the structural byte bound."""

import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    'device_projection', Path(__file__).with_name('causal-device-projection.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def inventory():
    event = {'event_identity': '1', 'event_alias': '0', 'queue_ordinal': '0',
             'tick': '10', 'priority': '-128', 'flags': '0', 'native_type': 'NativeEvent',
             'description': 'actual callback', 'payload_complete': False,
             'modeled_fields': {'callback.owner': '1'}}
    objects = [{'name': f'system.device{index}', 'native_type': 'NativeDevice',
                'object_alias': str(index + 1), 'state_complete': False,
                'modeled_fields': {'virtio.status': '4'}} for index in range(5)]
    return {'schema': 'crucible.gem5.causal-device-state.v1', 'complete': False,
            'selected_names': [item['name'] for item in objects], 'native_tick': '10',
            'unsupported_domains': ['cpu-and-memory'], 'events': [event], 'objects': objects,
            'rng': {'global_seed': '1', 'engines': [{'engine_state': 'actual random state'}]},
            'reference_ledger': [{'reference_identity': '0', 'kind': 'event', 'payload_complete': False}]}


def projected(value=None, rows=None):
    return module.project(inventory() if value is None else value, 'system.terminal',
                          [[1, 10, 1, 1, 0, 91]] if rows is None else rows)


class ProjectionTests(unittest.TestCase):
    def test_original_uart_rows_and_control_values_survive(self):
        result = projected()
        self.assertEqual(result['original_closed_terminal_fifo']['rows'], [[1, 10, 1, 1, 0, 91]])
        self.assertEqual(result['objects'][0]['modeled_fields']['virtio.status'], '4')
        self.assertFalse(result['complete'])
        self.assertEqual(result['diagnostic_scope'], module.PROJECTION_SCOPE)

    def test_ring_cache_and_dma_spans_are_explicit_commitments(self):
        value = inventory()
        fields = value['objects'][0]['modeled_fields']
        omitted = {'virtio.queue[0].descriptor[0].flags': '1',
                   'virtio.queue[0].available.cached[0]': '2',
                   'virtio.queue[0].used.cached[0].id': '3',
                   'request.pending[0].span[0].address': '4'}
        fields.update(omitted)
        item = projected(value)['objects'][0]
        self.assertEqual(item['modeled_fields'], {'virtio.status': '4'})
        self.assertEqual(item['omitted_modeled_fields'], module.commitment(omitted))
        self.assertEqual(item['omitted_modeled_field_count'], '4')

    def test_changed_omitted_state_changes_its_original_commitment(self):
        value = inventory()
        value['objects'][0]['modeled_fields']['request.pending[0].span[0].address'] = '4'
        before = projected(value)
        value['objects'][0]['modeled_fields']['request.pending[0].span[0].address'] = '5'
        self.assertNotEqual(before['objects'][0]['omitted_modeled_fields'],
                            projected(value)['objects'][0]['omitted_modeled_fields'])

    def test_event_birth_metadata_and_payload_commitment_remain_original(self):
        value = inventory()
        row = projected(value)['events'][0]
        self.assertEqual(row[:6], ['1', '0', '0', '10', '-128', '0'])
        self.assertEqual(row[-1], module.commitment(value['events'][0]['modeled_fields'])['sha256'])

    def test_unknown_decimal_geometry_refused(self):
        for value in ('01', '+1', '18446744073709551616', 1):
            with self.assertRaises(ValueError):
                module.decimal(value)

    def test_event_object_and_field_credit_refuse(self):
        for kind in ('events', 'objects', 'fields'):
            value = inventory()
            if kind == 'events':
                value['events'] *= module.MAX_EVENTS + 1
            elif kind == 'objects':
                value['objects'].pop()
            else:
                value['objects'][0]['modeled_fields'] = {str(index): '0' for index in range(module.MAX_FIELDS + 1)}
            with self.assertRaises(ValueError):
                projected(value)

    def test_native_complete_flags_cannot_be_promoted(self):
        for kind in ('global', 'event', 'object'):
            value = inventory()
            if kind == 'global':
                value['complete'] = True
            elif kind == 'event':
                value['events'][0]['payload_complete'] = True
            else:
                value['objects'][0]['state_complete'] = True
            with self.assertRaises(ValueError):
                projected(value)

    def test_original_field_extent_is_reserved_before_blob_allocation(self):
        value = inventory()
        value['objects'][0]['modeled_fields']['oversize'] = 'x' * module.MAX_FIELD_BYTES
        with self.assertRaises(ValueError):
            projected(value)

    def test_original_uart_row_extent_is_reserved(self):
        with self.assertRaises(ValueError):
            projected(rows=[[2**100] * 6])

    def test_rng_and_alias_bodies_are_explicit_commitments(self):
        value = inventory()
        result = projected(value)
        self.assertEqual(result['rng_commitment'], module.commitment(value['rng']))
        self.assertEqual(result['reference_ledger_commitment'], module.commitment(value['reference_ledger']))
        self.assertNotIn('rng', result)
        self.assertNotIn('reference_ledger', result)

    def test_full_source_selected_structural_census_fits_four_mib(self):
        value = inventory()
        event = value['events'][0]
        for key in ('event_identity', 'event_alias', 'queue_ordinal', 'tick', 'flags'):
            event[key] = str(2**64 - 1)
        event['priority'] = str(-(2**63))
        value['events'] *= module.MAX_EVENTS
        fields = {f'control[{index}]' + 'x' * 90: 'v' * 128 for index in range(module.MAX_FIELDS - 4)}
        value['objects'][0]['modeled_fields'] = fields
        rows = [[32768, 1000000000000, 16000000, 1000000, 0, 255]] * module.MAX_TERMINAL_ROWS
        result = projected(value, rows)
        self.assertLess(len(module.canonical(result)), module.MAX_OBJECT_BYTES)


if __name__ == '__main__':
    unittest.main()
