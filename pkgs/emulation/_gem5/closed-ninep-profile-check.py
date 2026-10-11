# SPDX-License-Identifier: MIT
"""Refuses incomplete or inflated mechanism metadata before profile emission.

These are data-contract cases. Their fixture is not native evidence and cannot
construct a live certificate, installed qualification or prepared owner.
"""

import importlib.util
import os
import hashlib
import struct
from pathlib import Path
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    'source_owned_device_profile', Path(__file__).with_name('closed-ninep-profile.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def evidence():
    branch = {'fresh_byte_closure': True, 'held_original_write_and_owned_future_tree_reaction': True,
              'native_completion_unchanged': True, 'group_reclaimed': True,
              'original_terminal_births_and_bytes': 100}
    return {'schema': 'crucible.gem5.arm-linux-closed-ninep-lifecycle-mechanism.v1',
            'original_namespace_gone': True, 'closed_terminal_monitor': True,
            'external_serial_admitted': False, 'typed_diagnostics_complete': False,
            'common_preparation_qualified': False, 'full_device_parity_qualified': False,
            'cpu_timing_qualified': False, 'guest_application_ready_qualified': False,
            'capture_phase': 'application-ninep-write-before-owned-tree-reaction-v1',
            'actual_application_init_ready_observed': True, 'actual_ninep_write_flush_readback_verified': True,
            'original_request': {'facet': 'ninep_request', 'endpoint': 'system.ninep',
                                 'native_id': '3', 'tick': '100', 'event_ordinal': '10',
                                 'tick_ordinal': '1', 'causal_parent': '17', 'output_id': '7',
                                 'opcode': '118', 'sector': '0', 'tag': '7', 'count': '4096',
                                 'payload': list(struct.pack('<IBHIQI', 23 + len(b'crucible native 9p ownership\n\0'),
                                                            118, 7, 1, 0, len(b'crucible native 9p ownership\n\0'))
                                                 + b'crucible native 9p ownership\n\0')},
            'final_file_sha256': hashlib.sha256(b'crucible native 9p ownership\n\0').hexdigest(),
            'final_flushed_file_sha256': hashlib.sha256(b'crucible native 9p ownership\n\0').hexdigest(),
            'branches': [dict(branch, name='child-a'), dict(branch, name='child-b')]}


class ProfileTests(unittest.TestCase):
    def test_finite_mechanism_contract_accepts_no_admission(self):
        module.validate_evidence(evidence())

    def test_missing_real_gate_is_refused(self):
        for field in ('original_namespace_gone', 'closed_terminal_monitor'):
            body = evidence()
            body[field] = False
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.validate_evidence(body)

    def test_scope_cannot_promote_public_or_timing_admission(self):
        for field in ('external_serial_admitted', 'typed_diagnostics_complete',
                      'common_preparation_qualified', 'full_device_parity_qualified',
                      'cpu_timing_qualified', 'guest_application_ready_qualified'):
            body = evidence()
            body[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.validate_evidence(body)

    def test_wrong_phase_and_predecessor_schema_are_refused(self):
        for field, value in (('capture_phase', 'pid1-ready'), ('schema', 'uart-only')):
            body = evidence()
            body[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.validate_evidence(body)

    def test_both_fresh_branches_need_all_actual_gates(self):
        for index in range(2):
            for field in ('fresh_byte_closure', 'held_original_write_and_owned_future_tree_reaction',
                          'native_completion_unchanged', 'group_reclaimed'):
                body = evidence()
                body['branches'][index][field] = False
                with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                    module.validate_evidence(body)

    def test_duplicate_child_does_not_stand_for_two_owners(self):
        body = evidence()
        body['branches'][1]['name'] = 'child-a'
        with self.assertRaises(ValueError):
            module.validate_evidence(body)

    def test_original_uart_custody_is_nonzero_bounded_and_equal(self):
        for count in (0, 32769, True, '100', 99):
            body = evidence()
            body['branches'][1]['original_terminal_births_and_bytes'] = count
            with self.subTest(count=count), self.assertRaises(ValueError):
                module.validate_evidence(body)

    def test_application_readiness_and_incoming_markers_are_mandatory(self):
        for field in ('actual_application_init_ready_observed', 'actual_ninep_write_flush_readback_verified'):
            body = evidence()
            body[field] = False
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.validate_evidence(body)

    def test_held_write_must_be_the_exact_guest_application_original(self):
        for field, value in (('facet', 'ninep'), ('endpoint', 'system.block'),
                             ('causal_parent', '0'), ('payload', [0] * 64)):
            body = evidence()
            body['original_request'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.validate_evidence(body)

    def test_configuration_census_requires_immutable_source_route(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                module.configuration_tree(Path(directory))

    def test_unknown_original_frame_fields_refuse(self):
        body = evidence()
        body['original_request']['unmeasured_input'] = 'external'
        with self.assertRaises(ValueError):
            module.validate_evidence(body)

    def test_malformed_original_native_birth_geometry_refuses(self):
        for field, value in (('native_id', '0'), ('native_id', '129'),
                             ('tick', '0100'), ('event_ordinal', '16000001'),
                             ('tick_ordinal', '0'), ('output_id', True)):
            body = evidence()
            body['original_request'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                module.validate_evidence(body)

    def test_write_geometry_and_every_original_byte_are_required(self):
        for payload in (evidence()['original_request']['payload'][:-1],
                        [0] + evidence()['original_request']['payload'][1:]):
            body = evidence()
            body['original_request']['payload'] = payload
            with self.assertRaises(ValueError):
                module.validate_evidence(body)

    def test_configuration_census_uses_native_canonical_row_codec(self):
        source = Path('/nix/store/fixed-source/configs')
        leaf = source / 'model.py'
        metadata = type('Metadata', (), {'st_mode': 0o40555})()
        entries = [type('Entry', (), {'path': str(leaf),
                                    'is_dir': lambda self, **kwargs: False})()]
        with mock.patch.object(Path, 'resolve', lambda value: value), \
                mock.patch.object(Path, 'lstat', return_value=metadata), \
                mock.patch.object(module.os, 'scandir') as scan, \
                mock.patch.object(module, 'measure', return_value={
                    'length': '0', 'sha256': 'a' * 64}) as measure:
            scan.return_value.__enter__.return_value = entries
            actual = module.configuration_tree(source)
        import hashlib
        import json
        expected_rows = [{'path': 'model.py', 'bytes': '0', 'sha256': 'a' * 64}]
        expected_body = json.dumps(expected_rows, sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(actual, {'files': '1', 'bytes': '0',
                                  'sha256': hashlib.sha256(expected_body).hexdigest()})
        measure.assert_called_once_with(leaf, maximum=64 * 1024**2)

    def test_measure_refuses_symlink_and_multiple_link_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            leaf = root / 'leaf'
            leaf.write_bytes(b'owned-original-artifact')
            (root / 'symlink').symlink_to(leaf)
            with self.assertRaises(OSError):
                module.measure(root / 'symlink')
            os.link(leaf, root / 'hardlink')
            with self.assertRaises(ValueError):
                module.measure(leaf)


    def test_source_file_and_flush_bytes_are_mandatory(self):
        for field in ('final_file_sha256', 'final_flushed_file_sha256'):
            body = evidence()
            body[field] = '0' * 64
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.validate_evidence(body)

    def test_message_tag_and_original_writable_extent_are_checked(self):
        for field, value in (('tag', '8'), ('count', '10'), ('count', '4097'),
                             ('count', '04096'), ('count', True), ('opcode', '116')):
            body = evidence()
            body['original_request'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.validate_evidence(body)

    def test_native_message_header_fields_cannot_be_regenerated(self):
        for offset in (0, 4, 5, 7, 11, 19):
            body = evidence()
            body['original_request']['payload'][offset] ^= 1
            # A different valid FID is allowed within this fixed root/probe
            # model. The sentinel is not a legitimate retained native FID.
            if offset == 7:
                body['original_request']['payload'][7:11] = [255] * 4
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                module.validate_evidence(body)

    def test_payload_booleans_are_not_native_bytes(self):
        body = evidence()
        body['original_request']['payload'][23] = True
        with self.assertRaises(ValueError):
            module.validate_evidence(body)

    def test_primitive_envelopes_require_exact_enabled_and_disabled_modes(self):
        body = {
            'schema': 'crucible.gem5.closed-ninep-native-boundary-mechanism.v1',
            'mode': 'enabled', 'actual_request_birth_handler': True,
            'strong_owned_future_reply_event': True, 'exclusive_ceiling_preserved': True,
            'original_9p_tag_reply_bytes_verified': True, 'head1_status0_independently_verified': True,
            'completion_excludes_block_status_octet': True,
            'original_request_ack_completion_retirement': True,
            'linux_ready_qualified': False, 'opaque_capture_qualified': False,
            'common_admission_qualified': False, 'device_parity_qualified': False,
        }
        module.validate_primitive(body, 'enabled')
        with self.assertRaises(ValueError):
            module.validate_primitive(body, 'disabled')
        for field in ('head1_status0_independently_verified', 'completion_excludes_block_status_octet'):
            changed = dict(body)
            changed[field] = False
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.validate_primitive(changed, 'enabled')
        for field in ('linux_ready_qualified', 'opaque_capture_qualified',
                      'common_admission_qualified', 'device_parity_qualified'):
            changed = dict(body)
            changed[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.validate_primitive(changed, 'enabled')
        with self.assertRaises(ValueError):
            module.validate_primitive(dict(body, unknown=True), 'enabled')

if __name__ == '__main__':
    unittest.main()
