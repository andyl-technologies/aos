# SPDX-License-Identifier: MIT
"""Refuses incomplete or inflated mechanism metadata before profile emission.

These are data-contract cases. Their fixture is not native evidence and cannot
construct a live certificate, installed qualification or prepared owner.
"""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    'source_owned_device_profile', Path(__file__).with_name('device-profile.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def evidence():
    branch = {'fresh_byte_closure': True, 'held_original_request_and_future_reply': True,
              'native_completion_unchanged': True, 'group_reclaimed': True,
              'original_terminal_births_and_bytes': 100}
    return {'schema': 'crucible.gem5.arm-linux-inflight-device-mechanism.v1',
            'original_namespace_gone': True, 'closed_terminal_monitor': True,
            'external_serial_admitted': False, 'typed_diagnostics_complete': False,
            'common_preparation_qualified': False, 'full_device_parity_qualified': False,
            'cpu_timing_qualified': False, 'guest_application_ready_qualified': False,
            'capture_phase': 'first-kernel-virtio-block-request-v1',
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
            for field in ('fresh_byte_closure', 'held_original_request_and_future_reply',
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

    def test_configuration_census_requires_immutable_source_route(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                module.configuration_tree(Path(directory))

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


if __name__ == '__main__':
    unittest.main()
