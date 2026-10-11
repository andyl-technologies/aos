"""Exercise exclusive epoch coverage and closed External process-role selection."""

import copy
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


class ExternalCaptureTests(unittest.TestCase):
    def setUp(self):
        self.fixture = module('_hub-external-oci-accounting')
        self.fixture.native_corpus_json = module('_hub-native-corpus-segments').native_corpus_json
        self.window = module('_hub-managed-storage-window')
        self.run = 'a' * 32
        self.row = {'rowSha256': 'b' * 64, 'originalRequestId': None,
            'transportCallId': 'c' * 32, 'compactSha256': 'd' * 64}

    def receipt(self, role, start, end):
        identity = {'path': '/private/' + role, 'device': '1', 'inode': '2'}
        return {'before': {**identity, 'byteSize': start}, 'after': {**identity, 'byteSize': end},
            'capturedBytes': end - start}

    def interval(self, start, end, sequence):
        return {'sequence': sequence, 'scope': 'business', 'rows': {
            role: {} for role in self.fixture.EXTERNAL_BODY_ROLES}, 'rawWindowReceipts': {
                role: self.receipt(role, start, end) for role in self.fixture.EXTERNAL_PROXY_FILES}}

    def corpus(self):
        first, second = self.interval(0, 10, 0), self.interval(10, 20, 1)
        first['rows']['nativeOutbound']['1' * 32] = self.row
        root = {'rows': {role: dict(first['rows'][role]) for role in self.fixture.EXTERNAL_BODY_ROLES},
            'rawWindowReceipts': {role: self.receipt(role, 0, 20)
                for role in self.fixture.EXTERNAL_PROXY_FILES}}
        return root, [first, second]

    def test_distinct_process_logs_do_not_replace_the_complete_proxy_inventory(self):
        root, intervals = self.corpus()
        # Process logs are retained in each window. They do not acquire the
        # other executable's inode or enter the global fixed-proxy partition.
        intervals[0]['window'] = {'processObservations': {'native': {'pid': 10}},
            'rawWindowReceipts': {'nativeLog': {'before': {'inode': '30'}}}}
        intervals[1]['window'] = {'processObservations': {'native': {'pid': 11}},
            'rawWindowReceipts': {'nativeLog': {'before': {'inode': '31'}}}}

        observed = self.fixture.join_external_epoch_partition(root, intervals)

        self.assertTrue(observed['complete'])
        self.assertEqual(observed['assigned']['nativeOutbound']['1' * 32]['interval'], 0)
        self.assertNotIn('nativeBulkBytes', observed)

    def test_missing_prefix_duplicate_row_and_inode_substitution_refuse(self):
        root, intervals = self.corpus()
        cases = []
        missing = copy.deepcopy(intervals)
        missing[1]['rawWindowReceipts']['nativeHeaders']['before']['byteSize'] = 11
        cases.append(missing)
        duplicate = copy.deepcopy(intervals)
        duplicate[1]['rows']['nativeOutbound']['1' * 32] = self.row
        cases.append(duplicate)
        changed = copy.deepcopy(intervals)
        changed[1]['rawWindowReceipts']['workerOriginal']['after']['inode'] = '3'
        cases.append(changed)
        omitted = copy.deepcopy(intervals)
        omitted[0]['rows']['nativeOutbound'].clear()
        cases.append(omitted)

        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.fixture.join_external_epoch_partition(root, case)

    def test_external_log_roles_are_closed_and_default_managed_layout_is_preserved(self):
        selected = {'run': self.run, 'sourceDigest': 'b' * 64, 'nativeAddress': '10.0.0.2'}
        self.assertEqual(self.window.selected_storage_window_roots(selected)['prefix'], 'managed-' + self.run)
        external = {**selected, 'kind': 'external_oci', 'nativeRole': 'ordinary_native'}
        roots = self.window.selected_storage_window_roots(external)
        processes = {'native': {'logFile': roots['native'] + '/native-bootstrap.log'},
            'worker': {'logFile': roots['worker'] + '/external-oci-final.log'}}
        self.window.validate_selected_storage_logs(external, processes, roots)
        helper = {**external, 'nativeRole': 'controlled_external_oci_native'}
        with self.assertRaises(ValueError):
            self.window.validate_selected_storage_logs(helper, processes, roots)
        processes['native']['logFile'] = roots['native'] + '/native-controlled.log'
        self.window.validate_selected_storage_logs(helper, processes, roots)
        with self.assertRaises(ValueError):
            self.window.managed_window_selector({'captureSelection': {**external, 'nativeRole': 'managed_native'}},
                {'run': self.run}, 'external-whole-0')

    def test_external_roots_cannot_be_selected_as_managed_or_arbitrary_paths(self):
        selected = {'run': self.run, 'sourceDigest': 'b' * 64, 'nativeAddress': '10.0.0.2',
            'kind': 'external_oci', 'nativeRole': 'controlled_external_oci_native'}
        self.window.managed_window_selector({'captureSelection': selected}, {'run': self.run}, 'external-whole-0')
        for extra in ({'root': '/somewhere'}, {'kind': 'hosted'}, {'nativeAddress': '127.0.0.1'}):
            with self.assertRaises(ValueError):
                self.window.managed_window_selector({'captureSelection': {**selected, **extra}},
                    {'run': self.run}, 'external-whole-0')


if __name__ == '__main__':
    unittest.main()
