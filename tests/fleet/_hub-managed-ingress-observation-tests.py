"""Actual private-file joins and consumed-prefix/refusal accounting regressions.

Controlled fixtures exercise custody and source parser/consumer behavior only;
no fixture emits an authorization, current-state or provider qualification.
"""

import ast
import copy
import hashlib
import importlib.util
import json
import os
import re
import stat
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).parent


def load(name, leaf):
    spec = importlib.util.spec_from_file_location(name, HERE / leaf)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


window = load('ingress_window', '_hub-managed-storage-window.py')
capture = load('ingress_capture', '_hub-storage-capture.py')
accounting = load('ingress_accounting', '_hub-managed-workflow-accounting.py')
window.native_corpus_json = lambda value: json.dumps(value, separators=(',', ':')).encode()
window._closed_review_json = json.loads
capture._closed_review_json = json.loads
window.observed_native_messages = capture.observed_native_messages
SOURCES = {'nativeHandlerSourceSha256': '1' * 64, 'checkedContextSourceSha256': '2' * 64}


def digest(body):
    return hashlib.sha256(body).hexdigest()


def frames(body, eof=True):
    return {'exposedBytes': str(len(body)), 'exposedSha256': digest(body),
        'eof': eof, 'failed': False, 'overflow': False}


def event(identifier='a' * 32):
    return {'version': 1, 'requestId': identifier, 'method': 'PUT',
        'pathSha256': digest(b'/v2/aos/manifests/tag?aos_hybrid_manifest_upload=' + b'c' * 32),
        'compactSha256': digest(b'controlled compact'), 'originalSha256': '4' * 64,
        'phase': 'complete', **SOURCES, 'envelopeAuthenticated': True, 'bodyAuthenticated': True,
        'stage': 'handler_completed', 'status': 201,
        'checkedContexts': {'incomplete': False, 'checks': [
            {'kind': kind, 'accepted': True, 'checkedContextSha256': '5' * 64,
             'observedAtUnixMicros': '100'} for kind in ('oci_actor_current', 'oci_manifest_catalog_current')]},
        'requestConsumed': frames(b'{}'), 'replyOffered': frames(b''), 'completedAtUnixMicros': '200'}


class IngressObservationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.originals, self.received, self.before, self.after = [], [], {}, {}
        self.add_exchange('a' * 32, 'b' * 32)

    def private(self, name, body):
        path = self.root / name
        path.write_bytes(body)
        path.chmod(0o600)
        return {'file': str(path), 'sha256': digest(body), 'byteSize': len(body)}

    def add_exchange(self, original, received):
        target = b'/v2/aos/manifests/tag?aos_hybrid_manifest_upload=' + b'c' * 32
        def body_row(identifier):
            return {'requestId': identifier, 'method': 'PUT', 'phase': 'complete', 'status': 201,
                'bodies': {'request': self.private(identifier + '-request', b'{}'),
                           'response': self.private(identifier + '-response', b'')}}
        def header(identifier, original_id):
            return {'requestId': identifier, 'originalRequestId': original_id, 'files': {
                'path_and_query': self.private(identifier + '-target', target),
                'ingress': self.private(identifier + '-compact', b'controlled compact')}}
        self.originals.append(body_row(original))
        self.received.append(body_row(received))
        self.before[original] = header(original, None)
        self.after[received] = header(received, original)

    def join(self, events):
        return window.join_ingress_application_observations(self.originals, self.received,
            self.before, self.after, events, lambda reference: Path(reference['file']).read_bytes())

    def decoded(self):
        return {'operation': 'oci_manifest_complete', 'class': 'oci_distribution_control_metadata',
            'requestSha256': digest(b'{}'), 'replySha256': digest(b''),
            'payload': {field: '0' for field in ('requestRawObjectBytes', 'replyRawObjectBytes',
                                               'selectedDataBytes', 'semanticOciProjectionBytes')}}

    def test_actual_private_plain_log_is_source_and_process_bound(self):
        value = event()
        path = self.root / 'native.log'
        path.write_text(window.INGRESS_EVENT_PREFIX + json.dumps(value) + '\n')
        path.chmod(0o600)
        raw = path.read_bytes()
        metadata = path.stat()
        process = {'pid': os.getpid(), 'ownerUid': os.getuid(), 'startTicks': 'controlled',
            'executableSha256': '6' * 64, 'commandLineSha256': '7' * 64, 'commandLineBytes': '42',
            'environmentSha256': '8' * 64, 'logFile': str(path)}
        position = {'path': str(path), 'device': str(metadata.st_dev), 'inode': str(metadata.st_ino)}
        provenance = {'beforeProcess': process, 'afterProcess': process, 'window': {
            'file': str(path), 'before': {**position, 'byteSize': 0},
            'after': {**position, 'byteSize': len(raw)}, 'capturedBytes': len(raw), 'sha256': digest(raw)}}

        rows = window.ingress_application_observations(path, process, provenance, SOURCES)
        self.assertEqual(rows, [value])
        foreign = {**process, 'pid': process['pid'] + 1}
        with self.assertRaises(ValueError):
            window.ingress_application_observations(path, foreign, provenance, SOURCES)
        path.write_bytes(raw[:-1])
        with self.assertRaises(ValueError):
            window.ingress_application_observations(path, process, provenance, SOURCES)

    def test_source_substitution_and_new_permission_flags_refuse(self):
        value = event()
        value['nativeHandlerSourceSha256'] = '9' * 64
        with self.assertRaises(ValueError):
            window.validate_ingress_application_observation(value, SOURCES)
        value = event()
        value['authorized'] = True
        with self.assertRaises(ValueError):
            window.validate_ingress_application_observation(value, SOURCES)

    def test_identical_bodies_stay_exclusive_per_actual_request_id(self):
        self.add_exchange('d' * 32, 'e' * 32)
        joined = self.join([event(), event('d' * 32)])
        self.assertEqual(len(joined['joined']), 2)
        self.assertEqual(joined['unresolved'], [])
        ambiguous = self.join([event(), event()])
        self.assertEqual(ambiguous['joined'], [])
        self.assertEqual(len(ambiguous['unresolved']), 2)

    def test_late_refused_identical_call_cannot_borrow_accepted_checks(self):
        self.add_exchange('d' * 32, 'e' * 32)
        refused = event('d' * 32)
        refused.update(status=401, stage='envelope_refused', checkedContexts=None,
                       envelopeAuthenticated=False, bodyAuthenticated=False, phase=None)
        refused['requestConsumed'] = frames(b'', False)
        self.originals[1]['status'] = self.received[1]['status'] = 401
        joined = self.join([event(), refused])
        self.assertEqual([row['handlerOutcome'] for row in joined['joined']], ['completed', 'refused'])
        self.assertIsNone(joined['joined'][1]['checkedContexts'])

    def test_body_substitution_and_prefix_mismatch_never_join(self):
        self.received[0]['bodies']['request'] = self.private('substitute', b'[]')
        self.assertEqual(self.join([event()])['joined'], [])
        self.received[0]['bodies']['request'] = self.private('restore', b'{}')
        value = event()
        value['requestConsumed']['exposedSha256'] = digest(b'[]')
        self.assertEqual(self.join([value])['joined'], [])

    def test_complete_metadata_uses_real_existing_checks(self):
        call = self.join([event()])['joined'][0]
        self.assertEqual(accounting.assess_ingress_body_partition(self.decoded(), call), [])
        call['checkedContexts']['checks'].clear()
        self.assertIn('missing_actual_oci_actor_or_catalog_check',
            accounting.assess_ingress_body_partition(self.decoded(), call))

    def test_expected_refusal_does_not_require_success_receipt(self):
        value = event()
        value.update(status=403, checkedContexts={'checks': [], 'incomplete': False})
        self.originals[0]['status'] = self.received[0]['status'] = 403
        call = self.join([value])['joined'][0]
        row = self.decoded()
        row['operation'] = 'ingress_refused_control'
        row['class'] = 'ingress_refused_metadata'
        self.assertEqual(accounting.assess_ingress_body_partition(row, call), [])
        row['class'] = 'oci_distribution_control_metadata'
        self.assertIn('refused_ingress_body_not_source_classified',
            accounting.assess_ingress_body_partition(row, call))

    def test_partial_metadata_prefix_does_not_borrow_content_partition(self):
        value = event()
        value['requestConsumed'] = frames(b'{', False)
        call = self.join([value])['joined'][0]
        self.assertEqual(accounting.assess_ingress_body_partition(self.decoded(), call), [])
        row = self.decoded()
        row['payload']['selectedDataBytes'] = '2'
        self.assertIn('unmapped_partial_content_partition',
            accounting.assess_ingress_body_partition(row, call))

    def test_cancelled_stream_has_no_completed_acceptance(self):
        value = event()
        value.update(stage='cancelled', checkedContexts=None)
        call = self.join([value])['joined'][0]
        self.assertIn('incomplete_ingress_acceptance',
            accounting.assess_ingress_body_partition(self.decoded(), call))


class WholeIngressAccountingTests(unittest.TestCase):
    """Exercise the actual final consumer over a complete controlled private join."""

    setUp = IngressObservationTests.setUp
    private = IngressObservationTests.private
    add_exchange = IngressObservationTests.add_exchange
    join = IngressObservationTests.join
    decoded = IngressObservationTests.decoded

    def workflow(self, refused=False):
        value = event()
        if refused:
            value.update(status=403, checkedContexts={'checks': [], 'incomplete': False})
            self.originals[0]['status'] = self.received[0]['status'] = 403
        joined = self.join([value])
        row = {**self.decoded(), 'requestId': 'a' * 32, 'sourceDigest': 'c' * 64}
        if refused:
            row.update(operation='ingress_refused_control', **{'class': 'ingress_refused_metadata'})
        roles = accounting.MANAGED_WORKFLOW_PROXY_ROLES
        assigned = {role: {} for role in roles}
        assigned['workerOriginal']['a' * 32] = {
            'originalRequestId': None, 'transportCallId': None, 'scope': 'business'}
        assigned['nativeReceived']['b' * 32] = {
            'originalRequestId': 'a' * 32, 'transportCallId': None, 'scope': 'business'}
        window = {'nativeIngressBoundary': {
            'workerOriginalBodies': {'bodies': self.originals},
            'applicationObservations': joined,
            'decoded': {'complete': True, 'observations': [row]}}}
        return {'coverage': {'complete': True, 'assigned': assigned,
            'inventorySha256': digest(b'controlled complete membership')},
            'epochs': [{'window': window}], 'failureClass': None}

    def assess(self, workflow):
        return accounting.assess_managed_workflow(workflow, {}, source_digest='c' * 64)

    def test_whole_consumer_distinguishes_captured_bound_from_unknown_consumption(self):
        observed = self.assess(self.workflow())
        self.assertTrue(observed['complete'])
        self.assertEqual(observed['originalCount'], observed['decodedOriginalCount'])
        self.assertEqual(observed['capturedApplicationObjectByteUpperBound'], 0)
        self.assertEqual(observed['capturedApplicationBodyBytes'], {'originalRequests': 2, 'fullReplies': 0})
        self.assertIsNone(observed['nativeConsumedApplicationBytes'])
        self.assertIsNone(observed['nativeBulkBytes'])

    def test_whole_consumer_accounts_expected_refused_original(self):
        observed = self.assess(self.workflow(refused=True))
        self.assertTrue(observed['complete'])
        self.assertEqual(observed['originalCount'], 1)
        self.assertIsNone(observed['nativeBulkBytes'])

    def test_whole_consumer_omission_substitution_and_unassigned_event_refuse(self):
        for defect in ('omitted', 'source', 'unassigned', 'capture', 'bodyCount'):
            with self.subTest(defect=defect):
                workflow = self.workflow()
                ingress = workflow['epochs'][0]['window']['nativeIngressBoundary']
                if defect == 'omitted':
                    ingress['decoded']['observations'].clear()
                elif defect == 'source':
                    ingress['decoded']['observations'][0]['sourceDigest'] = 'd' * 64
                elif defect == 'unassigned':
                    ingress['applicationObservations']['unassignedEventCount'] = 1
                elif defect == 'bodyCount':
                    ingress['workerOriginalBodies']['bodies'][0]['bodies']['request']['sha256'] = 'f' * 64
                else:
                    workflow['coverage']['complete'] = False
                observed = self.assess(workflow)
                self.assertFalse(observed['complete'])
                self.assertIsNone(observed['nativeBulkBytes'])

    def test_whole_consumer_partial_document_and_duplicate_codec_ownership_refuse(self):
        workflow = self.workflow()
        ingress = workflow['epochs'][0]['window']['nativeIngressBoundary']
        ingress['decoded']['observations'][0]['payload']['replyRawObjectBytes'] = '2'
        ingress['applicationObservations']['joined'][0]['partitions']['replyOffered']['eof'] = False
        observed = self.assess(workflow)
        self.assertFalse(observed['complete'])
        self.assertIsNone(observed['nativeBulkBytes'])
        workflow = self.workflow()
        rows = workflow['epochs'][0]['window']['nativeIngressBoundary']['decoded']['observations']
        rows.append(copy.deepcopy(rows[0]))
        with self.assertRaises(ValueError):
            self.assess(workflow)


class OutboundCorpusPreparationTests(unittest.TestCase):
    """Use the actual private reader and global partition with retained failures."""

    setUp = IngressObservationTests.setUp
    private = IngressObservationTests.private
    add_exchange = IngressObservationTests.add_exchange

    def prepare(self, original, received, before, after):
        segments = load('actual_corpus_segments', '_hub-native-corpus-segments.py')
        window.native_corpus_inventory = segments.native_corpus_inventory
        window.partition_native_codec_corpus = segments.partition_native_codec_corpus
        source = ast.parse((HERE / '_hub-direct-flow.py').read_text())
        reader = next(node for node in source.body
            if isinstance(node, ast.FunctionDef) and node.name == 'direct_selected_bytes')
        namespace = {'os': os, 're': re, 'stat': stat, 'hashlib': hashlib}
        exec(compile(ast.Module(body=[reader], type_ignores=[]), 'actual_private_reader', 'exec'), namespace)
        window.direct_selected_bytes = namespace['direct_selected_bytes']
        return window.prepare_managed_outbound_codec_segments(original, received, before, after,
            'c' * 64, 'fixture')

    def exchange(self, original='a' * 32, received='b' * 32, target='/unknown/control'):
        def row(identifier):
            return {'requestId': identifier, 'procedure': target, 'method': 'POST', 'phase': '',
                'status': 200, 'responseContentType': 'application/json', 'responseContentEncoding': '',
                'bodies': {'request': self.private(identifier + '-out-request', b'{}'),
                           'response': self.private(identifier + '-out-reply', b'{}')}}
        def header(identifier, original_id):
            return {'requestId': identifier, 'originalRequestId': original_id,
                'transportCallId': 'f' * 32, 'files': {
                    'path_and_query': self.private(identifier + '-out-target', target.encode())}}
        return row(original), row(received), header(original, None), header(received, original)

    def test_unsupported_actual_original_is_retained_in_the_called_codec_selection(self):
        original, received, before, after = self.exchange()
        result = self.prepare([original], [received], {'a' * 32: before}, {'b' * 32: after})
        self.assertEqual(result['completeOriginalInventory']['originalCount'], 1)
        self.assertEqual(result['selectedCodecSegments']['originalCount'], 1)
        case = result['selectedCodecSegments']['segments'][0]['manifest']['cases'][0]
        self.assertEqual(case['pathAndQuery'], '/unknown/control')
        self.assertIsNone(result['nativeBulkBytes'])

    def test_missing_and_substituted_reply_keep_the_complete_original_unresolved(self):
        for defect in ('missing', 'substituted'):
            with self.subTest(defect=defect):
                original, received, before, after = self.exchange()
                if defect == 'missing':
                    received['bodies']['response'] = None
                else:
                    received['bodies']['response'] = self.private('different-out-reply', b'[]')
                result = self.prepare([original], [received], {'a' * 32: before}, {'b' * 32: after})
                self.assertEqual(result['completeOriginalInventory']['originalCount'], 1)
                self.assertEqual(result['unresolvedOriginalRequestIds'], ['a' * 32])
                self.assertIsNone(result['selectedCodecSegments'])
                self.assertIsNone(result['nativeBulkBytes'])

    def test_distinct_originals_cannot_reuse_one_actual_call_id_in_global_pages(self):
        first = self.exchange()
        second = self.exchange('d' * 32, 'e' * 32)
        with self.assertRaises(ValueError):
            self.prepare([first[0], second[0]], [first[1], second[1]],
                {'a' * 32: first[2], 'd' * 32: second[2]},
                {'b' * 32: first[3], 'e' * 32: second[3]})


if __name__ == '__main__':
    unittest.main()
