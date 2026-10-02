"""Private-file and called-controller joins without Native or provider claims."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('cleanup_accounting', HERE / '_hub-managed-cleanup-accounting.py')
accounting = importlib.util.module_from_spec(spec)
spec.loader.exec_module(accounting)
ROUTE = '/_internal/storage/managed-oci-cleanup/v1'
RUN = 'a' * 32


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def retained(path, body):
    path.write_bytes(body)
    path.chmod(0o600)
    return {'path': str(path), 'sha256': hashlib.sha256(body).hexdigest(), 'byteSize': len(body)}


def scope():
    result = {}
    for name in ('_hub-native-corpus-segments.py', '_hub-storage-capture.py',
            '_hub-storage-final-sql.py', '_hub-managed-terminal-cleanup.py'):
        exec(compile((HERE / name).read_bytes(), name, 'exec'), result)
    result['_closed_review_json'] = json.loads
    return result


def events(index=1, outcome='success'):
    call_id = format(index, '032x')
    request, reply = hashlib.sha256(b'request').hexdigest(), hashlib.sha256(b'reply').hexdigest()
    auth = {'version': 2, 'transportCallId': call_id, 'route': ROUTE, 'planId': 'b' * 64,
        'operation': 'managed_oci_cleanup', 'requestSha256': request, 'replySha256': reply,
        'requestBytes': 7, 'replyBytes': 5}
    context = {'version': 1, 'exchange': auth, 'contextKind': 'managed_oci_cleanup_delete_checked',
        'commitments': {name: 'c' * 64 for name in scope()['STORAGE_FINAL_SQL_COMMITMENTS'][
            'managed_oci_cleanup_delete_checked']}, 'completedAtUnixMicros': '1500000'}
    context['commitments'].update(requestSha256=request, replySha256=reply)
    numeric = {'message': 'hybrid storage exchange accounting', 'transport_call_id': call_id,
        'offered_request_sha256': request, 'plan_id': 'b' * 64, 'operation': 'managed_oci_cleanup',
        'exchange_attempts': '1', 'offered_plan_bytes': '7', 'observed_body_bytes': '5',
        'discarded_status_responses': '0', 'outcome': outcome, 'exchange_elapsed_ms': '2'}
    if outcome != 'success':
        numeric['observed_body_bytes'] = '0'
        return [numeric]
    return [{'message': 'storage_final_sql_checked ' + encoded(context).decode()},
        {'message': 'managed_oci_cleanup_authenticated ' + encoded(auth).decode()}, numeric]


def fixture(root, label='positive', phase='replay_positive', rows=None, index=1):
    directory = root / 'cleanup-helper' / label
    directory.parent.mkdir(mode=0o700, exist_ok=True)
    directory.mkdir(mode=0o700)
    rows = events(index) if rows is None else rows
    parameters = {'phase': phase, 'outputFile': str(directory / 'result.private.json'),
        'privateCredentialFile': '/private/credential-do-not-echo'}
    retained(directory / 'input.private.json', encoded(parameters))
    observations = None if phase in accounting.READONLY_PHASES else {
        'version': 1, 'scope': 'actual_native_managed_cleanup_transport', 'complete': True, 'events': rows}
    value = {'nativeExchangeObservations': observations, 'inputSha256': hashlib.sha256(encoded(parameters)).hexdigest(),
        'originalSha256': 'a' * 64, 'originalFingerprint': 'b' * 64, 'protectedProfileDigest': 'c' * 64}
    output = retained(directory / 'result.private.json', encoded(value))
    arguments = ['/nix/store/controlled-helper', accounting.HELPER_TEST, '--exact', '--ignored', '--nocapture']
    command = retained(directory / 'command-line.private', b''.join(arg.encode() + b'\0' for arg in arguments))
    environment = retained(directory / 'environment.private',
        b'AOS_MANAGED_CLEANUP_CONTROLLED_INPUT=' + str(directory / 'input.private.json').encode()
        + b'\0PRIVATE_VALUE=do-not-echo\0')
    stdout = retained(directory / 'stdout', b'\n'.join(
        accounting.HELPER_PREFIX.encode() + encoded(row) for row in rows)
        + b'\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n')
    stderr = retained(directory / 'stderr', b'')
    invocation = {'version': 1, 'scope': 'actual_managed_cleanup_native_helper',
        'pid': 1000 + index, 'startTicks': str(index), 'ownerUid': os.getuid(),
        'executableSha256': 'd' * 64, 'commandLineSha256': command['sha256'],
        'environmentSha256': environment['sha256'], 'commandLine': command, 'environment': environment,
        'arguments': arguments, 'started': {'unixNs': '1000000000', 'monotonicNs': '1000000'},
        'finished': {'unixNs': '2000000000', 'monotonicNs': '2000000'},
        'stdout': stdout, 'stderr': stderr, 'exitCode': 0,
        'commonSourceStorePath': '/nix/store/current-common',
        'workerFilteredSourceStorePath': '/nix/store/current-worker', 'provenanceSha256': 'e' * 64}
    invocation_ref = retained(directory / 'invocation.private.json', encoded(invocation))
    helper = {'value': value, 'input': parameters, 'receipt': {**output,
        'testExecutableSha256': 'd' * 64, 'provenanceSha256': 'e' * 64,
        'exitCode': 0, 'invocation': invocation_ref, 'helperProcess': invocation}}
    selected = {'root': str(root), 'label': label, 'phase': phase,
        'commonSourceStorePath': '/nix/store/current-common',
        'workerFilteredSourceStorePath': '/nix/store/current-worker',
        'testExecutableSha256': 'd' * 64, 'provenanceSha256': 'e' * 64, 'servicePid': 42}
    return helper, selected


class CleanupInvocationTests(unittest.TestCase):
    def test_actual_private_files_equal_subscriber_output_without_private_values(self):
        with tempfile.TemporaryDirectory() as directory:
            helper, selected = fixture(Path(directory))
            projected = accounting.read_managed_cleanup_invocation(helper, selected)
            parsed = accounting.cleanup_invocation_events(projected,
                scope()['validate_storage_authenticated_value'], scope()['validate_storage_final_sql_value'])

            self.assertEqual(len(parsed['authenticated']), 1)
            self.assertEqual(len(parsed['contexts']), 1)
            self.assertIsNone(parsed['nativeBulkBytes'])
            self.assertNotIn('do-not-echo', json.dumps(projected))
            self.assertNotEqual(projected['process']['pid'], selected['servicePid'])

    def test_changed_private_body_and_foreign_process_or_source_refuse(self):
        for change in ('body', 'process', 'source', 'stdout'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                helper, selected = fixture(Path(directory))
                if change == 'body':
                    Path(helper['receipt']['path']).write_bytes(b'{}')
                elif change == 'process':
                    selected['servicePid'] = helper['receipt']['helperProcess']['pid']
                elif change == 'source':
                    selected['commonSourceStorePath'] = '/nix/store/substituted'
                else:
                    helper['value']['nativeExchangeObservations']['events'].pop()
                with self.assertRaises(ValueError):
                    accounting.read_managed_cleanup_invocation(helper, selected)

    def test_readonly_upstream_authentication_cannot_supply_native_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            helper, selected = fixture(Path(directory), phase='authenticate_lost_reply', rows=[])
            actual = accounting.read_managed_cleanup_invocation(helper, selected)
            self.assertEqual(actual['events'], [])
            self.assertIsNone(actual['nativeBulkBytes'])
            selected['phase'] = 'replay_positive'
            helper['input']['phase'] = selected['phase']
            with self.assertRaises(ValueError):
                accounting.read_managed_cleanup_invocation(helper, selected)

    def test_subscriber_overflow_null_and_excess_rows_refuse(self):
        for change in ('incomplete', 'null', 'rows'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                rows = events() if change != 'rows' else events() * 22
                helper, selected = fixture(Path(directory), rows=rows)
                if change == 'incomplete':
                    helper['value']['nativeExchangeObservations']['complete'] = False
                elif change == 'null':
                    helper['value']['nativeExchangeObservations'] = None
                helper['receipt'].update(retained(Path(helper['receipt']['path']), encoded(helper['value'])))
                with self.assertRaises(ValueError):
                    accounting.read_managed_cleanup_invocation(helper, selected)

    def test_failure_numeric_rows_preserve_actual_exposure_without_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            helper, selected = fixture(Path(directory), phase='dispatch_unknown', rows=events(outcome='transport_failed'))
            projected = accounting.read_managed_cleanup_invocation(helper, selected)
            parsed = accounting.cleanup_invocation_events(projected,
                scope()['validate_storage_authenticated_value'], scope()['validate_storage_final_sql_value'])
            self.assertEqual(parsed['authenticated'], [])
            self.assertEqual(parsed['contexts'], [])
            self.assertEqual(parsed['numeric'][0]['observed_body_bytes'], '0')
            self.assertIsNone(parsed['nativeBulkBytes'])

    def test_duplicate_call_counter_body_and_lifetime_substitution_refuse(self):
        base = {'events': events(), 'process': {'started': {'unixNs': '1000000000'},
            'finished': {'unixNs': '2000000000'}}}
        for change in ('duplicate', 'count', 'body', 'clock'):
            projected = copy.deepcopy(base)
            if change == 'duplicate':
                projected['events'].append(projected['events'][-1])
            elif change == 'count':
                projected['events'][-1]['observed_body_bytes'] = '6'
            else:
                context = json.loads(projected['events'][0]['message'].split(' ', 1)[1])
                if change == 'body':
                    context['commitments']['replySha256'] = 'f' * 64
                else:
                    context['completedAtUnixMicros'] = '2000001'
                projected['events'][0]['message'] = 'storage_final_sql_checked ' + encoded(context).decode()
            with self.subTest(change=change), self.assertRaises(ValueError):
                accounting.cleanup_invocation_events(projected,
                    scope()['validate_storage_authenticated_value'], scope()['validate_storage_final_sql_value'])

    def test_retained_proxy_stream_hash_custody_and_size_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            reference = retained(Path(directory) / 'rows', b'closed\n' * 20000)
            accounting.verify_cleanup_retained_window(reference, reference['byteSize'])
            for bad in ({**reference, 'sha256': '0' * 64}, {**reference, 'byteSize': reference['byteSize'] - 1}):
                with self.assertRaises(ValueError):
                    accounting.verify_cleanup_retained_window(bad, reference['byteSize'])
            with self.assertRaises(ValueError):
                accounting.verify_cleanup_retained_window(reference, reference['byteSize'] - 1)

    def test_shared_closed_receipt_keeps_managed_cleanup_sixteen_kib_bound(self):
        value = json.loads(events()[1]['message'].split(' ', 1)[1])
        validate = scope()['validate_storage_authenticated_value']
        validate(value, {ROUTE: 'managed_oci_cleanup'})
        for field in ('requestBytes', 'replyBytes'):
            with self.assertRaises(ValueError):
                validate({**value, field: 16385}, {ROUTE: 'managed_oci_cleanup'})


class CleanupControllerTests(unittest.TestCase):
    def run_controller(self, directory, change=None):
        root = Path(directory)
        environment = scope()
        artifacts, executions = {}, []

        def retain(name, value):
            if name in artifacts:
                raise ValueError('controlled retained artifact replacement')
            body = value if isinstance(value, bytes) else encoded(value)
            artifacts[name] = body
            return hashlib.sha256(body).hexdigest()

        environment['retain_direct_flow'] = retain
        environment['managed_fixture_module'] = lambda *args: accounting
        helpers, selectors = {}, {}
        for field, label, phase, index in (
                ('original', 'select-real-sql', 'select_original', 4),
                ('unknown', 'lost-response', 'dispatch_unknown', 1),
                ('replay', 'cold-positive', 'replay_positive', 2),
                ('settlement', 'normal-recovery', 'settle', 3)):
            rows = [] if field == 'original' else events(index,
                'transport_failed' if field == 'unknown' else 'success')
            helpers[field], selectors[label] = fixture(root, label, phase, rows, index)

        def guest(machine, python, script, selected, timeout):
            # This controlled callback executes real private-file validation;
            # it does not assert a running Native/Worker or ELF qualification.
            return json.dumps(accounting.read_managed_cleanup_invocation(
                selected['helper'], selectors[selected['label']]))

        environment['direct_guest_python'] = guest
        windows = []
        for index in (1, 2, 3):
            call_id, received_id = format(index, '032x'), format(index + 100, '032x')
            reference = lambda body: {'file': '/controlled/private-body',
                'sha256': hashlib.sha256(body).hexdigest(), 'byteSize': len(body)}
            original = {'requestId': call_id, 'procedure': ROUTE, 'method': 'POST', 'phase': '',
                'status': 200, 'responseContentType': 'application/json', 'responseContentEncoding': '',
                'bodies': {'request': reference(b'request'), 'response': reference(b'reply')}}
            received = {**copy.deepcopy(original), 'requestId': received_id}
            if index == 1:
                original['status'] = 502
                original['bodies']['response'] = None
            raw = {'version': '4', 'request_id': call_id, 'origin_request_id': '',
                'path_and_query': ROUTE, 'method': 'POST', 'phase': '', 'status': str(original['status']),
                'ingress': '', 'query_class': 'absent', 'transport_call_id': call_id,
                'request_signature': '', 'reply_signature': '', 'oci_request_signature': '', 'oci_reply_signature': '',
                **{name: '' for name in environment['EXTERNAL_OCI_SIGNATURE_FIELDS']},
                'managed_oci_cleanup_request_signature': 'a' * 64,
                'managed_oci_cleanup_reply_signature': 'b' * 64 if index != 1 else ''}
            worker = {**raw, 'request_id': received_id, 'origin_request_id': call_id, 'status': '200',
                'managed_oci_cleanup_reply_signature': 'b' * 64}
            native_path, worker_path = root / ('native-' + str(index)), root / ('worker-' + str(index))
            native_ref = retained(native_path, encoded(raw) + b'\n')
            worker_ref = retained(worker_path, encoded(worker) + b'\n')
            window_receipt = lambda ref: {'file': ref['path'], 'sha256': ref['sha256'],
                'capturedBytes': ref['byteSize'], 'collectionStartedAtUnixMicros': '900000',
                'collectionFinishedAtUnixMicros': '2100000'}
            originals = [original]
            if index == 3:
                # Real whole-window behavior must preserve concurrent service
                # rows even though this fixture provides no supported codec.
                originals.append({**copy.deepcopy(original), 'requestId': 'f' * 32,
                    'procedure': '/_internal/storage/unsupported', 'bodies': {'request': None, 'response': None}})
            windows.append({'storageBoundary': {'captureProvenance': {'sourceDigest': 'a' * 64, 'run': RUN},
                'nativeOriginalBodies': {'bodies': originals}, 'workerReceivedBodies': {'bodies': [received]}},
                'processObservations': {'native': {'pid': 42, 'executableSha256': '0' * 64}},
                'nativeServiceAuthenticatedRows': [], 'nativeServiceFinalSqlRows': [],
                'nativeIngressBoundary': {'codecInput': {'completeOriginalInventory': None,
                    'unresolvedOriginalRequestIds': [], 'unselectedReceivedRequestIds': []}},
                'rawWindowReceipts': {'nativeOutbound': window_receipt(native_ref),
                    'nativeHeaders': window_receipt(native_ref), 'workerHeaders': window_receipt(worker_ref),
                    **{name: window_receipt(native_ref) for name in (
                        'workerOriginal', 'nativeReceived', 'workerOriginalHeaders', 'nativeReceivedHeaders')}}})
        result = {**helpers, 'windows': windows,
            'completedResponseLoss': {'receipt': {'path': '/private/upstream-loss', 'sha256': '1' * 64}},
            'replayAuthentication': {'authentication': {'proofFile': {'path': '/private/upstream-replay', 'sha256': '2' * 64}}}}
        if change:
            change(environment, result)
        environment['validate_managed_codec_selection'] = lambda *args: {'codecSourceSha256': 'b' * 64}

        def codec(selection, bundle, codec_source, source, artifact_namespace):
            executions.append(bundle)
            return {'complete': True, 'nativeBulkBytes': None, 'scope': 'controlled controller callback only'}

        environment['run_storage_workflow_codec_segments'] = codec
        report = environment['account_managed_cleanup_windows'](None, {
            'python': 'controlled', 'managedCleanupAccounting': str(HERE / '_hub-managed-cleanup-accounting.py'),
            'managedCleanupNativeHelperProvenance': '/controlled/proof',
            'managedCleanupNativeHelper': '/nix/store/controlled-helper', 'commonSourceStorePath': '/nix/store/current-common',
            'workerSourcePath': '/nix/store/current-worker', 'deploymentId': 'controlled'},
            {'captureSelection': {'run': RUN, 'sourceDigest': 'a' * 64},
                'coordinates': {'nativeRoot': str(root)}},
            {'codecSelection': {}, 'codecProvenance': {}}, result)
        return report, artifacts, executions

    def test_called_controller_keeps_loss_service_and_auxiliary_unknowns_and_executes_positive_codec(self):
        with tempfile.TemporaryDirectory() as directory:
            report, _, executions = self.run_controller(directory)
            self.assertNotIn('failureClass', report)
            self.assertEqual(report['completeOriginalInventory']['originalCount'], 4)
            self.assertEqual(len(report['helperInventory']), 4)
            self.assertEqual(len(report['transport']['joined']), 2)
            self.assertEqual(len(report['finalSql']['joined']), 2)
            self.assertEqual(set(report['unresolvedNativeRequestIds']), {'1'.zfill(32), 'f' * 32})
            self.assertEqual(len(executions), 1)
            self.assertEqual(sum(len(page['manifest']['cases']) for page in executions[0]['segments']), 2)
            self.assertEqual(len(report['auxiliaryHelperInventory']), 2)
            self.assertFalse(report['complete'])
            self.assertIsNone(report['nativeBulkBytes'])

    def test_called_controller_reused_helper_lifetime_and_cross_window_call_refuse(self):
        def lifetime(environment, result):
            result['settlement'] = result['replay']

        def call(environment, result):
            first = result['windows'][1]['rawWindowReceipts']['nativeHeaders']
            second = result['windows'][2]['rawWindowReceipts']['nativeHeaders']
            value = json.loads(Path(second['file']).read_bytes())
            value['transport_call_id'] = json.loads(Path(first['file']).read_bytes())['transport_call_id']
            ref = retained(Path(second['file']), encoded(value) + b'\n')
            second.update(sha256=ref['sha256'], capturedBytes=ref['byteSize'])

        for change in (lifetime, call):
            with self.subTest(change=change.__name__), tempfile.TemporaryDirectory() as directory:
                report, _, executions = self.run_controller(directory, change)
                self.assertEqual(report['failureClass'], 'ValueError')
                self.assertIsNone(report['nativeBulkBytes'])
                self.assertEqual(executions, [])

    def test_called_controller_exact_report_overflow_never_persists_oversized_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            report, artifacts, _ = self.run_controller(directory,
                lambda environment, result: environment.update(NATIVE_SEGMENT_REPORT_BYTE_LIMIT=512))
            self.assertEqual(report['failureClass'], 'RetainedReportOverflow')
            self.assertIsNone(report['nativeBulkBytes'])
            self.assertLessEqual(len(artifacts['managed-cleanup-accounting-' + RUN + '.json']), 512)


if __name__ == '__main__':
    unittest.main()
