"""Actual retained-prefix, SQL and conditional-read observation refusals."""

import copy
import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest


HERE = Path(__file__).parent


def load(name, leaf):
    spec = importlib.util.spec_from_file_location(name, HERE / leaf)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


accounting = load('workflow_accounting', '_hub-managed-workflow-accounting.py')
sql = load('cleanup_sql', '_hub-managed-cleanup-sql.py')
collector = load('sdk_collector', '_hub-managed-gc-observer.py')
gc_tests = load('gc_query_tests', '_hub-managed-gc-window-tests.py')
gc_join_tests = load('gc_join_tests', '_hub-managed-gc-tests.py')
cleanup = load('cleanup_accounting', '_hub-managed-cleanup-accounting.py')


def private_json(path, value):
    body = json.dumps(value, separators=(',', ':')).encode()
    return private_bytes(path, body)


def private_bytes(path, body):
    path.write_bytes(body)
    path.chmod(0o600)
    return {'path': str(path), 'sha256': hashlib.sha256(body).hexdigest(), 'byteSize': len(body)}


def upstream_fixture(root):
    """Build controlled private records for custody refusal tests, not authority."""
    child = root / 'cleanup-loss' / 'upstream'
    child.mkdir(parents=True, mode=0o700)
    arguments = ['/nix/store/controlled-helper', cleanup.HELPER_TEST, '--exact', '--ignored', '--nocapture']
    command = private_bytes(child / 'command-line.private', b''.join(arg.encode() + b'\0' for arg in arguments))
    environment = private_bytes(child / 'environment.private',
        b'AOS_MANAGED_CLEANUP_STARTUP_NONCE=' + b'a' * 32
        + b'\0AOS_MANAGED_CLEANUP_STARTUP_ROOT=' + str(child).encode()
        + b'\0AOS_MANAGED_CLEANUP_CONTROLLED_INPUT=' + str(child / 'authentication-input.json').encode() + b'\0')
    pin = {'pid': 101, 'startTicks': '1', 'ownerUid': os.getuid(), 'executableSha256': 'b' * 64,
        'commandLineSha256': command['sha256'], 'environmentSha256': environment['sha256'],
        'commandLine': command, 'environment': environment}
    files = {field: private_bytes(child / (field + '.private'), field.encode())
        for field in ('request', 'request-signature', 'reply', 'reply-signature')}
    parameters = {'phase': 'authenticate_lost_reply', 'expectedOriginalSha256': 'c' * 64,
        'outputFile': str(child / 'authenticated.json')}
    for field, name in [('request', 'lostRequestFile'), ('request-signature', 'lostRequestSignatureFile'),
                       ('reply', 'lostReplyFile'), ('reply-signature', 'lostReplySignatureFile')]:
        parameters[name] = files[field]['path']
    input_ref = private_json(child / 'authentication-input.json', parameters)
    proof = {'outcome': 'authenticated_completed_response', 'inputSha256': input_ref['sha256'],
        'originalSha256': 'c' * 64, 'protectedProfileDigest': 'd' * 64,
        'nativeExchangeObservations': None, 'authenticatedRequestSha256': files['request']['sha256']}
    output = private_json(child / 'authenticated.json', proof)
    invocation = {'version': 1, 'scope': 'managed_cleanup_upstream_authentication_helper',
        'phase': 'authenticate_lost_reply', 'transportScope': 'read_only_upstream_validation',
        'nativeTransportObservation': None, 'helperProcess': pin, 'arguments': arguments,
        'input': input_ref, 'output': output, 'outputErrorKind': None,
        'started': {'unixNs': '1000', 'monotonicNs': '2000'},
        'finished': {'unixNs': '3000', 'monotonicNs': '4000'},
        'stdout': private_bytes(child / 'authentication.stdout', b'source-only controlled output'),
        'stderr': private_bytes(child / 'authentication.stderr', b''), 'exitCode': 0,
        'failureKind': None, 'completeProcessCustody': True,
        'startupReady': private_json(child / 'authentication-ready.private.json',
            {'version': 1, 'nonce': 'a' * 32, 'pid': 101, 'scope': 'managed_cleanup_before_input'}),
        'startupRelease': private_json(child / 'authentication-release.private.json',
            {'version': 1, 'nonce': 'a' * 32}),
        'outputBound': 65536, 'outputOverflow': {'stdout': False, 'stderr': False},
        'completeOutputCollection': True, 'listenerSourceSha256': 'e' * 64, 'runtimeSourceSha256': 'f' * 64}
    reference = private_json(child / 'authentication-invocation.private.json', invocation)
    authentication = {'invocation': reference, 'helperProcess': invocation, 'files': files, 'proof': proof}
    selected = {'root': str(root), 'servicePid': 42, 'testExecutable': arguments[0],
        'testExecutableSha256': 'b' * 64, 'originalSha256': 'c' * 64, 'protectedProfileDigest': 'd' * 64,
        'listenerSourceSha256': 'e' * 64, 'runtimeSourceSha256': 'f' * 64}
    return authentication, selected


def position(role, offset):
    return {'path': '/private/' + role, 'device': '10', 'inode': '20', 'byteSize': offset}


def interval(start, end, ids=(), sequence=0, scope='business'):
    receipts = {role: {'file': '/retained/' + role, 'before': position(role, start),
        'after': position(role, end), 'capturedBytes': end - start}
        for role in accounting.MANAGED_WORKFLOW_FILE_ROLES}
    rows = {role: {} for role in accounting.MANAGED_WORKFLOW_PROXY_ROLES}
    for role, identity, original in ids:
        rows[role][identity] = {'rowSha256': hashlib.sha256(identity.encode()).hexdigest(),
            'originalRequestId': original, 'transportCallId': identity if role == 'nativeOutbound' else None}
    return {'rawWindowReceipts': receipts, 'rows': rows, 'sequence': sequence, 'scope': scope}


def tuples():
    return {'uploadStateSha256': ['upload', 7, 'abandoned', 'pending', 20, 1, 2, 3],
        'chunkStateSha256': [0, 0, 42, 'sha256:' + 'd' * 64, 'oci/staging/chunk', 10],
        'placementStateSha256': [1, 4, 2, 5, 'qualification/cleanup'],
        'bindingStateSha256': [2, 6, 'binding-stable', 'deployment_r2', False, 3],
        'deleteCapabilitySha256': ['current-fingerprint', 8, 6, 'valid', 9, 'delete']}


def terminal_records():
    common = {'version': 1, 'capture_id': 'a' * 32, 'request_id': 'b' * 32,
        'scope': 'managed_terminal_cleanup', 'key': 'qualification/cleanup/oci/staging/chunk',
        'subject_id': 'c' * 128}
    events = [{'kind': 'request_entry'}]
    for index, method in enumerate(('head', 'get'), 1):
        events.extend([{'kind': 'call_invoke', 'ordinal': index, 'method': method, 'range': None},
            {'kind': 'call_result', 'ordinal': index, 'method': method,
             'outcome': {'kind': 'object', 'size': 42, 'etag': '"tag"', 'version': 'version'}}])
    events.extend([{'kind': 'read_complete', 'ordinal': 2, 'consumed_bytes': 42, 'eof': True,
        'sha256': 'd' * 64, 'etag': '"tag"', 'version': 'version'},
        {'kind': 'call_invoke', 'ordinal': 3, 'method': 'delete', 'range': None},
        {'kind': 'call_result', 'ordinal': 3, 'method': 'delete', 'outcome': {'kind': 'resolved'}},
        {'kind': 'request_terminal', 'healthy': True, 'invoked': 3, 'completed': 3, 'pending': 0}])
    return [{**common, 'event': event} for event in events]


class ManagedWorkflowAccountingTests(unittest.TestCase):
    def test_actual_fixed_prefix_retainer_never_absorbs_later_append(self):
        # Execute the production retainer and its real private-file reader with
        # the selected interpreter. The guest callback is local in this test.
        tree = ast.parse((HERE / '_hub-direct-flow.py').read_bytes())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name in {'retain_direct_log_window', 'retain_direct_flow'}]

        def guest(machine, python, body, selected):
            # The normal guest wrapper dedents embedded Python before running.
            import textwrap
            source = 'import json,base64\nselected=' + repr(selected) + '\n' + textwrap.dedent(body)
            return subprocess.run([sys.executable, '-c', source], capture_output=True,
                                  check=True, timeout=10).stdout.decode()

        namespace = {'Path': Path, 'os': os, 'hashlib': hashlib, 'json': json,
            're': __import__('re'), 'base64': base64, 'direct_guest_python': guest}
        exec(compile(ast.Module(body=functions, type_ignores=[]), 'actual_retainer', 'exec'), namespace)
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                path = Path(directory) / 'actual.log'
                path.write_bytes(b'prefix')
                path.chmod(0o600)
                metadata = path.stat()
                before = {'path': str(path), 'device': str(metadata.st_dev),
                    'inode': str(metadata.st_ino), 'byteSize': 2}
                after = {**before, 'byteSize': 5}
                with path.open('ab') as output:
                    output.write(b'later')
                retained, receipt = namespace['retain_direct_log_window'](
                    None, sys.executable, before, 'actual-prefix', after=after)
                self.assertEqual(retained.read_bytes(), b'efi')
                self.assertEqual(receipt['capturedBytes'], 3)
                for changed in ({**after, 'path': str(path) + '-foreign'},
                                {**after, 'inode': '0'}, {**after, 'byteSize': 1}):
                    with self.assertRaises(ValueError):
                        namespace['retain_direct_log_window'](
                            None, sys.executable, before, 'refused-prefix', after=changed)
                path.write_bytes(b'x')
                with self.assertRaises(subprocess.CalledProcessError):
                    namespace['retain_direct_log_window'](
                        None, sys.executable, before, 'truncated-prefix', after=after)
            finally:
                os.chdir(previous)

    def test_cleanup_subset_requires_fresh_call_sql_sdk_and_actual_consumed_reply(self):
        original = {'placement_prefix': 'qualification/cleanup', 'path': 'oci/staging/chunk',
            'size': 42, 'sha256': 'd' * 64}
        physical = {'object': {'key': 'qualification/cleanup/oci/staging/chunk', 'size': 42,
            'etag': '"tag"', 'provider_version': 'opaque-version'},
            'receipt_digest': 'r', 'original_digest': 'o', 'nonce': 'old', 'request_digest': 'old'}
        # Fresh canonical reply correlation is the compiled shared decoder's
        # responsibility; retained physical fields stay exact across replay.
        actual = {**physical, 'nonce': 'fresh', 'request_digest': 'fresh'}
        body = json.dumps(actual, separators=(',', ':')).encode()
        request_sha, reply_sha = 'a' * 64, hashlib.sha256(body).hexdigest()
        call_id, identity, source = 'b' * 32, 'c' * 32, 'e' * 64
        payload = {field: '0' for field in ('requestRawObjectBytes', 'replyRawObjectBytes',
            'selectedDataBytes', 'semanticOciProjectionBytes')}
        sql_join = {'transportCallId': call_id, 'sourceDigest': source,
                    'requestSha256': request_sha, 'replySha256': reply_sha}
        row = {'requestId': identity, 'operation': 'managed_oci_cleanup',
            'class': 'managed_oci_terminal_cleanup_metadata', 'sourceDigest': source,
            'requestSha256': request_sha, 'replySha256': reply_sha, 'payload': payload}
        call = {'nativeRequestId': identity, 'transportCallIdSha256': hashlib.sha256(call_id.encode()).hexdigest(),
            'requestSha256': request_sha, 'replySha256': reply_sha, 'consumedReplyBytes': len(body)}
        subject = 'f' * 64 + request_sha
        accounting_record = {'auxiliaryHelperInventory': [
            {'nativeTransportObservation': None, 'process': {'pid': 1}},
            {'nativeTransportObservation': None, 'process': {'pid': 2}}],
            'decoded': {'complete': True, 'observations': [row]},
            'independentCurrentSql': [sql_join], 'transport': {'joined': [call]},
            'actualCheckedProfile': {'sourceDigest': source, 'namespaceBackingIdentity': '1' * 64},
            'actualOriginalFingerprint': 'f' * 64,
            'actualSdkWindows': [{'backingIdentity': '1' * 64, 'calls': [], 'brackets': [{
                'scope': 'managed_terminal_cleanup', 'subjectId': subject, 'invoked': 0}]}]}
        read = {'consumedBytes': 42, 'sha256': 'd' * 64}
        joined = accounting.join_checked_cleanup_body_partitions(accounting_record, read, original,
            physical, lambda *args: body)
        self.assertEqual(joined[0]['nativeRequestId'], identity)
        self.assertEqual(joined[0]['payload'], payload)
        for mutate in (
                lambda value: value['actualSdkWindows'][0]['brackets'][0].update(invoked=1),
                lambda value: value['actualSdkWindows'][0]['brackets'][0].update(subjectId='0' * 128),
                lambda value: value['actualCheckedProfile'].update(sourceDigest='0' * 64),
                lambda value: value['independentCurrentSql'][0].update(requestSha256='0' * 64)):
            changed = copy.deepcopy(accounting_record)
            mutate(changed)
            with self.assertRaises(ValueError):
                accounting.join_checked_cleanup_body_partitions(changed, read, original, physical,
                    lambda *args: body)
        with self.assertRaises(ValueError):
            accounting.join_checked_cleanup_body_partitions(accounting_record, read, original, physical,
                lambda *args: body + b' ')
        self.assertEqual(accounting.join_checked_cleanup_body_partitions({**accounting_record,
            'auxiliaryInventoryFailureClass': 'ValueError'}, read, original, physical,
            lambda *args: body), [])

    def test_upstream_child_custody_never_becomes_native_consumption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authentication, selected = upstream_fixture(root)
            result = cleanup.read_managed_cleanup_upstream_invocation(authentication, selected)
            self.assertIsNone(result['nativeTransportObservation'])
            self.assertEqual(result['process']['pid'], 101)
            for mutate in (
                    lambda row: row.update(nativeTransportObservation={}),
                    lambda row: row['outputOverflow'].update(stdout=True),
                    lambda row: row.update(completeOutputCollection=False),
                    lambda row: row['helperProcess'].update(pid=42),
                    lambda row: row.update(outputBound=65537)):
                changed = copy.deepcopy(authentication)
                mutate(changed['helperProcess'])
                changed['invocation'] = private_json(Path(changed['invocation']['path']), changed['helperProcess'])
                with self.assertRaises(ValueError):
                    cleanup.read_managed_cleanup_upstream_invocation(changed, selected)
            authentication['invocation'] = private_json(Path(authentication['invocation']['path']),
                authentication['helperProcess'])
            ready = authentication['helperProcess']['startupReady']
            substituted = {'version': 1, 'nonce': '0' * 32, 'pid': 101, 'scope': 'managed_cleanup_before_input'}
            authentication['helperProcess']['startupReady'] = private_json(Path(ready['path']), substituted)
            authentication['invocation'] = private_json(Path(authentication['invocation']['path']),
                authentication['helperProcess'])
            with self.assertRaises(ValueError):
                cleanup.read_managed_cleanup_upstream_invocation(authentication, selected)

    def test_gc_consumer_reopens_exact_already_retained_action_and_sdk_join(self):
        action, plan, result, sdk, before, after = gc_join_tests.controlled_join()
        source = 'e' * 64
        exchange = {'plan': plan, 'result': result,
            'validationReceipt': {'sourceDigest': source, 'observation': {'sourceDigest': source},
                'requestSha256': 'a' * 64, 'replySha256': 'b' * 64},
            'handlerCompletion': {'nativeRequestId': 'c' * 32}}
        joined = gc_join_tests.helper.join_managed_deletion(action, plan, result, sdk, before, after)
        value = {'evidence': [{'action': action, **exchange}], 'joins': [joined],
            'sdkWindow': sdk, 'before': before, 'after': after}
        body = json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        positive = {'retainedReference': {'file': 'external-direct-flow/gc-positive',
            'sha256': hashlib.sha256(body).hexdigest(), 'byteSize': len(body)}, 'observations': value}
        windows = [{'validatedExchanges': [exchange]}]
        observed = accounting.join_managed_gc_positive_evidence(positive, windows, source,
            lambda reference: body, gc_join_tests.helper.join_managed_deletion)
        self.assertIsNone(observed['nativeBulkBytes'])
        self.assertEqual(observed['joins'][0]['action'], joined)
        for selected in ([], [{'validatedExchanges': [exchange, exchange]}]):
            with self.assertRaises(ValueError):
                accounting.join_managed_gc_positive_evidence(positive, selected, source,
                    lambda reference: body, gc_join_tests.helper.join_managed_deletion)
        with self.assertRaises(ValueError):
            accounting.join_managed_gc_positive_evidence(positive, windows, source,
                lambda reference: body + b' ', gc_join_tests.helper.join_managed_deletion)

    def test_every_actual_epoch_and_startup_row_has_one_root_owner(self):
        first = interval(0, 10, [('nativeOutbound', 'a' * 32, None)], 0)
        gap = interval(10, 20, [('workerOriginal', 'b' * 32, None)], 1, 'startup')
        last = interval(20, 30, [('nativeOutbound', 'c' * 32, None)], 2)
        root = interval(0, 30)
        for item in (first, gap, last):
            for role in accounting.MANAGED_WORKFLOW_PROXY_ROLES:
                root['rows'][role].update(item['rows'][role])
        result = accounting.join_managed_workflow_partition(root, [first, last], [gap])
        self.assertTrue(result['complete'])
        self.assertEqual(result['assigned']['workerOriginal']['b' * 32]['scope'], 'startup')
        for mutate in (
                lambda selected: selected['rows']['nativeOutbound'].pop('c' * 32),
                lambda selected: selected['rows']['nativeOutbound']['a' * 32].update(rowSha256='f' * 64),
                lambda selected: selected['rawWindowReceipts']['nativeHeaders']['after'].update(byteSize=31)):
            selected = copy.deepcopy(root)
            mutate(selected)
            with self.assertRaises(ValueError):
                accounting.join_managed_workflow_partition(selected, [first, last], [gap])
        last['rows']['nativeOutbound']['c' * 32]['transportCallId'] = 'a' * 32
        root['rows']['nativeOutbound']['c' * 32]['transportCallId'] = 'a' * 32
        with self.assertRaises(ValueError):
            accounting.join_managed_workflow_partition(root, [first, last], [gap])

    def test_retained_file_hash_row_truncation_and_symlink_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'rows'
            body = b'{"request_id":"actual"}\n'
            path.write_bytes(body)
            path.chmod(0o600)
            receipt = {'file': str(path), 'sha256': hashlib.sha256(body).hexdigest(), 'capturedBytes': len(body)}
            parser = lambda line: ([json.loads(line)], {})
            rows = accounting.managed_workflow_rows(path, parser, receipt)
            self.assertEqual(set(rows), {'actual'})
            with self.assertRaises(ValueError):
                accounting.managed_workflow_rows(path, parser, {**receipt, 'sha256': 'f' * 64})
            path.write_bytes(body[:-1])
            with self.assertRaises(ValueError):
                accounting.managed_workflow_rows(path, parser)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                accounting.managed_workflow_rows(link, parser)

    def test_actual_controller_retains_restart_gap_and_refuses_overflow_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, retained = {}, {}
            for role in accounting.MANAGED_WORKFLOW_FILE_ROLES:
                path = root / (role + '.log')
                path.write_bytes(b'')
                path.chmod(0o600)
                sources[role] = path

            def pin(machine, tools, path):
                info = Path(path).stat()
                return {'path': str(path), 'device': str(info.st_dev), 'inode': str(info.st_ino),
                    'byteSize': info.st_size}

            def retain_window(machine, python, before, name, after=None):
                after = after or pin(machine, {}, before['path'])
                source = Path(before['path']).read_bytes()[before['byteSize']:after['byteSize']]
                path = root / name
                path.write_bytes(source)
                path.chmod(0o600)
                return path, {'before': before, 'after': after, 'capturedBytes': len(source),
                              'sha256': hashlib.sha256(source).hexdigest()}

            def begin(*args):
                return {'positions': {role: pin(None, {}, path) for role, path in sources.items()},
                        'label': args[-1], 'beforeProcesses': {'worker': copy.deepcopy(args[4])}}

            def finish(*args):
                token = args[-2]
                receipts = {}
                for role, before in token['positions'].items():
                    path, receipt = retain_window(None, None, before, token['label'] + '-' + role)
                    receipts[role] = {'file': str(path), **receipt}
                return {'rawWindowReceipts': receipts, 'workerLogText': 'raw text retained separately'}

            def headers(path, role, prefix):
                return {row['requestId']: row for row in map(json.loads, path.read_text().splitlines())}

            def append(identifier):
                with sources['nativeOutbound'].open('ab') as stream:
                    stream.write(json.dumps({'request_id': identifier}).encode() + b'\n')
                with sources['nativeHeaders'].open('ab') as stream:
                    stream.write(json.dumps({'requestId': identifier,
                        'originalRequestId': None, 'transportCallId': identifier, 'files': {}}).encode() + b'\n')

            workflow = accounting.ManagedWorkflowCapture(None, None, {'python': 'selected'},
                {'coordinates': {'runId': 'a' * 32}}, {'worker': 'A'}, {}, begin, finish,
                pin, retain_window, lambda line, role: ([json.loads(line)], {}), headers,
                lambda name, value: retained.setdefault(name, value))
            append('b' * 32)
            workflow.close({'worker': 'A'})
            append('c' * 32)
            workflow.resume({'worker': 'restored-A'})
            append('d' * 32)
            result = workflow.complete({'worker': 'restored-A'})
            self.assertTrue(result['coverage']['complete'])
            self.assertEqual(result['coverage']['assigned']['nativeOutbound']['c' * 32]['scope'], 'startup')
            self.assertIsNone(result['nativeBulkBytes'])
            complete = [value for name, value in retained.items() if name.endswith('complete-workflow.json')]
            self.assertIsInstance(complete[0], bytes)
            previous = accounting.MANAGED_WORKFLOW_REPORT_BYTES
            try:
                accounting.MANAGED_WORKFLOW_REPORT_BYTES = 1024
                refused = accounting.ManagedWorkflowCapture(None, None, {'python': 'selected'},
                    {'coordinates': {'runId': 'f' * 32}}, {'worker': 'restored-A'}, {}, begin, finish,
                    pin, retain_window, lambda line, role: ([json.loads(line)], {}), headers,
                    lambda name, value: retained.setdefault(name, value))
                append('e' * 32)
                overflow = refused.complete({'worker': 'restored-A'})
                self.assertFalse(overflow['coverage']['complete'])
                self.assertIsNone(overflow['nativeBulkBytes'])
                final = retained['managed-' + 'f' * 32 + '-complete-workflow.json']
                self.assertLessEqual(len(final), 1024)
                self.assertNotIn(b'"complete":true', final)
                self.assertTrue(any('f' * 32 + '-complete-nativeOutbound' in path.name
                                    for path in root.iterdir()))
            finally:
                accounting.MANAGED_WORKFLOW_REPORT_BYTES = previous

    def test_tuple_types_and_changed_current_sql_refuse(self):
        values = tuples()
        hashes = sql.cleanup_sql_hashes(values)
        before = {'sourceDigest': 'e' * 64, 'database': 'actual', 'tuples': values, 'commitments': hashes,
            'afterProcess': {'observedAtUnixMicros': '1'},
            'beforeProcess': {'observedAtUnixMicros': '3'}}
        context = {'contextKind': 'managed_oci_cleanup_delete_checked', 'commitments': hashes,
            'completedAtUnixMicros': '2', 'exchange': {'transportCallId': 'a' * 32,
                'requestSha256': 'b' * 64, 'replySha256': 'c' * 64}}
        helper = {'started': {'unixNs': '1000'}, 'finished': {'unixNs': '3000'},
            'pid': 1, 'startTicks': '1', 'executableSha256': 'd' * 64}
        self.assertEqual(sql.join_managed_cleanup_sql(before, copy.deepcopy(before), context,
            'e' * 64, helper)['transportCallId'], 'a' * 32)
        after = copy.deepcopy(before)
        after['tuples']['bindingStateSha256'][1] += 1
        after['commitments'] = sql.cleanup_sql_hashes(after['tuples'])
        with self.assertRaises(ValueError):
            sql.join_managed_cleanup_sql(before, after, context, 'e' * 64, helper)
        invalid = copy.deepcopy(values)
        invalid['chunkStateSha256'][0] = True
        with self.assertRaises(ValueError):
            sql.cleanup_sql_hashes(invalid)

    def test_normal_settlement_must_preserve_original_and_clear_exact_locators(self):
        before = {'sourceDigest': 'e' * 64, 'database': 'actual', 'tuples': tuples(),
            'afterProcess': {'observedAtUnixMicros': '1'},
            'beforeProcess': {'observedAtUnixMicros': '3'}}
        before['commitments'] = sql.cleanup_sql_hashes(before['tuples'])
        after = copy.deepcopy(before)
        after['tuples']['uploadStateSha256'] = ['upload', 8, 'abandoned', 'complete', 20, None, None, None]
        after['commitments'] = sql.cleanup_sql_hashes(after['tuples'])
        context = {'contextKind': 'managed_oci_cleanup_delete_checked', 'commitments': before['commitments'],
            'completedAtUnixMicros': '2', 'exchange': {'transportCallId': 'a' * 32,
                'requestSha256': 'b' * 64, 'replySha256': 'c' * 64}}
        helper = {'started': {'unixNs': '1000'}, 'finished': {'unixNs': '3000'},
            'pid': 1, 'startTicks': '1', 'executableSha256': 'd' * 64}
        sql.join_managed_cleanup_sql(before, after, context, 'e' * 64, helper, settled=True)
        after['tuples']['uploadStateSha256'][0] = 'another-upload'
        after['commitments'] = sql.cleanup_sql_hashes(after['tuples'])
        with self.assertRaises(ValueError):
            sql.join_managed_cleanup_sql(before, after, context, 'e' * 64, helper, settled=True)

    def test_actual_terminal_eof_joins_exact_subject_hash_size_and_incarnation(self):
        records = terminal_records()
        expected = [{'scope': records[0]['scope'], 'key': records[0]['key'], 'subject_id': 'c' * 128}]
        window = collector.collect(records, 'a' * 32, 'e' * 64, expected)
        original = {'placement_prefix': 'qualification/cleanup', 'path': 'oci/staging/chunk',
            'size': 42, 'sha256': 'd' * 64}
        physical = {'object': {'key': records[0]['key'], 'size': 42, 'etag': '"tag"', 'provider_version': 'version'}}
        result = accounting.join_terminal_provider_read(window, original, physical, 'c' * 128, 'a' * 32, 'e' * 64)
        self.assertEqual(result['consumedBytes'], 42)
        for field, value in [('sha256', 'f' * 64), ('consumed_bytes', 41), ('eof', False), ('version', 'substituted')]:
            changed = copy.deepcopy(window)
            changed['calls'][1]['read'][field] = value
            with self.assertRaises(ValueError):
                accounting.join_terminal_provider_read(changed, original, physical, 'c' * 128, 'a' * 32, 'e' * 64)
        for mutate in (lambda rows: rows.insert(6, copy.deepcopy(rows[5])),
                       lambda rows: rows[5]['event'].update(eof=False),
                       lambda rows: rows[5]['event'].update(etag='"other"')):
            changed = terminal_records()
            mutate(changed)
            with self.assertRaises(ValueError):
                collector.collect(changed, 'a' * 32, 'e' * 64, expected)

    def test_supplied_status_or_digest_never_completes_whole_budget(self):
        original = interval(0, 10, [('workerOriginal', 'a' * 32, None)])
        coverage = accounting.join_managed_workflow_partition(original, [original], [])
        workflow = {'coverage': coverage, 'epochs': [{**original, 'window': {
            'status': 200, 'actorSnapshotSha256': 'a' * 64, 'purposeArtifactSha256': 'b' * 64}}]}
        result = accounting.assess_managed_workflow(workflow, {}, source_digest='c' * 64)
        self.assertFalse(result['complete'])
        self.assertIsNone(result['nativeBulkBytes'])
        self.assertEqual(result['originalCount'], 1)


@unittest.skipUnless(os.environ.get('AOS_MANAGED_GC_TEST_PG_BIN'), 'explicit source-built PostgreSQL required')
class ManagedCleanupPostgresTests(unittest.TestCase):
    # Reuse the existing genuine confined private cluster lifecycle; no second
    # PostgreSQL harness or production database is introduced.
    selected = gc_tests.ManagedGcPostgresProjectionTests
    setUpClass = classmethod(selected.setUpClass.__func__)
    tearDownClass = classmethod(selected.tearDownClass.__func__)
    command = classmethod(selected.command.__func__)
    query = classmethod(selected.query.__func__)

    def test_real_query_geometry_and_post_settlement_original_selection(self):
        self.query('''
          CREATE TABLE oci_upload_sessions(id TEXT, resource_version BIGINT, state TEXT,
            cleanup_state TEXT, finished_at BIGINT, staging_placement_id BIGINT,
            staging_binding_id BIGINT, staging_binding_write_revision BIGINT);
          CREATE TABLE oci_upload_chunks(upload_id TEXT, ordinal BIGINT, byte_offset BIGINT,
            byte_size BIGINT, digest TEXT, staging_object_key TEXT, created_at BIGINT);
          CREATE TABLE surface_placements(id BIGINT, resource_version BIGINT, binding_id BIGINT,
            registry_id BIGINT, prefix TEXT);
          CREATE TABLE bindings(id BIGINT, resource_version BIGINT, stable_id TEXT,
            kind TEXT, is_instance_default BOOLEAN);
          CREATE TABLE binding_write_state(binding_id BIGINT, current_write_revision BIGINT);
          CREATE TABLE oci_conditional_delete_capabilities(binding_id BIGINT,
            binding_resource_version BIGINT, binding_write_revision BIGINT,
            capability_fingerprint TEXT, resource_version BIGINT, state TEXT,
            delete_credential_generation BIGINT, delete_credential_purpose TEXT);
          INSERT INTO oci_upload_sessions VALUES ('upload',7,'abandoned','pending',20,1,2,3);
          INSERT INTO oci_upload_chunks VALUES ('upload',0,0,42,'sha256:' || repeat('d',64), 'oci/staging/chunk',10);
          INSERT INTO surface_placements VALUES (1,4,2,5,'qualification/cleanup');
          INSERT INTO bindings VALUES (2,6,'binding-stable','deployment_r2',false);
          INSERT INTO binding_write_state VALUES (2,3);
          INSERT INTO oci_conditional_delete_capabilities VALUES (2,6,3,'current-fingerprint',8,'valid',9,'delete');
        ''')
        original = {'upload_id': 'upload', 'ordinal': 0, 'placement_id': 1,
                    'binding_id': 2, 'binding_write_revision': 3}
        statement = sql.managed_cleanup_sql_query(original, self.database, gc_tests.sql.transaction)
        before = json.loads(self.query(statement))['value']
        self.assertEqual(before[0]['bindingStateSha256'], [2,6,'binding-stable','deployment_r2',False,3])
        self.query("UPDATE oci_upload_sessions SET resource_version=8, cleanup_state='complete', "
                   "staging_placement_id=NULL, staging_binding_id=NULL, staging_binding_write_revision=NULL")
        after = json.loads(self.query(statement))['value']
        self.assertEqual(len(after), 1)
        self.assertEqual(after[0]['uploadStateSha256'][5:], [None, None, None])
        self.assertEqual(after[0]['chunkStateSha256'], before[0]['chunkStateSha256'])
        self.query('UPDATE binding_write_state SET current_write_revision=4')
        changed = json.loads(self.query(statement))['value']
        self.assertEqual(changed[0]['bindingStateSha256'][-1], 4)
        self.assertNotEqual(sql.cleanup_sql_hashes(changed[0])['bindingStateSha256'],
                            sql.cleanup_sql_hashes(before[0])['bindingStateSha256'])


class ConclusionRetentionTests(unittest.TestCase):
    def test_failed_sink_preserves_the_actual_producer_exception(self):
        original = RuntimeError('producer failed')
        workflow = {'assessment': {'complete': False, 'nativeBulkBytes': None}}

        def failed_sink(name, body):
            raise OSError('sink unavailable')

        with self.assertRaises(RuntimeError) as caught:
            try:
                raise original
            finally:
                accounting.retain_managed_workflow_conclusion(
                    workflow, failed_sink, 'actual-conclusion.json', original)

        self.assertIs(caught.exception, original)
        self.assertEqual(workflow['retentionFailureClass'], 'OSError')
        self.assertEqual(original.__notes__, ['Managed conclusion retention failed: OSError'])
        self.assertIsNone(workflow['assessment']['nativeBulkBytes'])

    def test_failed_sink_stops_an_otherwise_successful_workflow(self):
        workflow = {'assessment': {'complete': True, 'nativeBulkBytes': 0}}

        def failed_sink(name, body):
            raise OSError('sink unavailable')

        with self.assertRaises(OSError):
            accounting.retain_managed_workflow_conclusion(
                workflow, failed_sink, 'actual-conclusion.json')

        self.assertFalse(workflow['assessment']['complete'])
        self.assertIsNone(workflow['assessment']['nativeBulkBytes'])


if __name__ == '__main__':
    unittest.main()
