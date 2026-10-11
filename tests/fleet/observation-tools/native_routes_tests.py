"""Synthetic source-contract joins, never actual authentication or hosted proof."""

import argparse
import ast
import copy
from pathlib import Path
import unittest

import native_inventory as inventory
import native_routes as routes


SOURCE = Path(__file__).resolve().parents[3]
WINDOW = 'a' * 32
IDENTIFIER = 'b' * 32


def read_source(path, maximum):
    raw = Path(path).read_bytes()
    if len(raw) > maximum:
        raise ValueError('Synthetic source exceeds bound')
    return raw


def frame(raw):
    return {'exposedBytes': str(len(raw)), 'exposedSha256': routes.sha(raw),
            'eof': True, 'failed': False, 'overflow': False}


def fixture(shell=False):
    method, path = next(key for key in routes.ROUTES if (key[0] == 'GET') == shell)
    classification, constructor, required = routes.ROUTES[(method, path)]
    request, response = (b'', b'synthetic bounded template output') if shell else (
        b'{}', b'{"directRequired":true}')
    images = {name: {'byteSize': str(len(raw)), 'sha256': routes.sha(raw),
                    'typedSemanticSha256': routes.sha(raw)}
              for name, raw in (('request', request), ('response', response))}
    constructor_sha = routes.sha(read_source(SOURCE / routes.BROWSER_SOURCE, 1024 * 1024)) if shell else (
        routes.sha(b''.join(read_source(SOURCE / name, 1024 * 1024) for name in routes.RPC_SOURCES)))
    browser = {'handlerSourceSha256': constructor_sha, 'templateSha256': 'e' * 64,
               'assetVersion': 'deadbeef', 'consoleJsSha256': 'e' * 64,
               'consoleWasmSha256': 'e' * 64, 'consoleCssSha256': 'e' * 64}
    member = {'requestId': IDENTIFIER, 'queryClass': 'absent', 'method': method,
              'pathSha256': routes.sha(path.encode()), 'status': 200, 'handlerReturned': True,
              'requestTrailers': False, 'replyTrailers': False,
              'requestConsumed': frame(request), 'replyOffered': frame(response),
              'typedEvidence': {'constructor': constructor, 'constructorSourceSha256': constructor_sha,
                  'requiredProjection': required, 'request': None if shell else {
                      'byteSize': str(len(request)), 'sha256': routes.sha(request)},
                  'reply': {'byteSize': str(len(response)), 'sha256': routes.sha(response)}}}
    row = {'requestIdSha256': routes.sha(IDENTIFIER.encode()), 'method': method, 'procedure': path,
           'phase': None, 'class': classification, **images,
           'browserSource': browser if shell else None,
           'authentication': 'not_checked_join_independent_authenticated_worker_receipt'}
    capture = {'requestId': IDENTIFIER, 'method': method, 'procedure': path, 'phase': None,
               'status': 200, 'bodies': {name: {'sha256': value['sha256'], 'byteSize': value['byteSize']}
                                       for name, value in images.items()}}
    manifest = {'codecRevision': 'c' * 40, 'sourceDigest': 'd' * 64, 'captures': [capture]}
    report = {'version': 1, 'codecRevision': manifest['codecRevision'],
              'selectedSourceDigest': manifest['sourceDigest'], 'captures': [row]}
    auth = {'captures': [{'requestIdSha256': row['requestIdSha256'],
                         'sourceCheckedAuthentication': 'observed_native_checked_envelope_and_body',
                         'compactCustody': 'retained_bytes_match_native_checked_header',
                         'checkedContexts': {'incomplete': False}}]}
    compact = {'sha256': routes.sha(b'synthetic-private-compact'), 'byteSize': '25'}
    sidecar = {'nativeExecutableSha256': 'f' * 64, 'ingressCompacts': {IDENTIFIER: compact}}
    policy = {'windowId': WINDOW, 'startUnixMillis': '1000', 'endUnixMillis': '3000'}
    capture_policy = {'corpusId': 'a' * 32, 'windowId': WINDOW, 'sourceCommit': manifest['codecRevision'],
                      'sourceTree': 'c' * 40, 'runtimeSourceDigest': manifest['sourceDigest'],
                      'nativeExecutableSha256': sidecar['nativeExecutableSha256'],
                      'workerSourceDigest': manifest['sourceDigest'], 'captureImplementationSha256': 'e' * 64,
                      'startsAt': 1, 'expiresAt': 3, 'originRoutes': [
                          {'method': method, 'path': path, 'purpose': 'synthetic-source-selected-purpose'}]}
    receipts = []
    for direction, image in (('received_request', images['request']), ('exposed_response', images['response'])):
        private = [{'name': 'body', 'sha256': image['sha256'], 'bytes': image['byteSize']}]
        if direction == 'received_request':
            private.append({'name': 'x-aos-hybrid-ingress', 'sha256': compact['sha256'],
                            'bytes': compact['byteSize']})
        receipts.append({name: capture_policy[name] for name in (
            'corpusId', 'windowId', 'sourceCommit', 'sourceTree', 'runtimeSourceDigest',
            'nativeExecutableSha256', 'workerSourceDigest', 'captureImplementationSha256')})
        receipts[-1].update(role='origin_proxy', requestId=IDENTIFIER, transportCallId=None,
            method=method, pathSha256=member['pathSha256'], queryClass='absent',
            purpose='synthetic-source-selected-purpose', direction=direction,
            captureId='f' * 32, state='eof', eof=True, frameState='bounded',
            capturePersistence='written', qualificationClaim=False, instrumentationTraffic=True,
            responseConsumptionClaim=False, observedBytes=image['byteSize'], retainedBytes=image['byteSize'],
            privateImages=private, startedAtMillis='1500', finishedAtMillis='2000',
            status=None if direction == 'received_request' else 200,
            imageKind='complete_received_image' if direction == 'received_request' else 'complete_wrapper_reply_image',
            provenance='independent_wrapper_received_bytes' if direction == 'received_request' else 'wrapper_exposed_reply_bytes')
    return {'member': member, 'report': report, 'manifest': manifest, 'authentication': auth,
            'sidecar': sidecar, 'policy': policy,
            'receiver_context': {'policy': capture_policy, 'receipts': receipts},
            'provenance': {'browserSource': copy.deepcopy(browser)}}


def project(value):
    arguments = {name: value[name] for name in ('report', 'manifest', 'authentication', 'sidecar',
                                             'policy', 'receiver_context', 'provenance')}
    context = routes.prepare(**arguments, source=SOURCE, read_source=read_source)
    return routes.project(value['member'], context)


class RouteProof(unittest.TestCase):
    def test_identity_keeps_positive_control_counts_and_unknown_authority(self):
        value = fixture()
        result = project(value)
        self.assertEqual(result['class'], 'matched_bounded_identity_control')
        self.assertEqual(result['requestControlBytes'], '2')
        self.assertEqual(result['replyControlBytes'], value['member']['replyOffered']['exposedBytes'])
        self.assertGreater(int(result['replyControlBytes']), 0)
        for key in ('objectPayloadBytes', 'nativeBulkBytes', 'currentSqlAuthority'):
            self.assertIsNone(result[key])
        self.assertFalse(result['independentMacVerification'])

    def test_instance_keeps_intentional_query_output_and_exact_source(self):
        value = fixture(shell=True)
        result = project(value)
        self.assertEqual(result['class'], 'matched_bounded_instance_shell')
        self.assertGreater(int(result['replyQueryOutputBytes']), 0)
        self.assertIsNone(result['replyControlBytes'])
        value['report']['captures'][0]['browserSource']['templateSha256'] = '1' * 64
        with self.assertRaises(ValueError):
            project(value)

    def test_missing_old_query_and_observed_query_never_project(self):
        for query in (None, 'present'):
            value = fixture()
            value['member'].pop('queryClass')
            if query:
                value['member']['queryClass'] = query
            self.assertIsNone(project(value))
        value = fixture()
        value['receiver_context']['receipts'][0]['queryClass'] = 'unsupported'
        with self.assertRaises(ValueError):
            project(value)

    def test_missing_auth_compact_codec_receiver_and_eof_stay_unavailable(self):
        mutations = [lambda v: v.update(report=None), lambda v: v.update(receiver_context=None),
                     lambda v: v['authentication'].update(captures=[]),
                     lambda v: v['sidecar']['ingressCompacts'].clear(),
                     lambda v: v['receiver_context']['receipts'].pop(),
                     lambda v: v['member']['requestConsumed'].update(eof=False),
                     lambda v: v['receiver_context']['receipts'][1].update(eof=False)]
        for mutation in mutations:
            value = fixture()
            mutation(value)
            self.assertIsNone(project(value))

    def test_duplicate_or_substituted_call_body_compact_status_and_source_refuse(self):
        mutations = [lambda v: v['report']['captures'].append(copy.deepcopy(v['report']['captures'][0])),
                     lambda v: v['manifest']['captures'].append(copy.deepcopy(v['manifest']['captures'][0])),
                     lambda v: v['receiver_context']['receipts'].append(copy.deepcopy(v['receiver_context']['receipts'][0])),
                     lambda v: v['receiver_context']['receipts'][1].update(captureId='0' * 32),
                     lambda v: v['receiver_context']['receipts'][0]['privateImages'][0].update(sha256='0' * 64),
                     lambda v: v['receiver_context']['receipts'][0]['privateImages'][1].update(sha256='0' * 64),
                     lambda v: v['manifest']['captures'][0].update(status=201),
                     lambda v: v['member']['typedEvidence'].update(constructorSourceSha256='0' * 64)]
        for mutation in mutations:
            value = fixture()
            mutation(value)
            with self.assertRaises(ValueError):
                project(value)

    def test_wrong_runtime_original_window_purpose_and_actual_timestamps_refuse(self):
        mutations = [lambda v: v['receiver_context']['policy'].update(windowId='0' * 32),
                     lambda v: v['receiver_context']['policy'].update(workerSourceDigest='0' * 64),
                     lambda v: v['receiver_context']['policy'].update(expiresAt=4),
                     lambda v: v['receiver_context']['receipts'][0].update(purpose='another-purpose'),
                     lambda v: v['receiver_context']['receipts'][1].update(finishedAtMillis='3000')]
        for mutation in mutations:
            value = fixture()
            mutation(value)
            with self.assertRaises(ValueError):
                project(value)

    def test_unselected_or_unknown_route_does_not_classify_by_size(self):
        value = fixture()
        value['report']['captures'][0]['procedure'] = '/unselected'
        self.assertIsNone(project(value))
        value = fixture()
        value['member']['requestId'] = '0' * 32
        self.assertIsNone(project(value))

    def test_reader_accepts_optional_query_but_old_member_never_implies_absence(self):
        # Reuse the exact existing synthetic chain constructor, not a new writer.
        import native_inventory_tests as fixtures
        producer = inventory.producer(SOURCE, read_source)
        member = fixtures.synthetic_member(1, producer)
        for query in (None, 'absent', 'present'):
            if query is None:
                member.pop('queryClass', None)
            else:
                member['queryClass'] = query
            result = inventory.validate(fixtures.synthetic_messages([member], producer),
                                        fixtures.POLICY, producer, fixtures.parse)
            self.assertTrue(result['inventoryComplete'])
            self.assertEqual(result['members'][0].get('queryClass'), query)
        member['queryClass'] = 'unknown'
        with self.assertRaises(ValueError):
            inventory.validate(fixtures.synthetic_messages([member], producer),
                               fixtures.POLICY, producer, fixtures.parse)

    def test_actual_projection_loop_refuses_reused_member_request_id(self):
        value = fixture()
        result = {'members': [value['member'], copy.deepcopy(value['member'])]}
        with self.assertRaisesRegex(ValueError, 'request ownership is ambiguous'):
            inventory.project_members(result, {}, {}, value['policy'], SOURCE, {}, read_source,
                                      value['manifest'], value['report'], value['authentication'],
                                      lambda member: None)

    def test_actual_parent_handoff_passes_only_supplied_actual_local_arguments(self):
        path = Path(__file__).parent / 'hosted_assessment.py'
        function = next(node for node in ast.parse(path.read_bytes()).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'inbound_inventory')
        child = b"def assess(*args):\n    return args\n"
        globals_ = {'Path': Path, '__file__': str(path), 'MAX_JSON': 1024 * 1024,
                    'SOURCE': SOURCE, 'READERS': {},
                    'PACKAGE_READER': {'installed_bytes': lambda *_: child}}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), 'exec'), globals_)
        selected, manifest, report, receiver_context = {'nativeInventory': {'selected': True}}, {}, {}, {}
        result = globals_['inbound_inventory'](selected, manifest, report, receiver_context)
        self.assertIs(result[-2], report)
        self.assertIs(result[-1], receiver_context)
        result = globals_['inbound_inventory'](selected, manifest, None, None)
        self.assertIsNone(result[-2])
        self.assertIsNone(result[-1])

    def assessment_seam(self, codec_error=None, export_error=False):
        # Execute only the actual assessment function with synthetic reader
        # locals. This proves its call handoff, not installed authentication.
        path = Path(__file__).parent / 'hosted_assessment.py'
        function = next(node for node in ast.parse(path.read_bytes()).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'assess')
        runtime = {'runtimeCodecRevision': 'c' * 40, 'workerSourceDigest': 'd' * 64,
                   'sourceArchiveSha256': 'e' * 64, 'nativeExecutableSha256': 'f' * 64}
        provenance = {'version': 1, **runtime, 'browserSource': None}
        calls, exported = [], []
        manifest, report, policy = {'original': True}, {'captures': []}, {'actualParsedPolicy': True}
        receipt = {'captureId': 'a' * 32, 'direction': 'received_request', 'role': 'origin_proxy'}
        selection = {'version': 1, 'runtime': runtime, 'runtimeProvenance': 'runtime',
                     'bodyManifest': 'manifest', 'observerExecutable': 'observer', 'authSidecar': None,
                     'capturePolicy': 'policy', 'captureExport': 'export', 'workloadWindows': [],
                     'sdkApplicationLog': None, 'clientApplicationLog': None,
                     'indexSnapshots': None, 'wireMetrics': None}

        def exported_receipt(item, actual_policy):
            exported.append((item, actual_policy))
            if export_error:
                raise ValueError('Synthetic failed export validation')
            return receipt, 1

        def inbound_inventory(*args):
            calls.append(args)
            return None

        def parsed(reference, *args):
            return provenance if reference == 'runtime' else {
                'version': 1, 'runtime': runtime, 'windows': [], 'receipts': [{'rawExport': True}]}

        globals_ = {'RUNTIME': runtime, 'PACKAGE': {'observerExecutable': 'observer'},
                    'closed': lambda *_: None, 'parsed': parsed, 'read': lambda *_: b'',
                    'capture_policy': lambda *_: policy, 'exported_receipt': exported_receipt,
                    'observe': lambda *_: (manifest, report, codec_error),
                    'unique': lambda rows, key: {key(row): row for row in rows},
                    'index_parity': lambda *_: None, 'inbound_inventory': inbound_inventory,
                    'CLIENT_FIELDS': set(), 'SDK_FIELDS': set(), 'MAX_JSON': 1024 * 1024,
                    'MAX_CORPUS': 512 * 1024 * 1024}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), 'exec'), globals_)
        return globals_['assess'], selection, calls, exported, report, policy, receipt

    def test_actual_assessment_passes_validated_origin_locals_and_successful_report(self):
        assess, selection, calls, exported, report, policy, receipt = self.assessment_seam()
        assess(selection)
        self.assertEqual(len(exported), 1)
        self.assertIs(calls[0][-2], report)
        self.assertIs(calls[0][-1]['policy'], policy)
        self.assertIs(calls[0][-1]['receipts'][0], receipt)

    def test_actual_assessment_codec_failure_has_no_receiver_or_report_handoff(self):
        assess, selection, calls, exported, *_ = self.assessment_seam(codec_error={'reason': 'synthetic'})
        assess(selection)
        self.assertEqual(exported, [])
        self.assertEqual(calls[0][-2:], (None, None))

    def test_actual_assessment_export_failure_cannot_manufacture_receiver_handoff(self):
        assess, selection, calls, *_ = self.assessment_seam(export_error=True)
        with self.assertRaises(ValueError):
            assess(selection)
        self.assertEqual(calls, [])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=SOURCE)
    options, remaining = parser.parse_known_args()
    SOURCE = options.source
    unittest.main(argv=[__file__, *remaining])
