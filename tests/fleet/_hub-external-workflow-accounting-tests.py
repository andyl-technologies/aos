"""Exercise actual file custody and source-owned External accounting joins.

These local fixtures use the published event, decoder and provider schemas.
They do not execute a business upload, authenticate an artifact or qualify a
provider. Accepted checks and measured bytes remain separate report dimensions.
"""

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).parent


def load(name):
    specification = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    result = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(result)
    return result


class ExternalAccountingTests(unittest.TestCase):
    def setUp(self):
        self.module = load('_hub-external-workflow-accounting')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.source = 'a' * 64
        self.codec = 'b' * 64

    def reference(self, name, raw):
        path = self.directory / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return {'file': str(path), 'sha256': self.module.sha256(raw), 'byteSize': len(raw)}

    def control(self, identifier='1' * 32):
        request, reply = b'{"actual":"metadata"}', b'{"retained":"metadata"}'
        bodies = {'request': self.reference(identifier + '-request', request),
                  'response': self.reference(identifier + '-reply', reply)}
        original = {'requestId': identifier, 'bodies': bodies}
        row = {'requestId': identifier, 'sourceDigest': self.source,
            'codecSourceSha256': self.codec, 'requestSha256': bodies['request']['sha256'],
            'replySha256': bodies['response']['sha256'], 'exchangeIdSha256': 'c' * 64,
            'originalContextSha256': bodies['request']['sha256'],
            'operation': 'external_oci_control', 'class': 'external_oci_control_metadata',
            'payload': {field: '0' for field in self.module.PAYLOAD_FIELDS}}
        call = {'nativeRequestId': identifier, 'transportCallIdSha256': 'd' * 64,
            'requestSha256': row['requestSha256'], 'replySha256': row['replySha256'],
            'offeredRequestBytes': len(request), 'consumedReplyBytes': len(reply)}
        return original, row, {'kind': 'authenticated_control', 'value': call}

    def workflow(self):
        original, row, observation = self.control()
        identity = original['requestId']
        empty = {'bodies': []}
        window = {'storageBoundary': {'nativeOriginalBodies': {'bodies': [original]}},
            'nativeOutboundDecoded': {'complete': True, 'observations': [row]},
            'nativeIngressBoundary': {'workerOriginalBodies': empty, 'decoded': None},
            'nativeAuthenticatedTransports': {'joined': [observation['value']]},
            'nativeExecuteObservations': {'joined': []},
            'nativeFinalContextObservations': {'joined': []}}
        return {'coverage': {'complete': True, 'assigned': {
            'nativeOutbound': {identity: {}}, 'workerOriginal': {}},
            'inventorySha256': 'e' * 64}, 'epochs': [{'processRole': 'controlled_external_oci_native',
            'window': window}], 'failureClass': None}

    def test_complete_canonical_metadata_and_actual_consumption_are_separate_from_authority(self):
        original, row, observation = self.control()
        result = self.module.external_body_partition(row, original, observation, lambda *_: [])

        self.assertEqual(result['nativeObjectBytes'], 0)
        self.assertEqual(result['nativeApplicationObservation']['consumedReplyBytes'],
                         original['bodies']['response']['byteSize'])
        self.assertEqual(result['checkedOutcome'], 'existing_control_mac_and_correlation_accepted')
        self.assertNotIn('currentPermission', result)

    def test_missing_consumption_keeps_canonical_metadata_bound_without_inventing_zero(self):
        original, row, _ = self.control()
        result = self.module.external_body_partition(row, original, None, lambda *_: [])

        self.assertEqual(result['canonicalPayload']['replyRawObjectBytes'], 0)
        self.assertIsNone(result['nativeApplicationObservation'])
        self.assertIsNone(result['nativeObjectBytes'])

    def test_received_body_substitution_refuses(self):
        original, row, observation = self.control()
        original['bodies']['response']['sha256'] = 'f' * 64

        with self.assertRaises(ValueError):
            self.module.external_body_partition(row, original, observation, lambda *_: [])

    def test_single_authentication_cannot_cover_two_identical_calls(self):
        workflow = self.workflow()
        duplicate = copy.deepcopy(workflow['epochs'][0])
        workflow['epochs'].append(duplicate)

        with self.assertRaises(ValueError):
            self.module.collect_external_body_rows(workflow, self.source, self.codec)

    def test_actual_decoder_source_substitution_refuses(self):
        workflow = self.workflow()
        workflow['epochs'][0]['window']['nativeOutboundDecoded']['observations'][0]['sourceDigest'] = '0' * 64

        with self.assertRaises(ValueError):
            self.module.collect_external_body_rows(workflow, self.source, self.codec)

    def test_original_membership_cannot_be_extended_by_a_decoder(self):
        workflow = self.workflow()
        workflow['coverage']['assigned']['nativeOutbound'].clear()

        with self.assertRaises(ValueError):
            self.module.collect_external_body_rows(workflow, self.source, self.codec)

    def test_failed_unassigned_attempt_is_not_removed_from_the_global_gate(self):
        workflow = self.workflow()
        workflow['epochs'][0]['window']['nativeExecuteObservations']['unassignedAttemptCallIds'] = ['9' * 32]

        with self.assertRaises(ValueError):
            self.module.collect_external_body_rows(workflow, self.source, self.codec)

    def test_partial_content_does_not_borrow_full_decoded_payload(self):
        original, row, _ = self.control()
        row['payload']['replyRawObjectBytes'] = '100'
        attempt = {'offeredRequestSha256': row['requestSha256'],
            'offeredRequestBytes': str(original['bodies']['request']['byteSize']),
            'replyEof': False, 'outcome': 'response_read_failed'}
        observation = {'kind': 'typed_execute_attempt', 'value': {
            'attempt': attempt, 'payload': row['payload'],
            'fullReplyConsumed': False, 'nativeExposedReplyBytes': '3'}}

        result = self.module.external_body_partition(row, original, observation, lambda *_: [])

        self.assertEqual(result['nativeApplicationObservation']['consumedReplyBytes'], 3)
        self.assertIsNone(result['nativeObjectBytes'])
        self.assertIn('partial_content_reply_has_no_field_offset_mapping', result['unresolved'])

    def test_expected_refusal_preserves_actual_prefix_without_claiming_acceptance(self):
        original, row, _ = self.control()
        attempt = {'offeredRequestSha256': row['requestSha256'],
            'offeredRequestBytes': str(original['bodies']['request']['byteSize']),
            'replyEof': False, 'outcome': 'http_rejected'}
        observation = {'kind': 'typed_execute_attempt', 'value': {
            'attempt': attempt, 'payload': row['payload'],
            'fullReplyConsumed': False, 'nativeExposedReplyBytes': '3'}}

        result = self.module.external_body_partition(row, original, observation, lambda *_: [])

        self.assertEqual(result['nativeObjectBytes'], 0)
        self.assertEqual(result['checkedOutcome'], 'http_rejected')
        self.assertIsNone(result['nativeApplicationObservation']['replyMacAuthentication'])

    def test_actual_private_body_replacement_and_public_mode_refuse(self):
        reference = self.reference('custody', b'bounded metadata')
        self.assertEqual(self.module.retained_host_bytes(reference, 4096), b'bounded metadata')
        Path(reference['file']).write_bytes(b'changed metadata')
        with self.assertRaises(ValueError):
            self.module.retained_host_bytes(reference, 4096)
        Path(reference['file']).write_bytes(b'bounded metadata')
        Path(reference['file']).chmod(0o644)
        with self.assertRaises(ValueError):
            self.module.retained_host_bytes(reference, 4096)

    def test_both_actual_guest_reference_forms_are_closed(self):
        raw = b'canonical metadata'
        reference = self.reference('guest', raw)
        read = lambda machine, path, maximum: Path(path).read_bytes()
        source = {'path': reference['file'], 'sha256': reference['sha256'], 'bytes': len(raw)}
        self.assertEqual(self.module.retained_guest_bytes(None, reference, 4096, read), raw)
        self.assertEqual(self.module.retained_guest_bytes(None, source, 4096, read), raw)
        source['success'] = True
        with self.assertRaises(ValueError):
            self.module.retained_guest_bytes(None, source, 4096, read)

    def provider(self, *, caller='10.0.0.2', count='13'):
        callers = {'client': '10.0.0.1', 'worker': '10.0.0.2', 'native': '10.0.0.3', 'provider': '127.0.0.1'}
        value = {'method': 'GET', 'caller': caller, 'path': '/fleet-s3/exact-key',
            'status': '200', 'request_http_bytes': '200', 'request_body_bytes': '0',
            'transfer_encoding': '', 'response_http_bytes': '200', 'response_body_bytes': count,
            'etag': 'exact-incarnation', 'content_md5': '', 'elapsed_seconds': '0.01', 'operation': 'object'}
        raw = json.dumps(value).encode() + b'\n'
        reference = self.reference('provider', raw)
        position = {'path': reference['file'], 'device': 1, 'inode': 2, 'byteSize': 0}
        parser = load('_hub-direct-boundary')
        runtime = load('_hub-direct-runtime-observations')
        parser._direct_runtime_integer = runtime._direct_runtime_integer
        parser._direct_runtime_closed_json = runtime._direct_runtime_closed_json
        projected = parser.provider_boundary_observations(raw.decode(), callers)
        return {'callers': callers, 'rawWindowReceipt': {**reference, 'capturedBytes': len(raw),
                    'before': position, 'after': {**position, 'byteSize': len(raw)}},
                'observations': projected}

    def test_provider_whole_window_counts_without_per_call_attribution(self):
        result = self.module.provider_window_partition(self.provider())

        self.assertEqual(result['recordCount'], 1)
        self.assertEqual(result['applicationBodies']['worker']['responseBodyBytes'], 13)
        self.assertEqual(result['nativeProviderCalls'], 0)
        self.assertIsNone(result['perCallAttribution'])

    def test_provider_projection_substitution_refuses(self):
        provider = self.provider()
        provider['observations']['receipts'][0]['response_body_bytes'] = 0
        with self.assertRaises(ValueError):
            self.module.provider_window_partition(provider)

    def test_provider_truncated_final_row_refuses(self):
        provider = self.provider()
        path = Path(provider['rawWindowReceipt']['file'])
        raw = path.read_bytes()[:-1]
        path.write_bytes(raw)
        provider['rawWindowReceipt'].update(sha256=self.module.sha256(raw), capturedBytes=len(raw))
        provider['rawWindowReceipt']['after']['byteSize'] = len(raw)

        with self.assertRaises(ValueError):
            self.module.provider_window_partition(provider)

    def test_provider_original_inode_and_prefix_must_remain_contiguous(self):
        provider = self.provider()
        provider['rawWindowReceipt']['after']['inode'] += 1

        with self.assertRaises(ValueError):
            self.module.provider_window_partition(provider)

        provider['rawWindowReceipt']['after']['inode'] -= 1
        provider['rawWindowReceipt']['after']['byteSize'] += 1
        with self.assertRaises(ValueError):
            self.module.provider_window_partition(provider)

    def test_provider_native_count_cannot_be_relabelled(self):
        provider = self.provider(caller='10.0.0.3')
        provider['observations']['nativeProviderCalls'] = 0
        with self.assertRaises(ValueError):
            self.module.provider_window_partition(provider)

    def test_actual_controller_stops_before_oversized_partition_append(self):
        self.module.PARTITION_TOTAL_MAXIMUM = 8
        tools = {'workerSourcePath': '/selected-worker', 'storageCodecSourceSha256': self.codec}
        workflow = self.workflow()
        self.module.collect_external_body_rows = lambda *_: (
            {('nativeOutbound', '1' * 32)},
            {('nativeOutbound', '1' * 32): workflow['epochs'][0]['window']['nativeOutboundDecoded']['observations'][0]},
            {('nativeOutbound', '1' * 32): workflow['epochs'][0]['window']['storageBoundary']['nativeOriginalBodies']['bodies'][0]},
            {}, {})

        result = self.module.consume_external_workflow_evidence(None, None, tools, {}, {},
            workflow, None, lambda *_: None, read_private=lambda *_: b'')

        self.assertFalse(result['complete'])
        self.assertEqual(result['bodyPartitions'], [])
        self.assertIsNone(result['nativeBulkBytes'])
        self.assertEqual(result['originalCount'], 1)

    def writer(self):
        return {'placement_id': '1', 'binding_id': '2', 'placement_resource_version': '3',
            'write_spec_version': '4', 'binding_resource_version': '5',
            'authority_id': '6', 'authority_resource_version': '7', 'authority_generation': '8',
            'binding_write_revision': '9', 'placement_prefix': 'registry/objects',
            'binding_prefix': 'selected', 'binding_stable_id': 'actual-binding',
            'authority_incarnation': 'actual-authority'}

    def writer_rows(self):
        return {'placement': {'id': 1, 'binding_id': 2, 'resource_version': 3,
                'write_spec_version': 4, 'prefix': 'registry/objects'},
            'binding': {'id': 2, 'resource_version': 5, 'object_prefix': 'selected',
                'stable_id': 'actual-binding'},
            'authority': {'id': 6, 'resource_version': 7, 'observed_generation': 8,
                'observed_binding_write_revision': 9, 'incarnation_id': 'actual-authority',
                'observed_placement_id': 1}, 'upload': None}

    def test_current_writer_rows_associate_without_recreating_past_permission(self):
        result = self.module.join_current_external_writer(self.writer(), None, self.writer_rows())

        self.assertEqual(result['writerOriginalSha256'], self.module.sha256(self.module.canonical(self.writer())))
        self.assertNotIn('iamAccepted', result)
        self.assertIn('not past IAM', result['scope'])

    def test_current_writer_generation_change_remains_an_association_failure(self):
        rows = self.writer_rows()
        rows['binding']['resource_version'] += 1

        with self.assertRaises(ValueError):
            self.module.join_current_external_writer(self.writer(), None, rows)

    def test_actual_sql_query_and_raw_result_must_match_the_live_selected_process(self):
        writer = self.writer()
        request = {'writer': writer, 'upload_id': None}
        process = {'pid': 123, 'startTicks': '456', 'executableSha256': 'a' * 64}
        raw = json.dumps(self.writer_rows()).encode()
        reference = self.reference('sql-rows', raw)
        query = self.module.external_writer_query(writer)
        receipt = {**reference, 'querySha256': self.module.sha256(query.encode()),
            'before': dict(process), 'after': dict(process),
            'databaseUrlSha256': 'b' * 64, 'psqlExecutableSha256': 'c' * 64}
        callback = lambda query, label: {'value': self.writer_rows(), 'receipt': receipt}
        read = lambda machine, path, maximum: Path(path).read_bytes()

        result = self.module.capture_external_current_sql(None, {'native': process}, request,
            callback, read, 'actual-current-observation')

        self.assertEqual(result['receipt']['sha256'], reference['sha256'])
        receipt['after']['startTicks'] = 'replacement'
        with self.assertRaises(ValueError):
            self.module.capture_external_current_sql(None, {'native': process}, request,
                callback, read, 'actual-current-observation')

    def test_private_source_upload_cannot_borrow_another_current_upload(self):
        request = {'writer': self.writer(), 'upload_id': '1' * 32}
        process = {'pid': 123, 'startTicks': '456', 'executableSha256': 'a' * 64}
        rows = self.writer_rows()
        rows['upload'] = {'id': '2' * 32}
        raw = json.dumps(rows).encode()
        reference = self.reference('private-source-sql', raw)
        query = self.module.external_writer_query(request['writer'], request['upload_id'])
        receipt = {**reference, 'querySha256': self.module.sha256(query.encode()),
            'before': dict(process), 'after': dict(process),
            'databaseUrlSha256': 'b' * 64, 'psqlExecutableSha256': 'c' * 64}

        with self.assertRaises(ValueError):
            self.module.capture_external_current_sql(None, {'native': process}, request,
                lambda *_: {'value': rows, 'receipt': receipt},
                lambda machine, path, maximum: Path(path).read_bytes(), 'actual-private-source')

    def purpose_inputs(self):
        source_path = '/selected-source-built-worker'
        source_digest = self.module.sha256(source_path.encode())
        process = {'pid': 321, 'startTicks': '654', 'executableSha256': '7' * 64}
        native_artifact = self.reference('native-artifact', b'fixture artifact bytes')
        worker_artifact = self.reference('worker-artifact', b'fixture artifact bytes')
        reviewers = self.reference('reviewers', b'fixture reviewer bytes')
        guard = self.reference('guard', b'fixture guard bytes')
        review = self.reference('review', b'fixture independent review bytes')
        audience = {'deploymentId': 'fixture-external', 'publicOrigin': 'https://localhost:4673',
            'sourceDigest': source_digest, 'scriptVersion': 'actual-script-v1'}
        candidate = {'deployment_id': audience['deploymentId'], 'source_digest': source_digest,
            'script_version': audience['scriptVersion'], 'placement_prefix': 'fixture/reserved',
            'expires_at': 1234, 'profile_digest': '8' * 64}
        candidate_file = self.reference('candidate', json.dumps(candidate).encode())
        candidate_reference = {'path': candidate_file['file'], 'sha256': candidate_file['sha256'],
            'bytes': candidate_file['byteSize']}
        ready_path = str(self.directory / 'ready')
        input_value = {'expectedExecutableSha256': process['executableSha256'],
            'deploymentId': audience['deploymentId'], 'publicOrigin': audience['publicOrigin'],
            'workerSourceDigest': source_digest, 'workerScriptVersion': audience['scriptVersion'],
            'placementPrefix': candidate['placement_prefix'], 'readinessFile': ready_path,
            'files': {'candidateFile': candidate_file['file'], 'direct': {
                'acceptanceFile': native_artifact['file'], 'reviewKeysFile': reviewers['file'],
                'guardKeyFile': guard['file']}}}
        input_file = self.reference('helper-input', json.dumps(input_value).encode())
        readiness = {'identity': {**process, 'inputSha256': input_file['sha256'],
            'selectedWorkerSourceDigest': source_digest,
            'selectedWorkerScriptVersion': audience['scriptVersion'],
            'candidateSha256': candidate_file['sha256'], 'expiresAt': candidate['expires_at']}}
        Path(ready_path).write_bytes(json.dumps(readiness).encode())
        Path(ready_path).chmod(0o600)
        business = {'helper': {'process': process, 'input': input_file, 'readiness': readiness},
            'candidate': {'candidateReference': candidate_reference}, 'direct': {
                'directReferences': {'version': 1, 'audience': audience,
                    'nativeArtifact': native_artifact, 'workerArtifact': worker_artifact,
                    'nativeReviewKeys': reviewers, 'nativeGuardKey': guard,
                    'nativeIndependentReview': review, 'artifactSha256': native_artifact['sha256'],
                    'reviewSha256': review['sha256']},
                'workerAcceptance': {'artifactSha256': worker_artifact['sha256']}}}
        return {'deploymentId': audience['deploymentId'], 'workerSourcePath': source_path}, business

    def test_constructor_association_keeps_controlled_and_direct_purposes_distinct(self):
        tools, business = self.purpose_inputs()
        read = lambda machine, path, maximum: Path(path).read_bytes()

        result = self.module.external_helper_purpose(None, None, tools, business, read)

        self.assertEqual(result['directArtifactSha256'], business['direct']['workerAcceptance']['artifactSha256'])
        self.assertEqual(result['candidateSha256'], business['candidate']['candidateReference']['sha256'])
        self.assertIn('test-only OCI', result['scope'])
        self.assertNotIn('permission', result)

    def test_constructor_readiness_cannot_be_borrowed_from_another_process(self):
        tools, business = self.purpose_inputs()
        business['helper']['process']['startTicks'] = 'different-lifetime'
        read = lambda machine, path, maximum: Path(path).read_bytes()

        with self.assertRaises(ValueError):
            self.module.external_helper_purpose(None, None, tools, business, read)

    def copy_inputs(self):
        process = {'pid': 321, 'startTicks': '654', 'executableSha256': '7' * 64}
        objects = [{'path': 'objects/exact', 'sha256': 'a' * 64, 'byteSize': 17}]
        rows = {'registry': {'id': 7, 'slug': 'actual/catalogue', 'stable_id': 'stable'},
            'indexed': {'registry_id': 7, 'state': 'fresh', 'last_indexed_commit': 'b' * 64},
            'objects': [{'id': 9, 'path': 'objects/exact', 'digest': 'sha256:' + 'a' * 64,
                'size': 17, 'resource_version': 3}]}
        raw = json.dumps(rows).encode()
        reference = self.reference('copy-catalogue', raw)
        catalogue = {'version': 1, 'registrySlug': 'actual/catalogue', 'registryStableId': 'stable',
            'sourceCommit': 'b' * 64, 'objects': objects, 'sql': rows,
            'receipt': {**reference, 'before': dict(process), 'after': dict(process),
                'databaseUrlSha256': 'c' * 64, 'querySha256': 'd' * 64,
                'psqlExecutableSha256': 'e' * 64}}
        workflows = {}
        for kind in ('replicate', 'repair'):
            operation_id = kind + '-actual-operation'
            facts = {'phase': 'complete', 'catalogObjects': 1, 'missingObjects': 0,
                'corruptObjects': 0, 'copy': {'source': 'source', 'destination': kind,
                    'copiedObjects': 1, 'copiedBytes': 17}}
            def presence(copied):
                return [{'presences': [
                    {'placementName': 'source', 'objectRef': 'objects/exact', 'state': 'present',
                        'contentDigest': 'a' * 64, 'size': '17'},
                    {'placementName': kind, 'objectRef': 'objects/exact',
                        'state': 'present' if copied else 'missing',
                        'contentDigest': 'a' * 64, 'size': '17'}]}]
            workflows[kind] = {'plan': {'planId': kind, 'confirmationHash': 'actual-confirmation'},
                'apply': {'planId': kind, 'confirmationHash': 'actual-confirmation'},
                'original': {'operationId': operation_id}, 'replayedOriginal': {'operationId': operation_id},
                'completed': {'operation': {'kind': kind + '_placement', 'state': 'succeeded',
                    'operationId': operation_id}, 'detailJson': json.dumps(facts)},
                'controllerFacts': facts, 'missingScan': {'detailJson': json.dumps({
                    'catalogObjects': 1, 'missingObjects': 1})},
                'presenceBefore': presence(False), 'presenceAfter': presence(True),
                'catalogueAfter': catalogue}
        business = {'copy': {'catalogueBefore': catalogue, 'workflows': workflows},
            'publication': {'signedSource': {'sourceCommit': 'b' * 64}},
            'reindex': {'sourceCommit': 'b' * 64}}
        return process, business

    def test_copy_actual_catalogue_inventory_and_original_replay_associate(self):
        process, business = self.copy_inputs()
        read = lambda machine, path, maximum: Path(path).read_bytes()
        association = self.module.external_copy_association(None, process, business, read)
        request = {'original': {'topology': {'operation_id': 'replicate-actual-operation',
            'operation_kind': 'replicate_placement'}, 'path': 'objects/exact',
            'source': {'registry_id': '7', 'cache_id': None},
            'destination': {'registry_id': '7', 'cache_id': None},
            'source_object': {'bytes': '17'}, 'expected_sha256': 'a' * 64}}

        result = self.module.join_copy_original(request, association)

        self.assertEqual(result['catalogueObjectBytes'], 17)
        self.assertIn('not past claim', result['scope'])
        request['original']['source_object']['bytes'] = '18'
        with self.assertRaises(ValueError):
            self.module.join_copy_original(request, association)

    def test_copy_replay_new_operation_cannot_borrow_completed_inventory(self):
        process, business = self.copy_inputs()
        business['copy']['workflows']['repair']['replayedOriginal']['operationId'] = 'another-operation'
        read = lambda machine, path, maximum: Path(path).read_bytes()

        with self.assertRaises(ValueError):
            self.module.external_copy_association(None, process, business, read)

    def test_copy_catalogue_raw_substitution_refuses(self):
        process, business = self.copy_inputs()
        Path(business['copy']['catalogueBefore']['receipt']['file']).write_bytes(b'{}')
        read = lambda machine, path, maximum: Path(path).read_bytes()

        with self.assertRaises(ValueError):
            self.module.external_copy_association(None, process, business, read)

    def test_known_metadata_upper_bound_does_not_invent_consumption_or_global_zero(self):
        workflow = self.workflow()
        workflow['epochs'][0]['window']['nativeAuthenticatedTransports']['joined'] = []
        source = '/selected-worker'
        row = workflow['epochs'][0]['window']['nativeOutboundDecoded']['observations'][0]
        row['sourceDigest'] = self.module.sha256(source.encode())

        result = self.module.consume_external_workflow_evidence(None, None,
            {'workerSourcePath': source, 'storageCodecSourceSha256': self.codec}, {}, {},
            workflow, None, lambda *_: None, read_private=lambda *_: b'')

        self.assertTrue(result['complete'])
        self.assertEqual(result['capturedObjectByteUpperBound'], 0)
        self.assertFalse(result['nativeConsumptionComplete'])
        self.assertIsNone(result['nativeControlBoundaryObjectBytes'])
        self.assertIsNone(result['nativeBulkBytes'])


if __name__ == '__main__':
    unittest.main()
