"""Bounded synthetic chain refusals and an optional actual producer fixture."""

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import unittest

import native_inventory as inventory


SOURCE = Path(__file__).resolve().parents[3]
POLICY = {'version': 1, 'windowId': 'a' * 32, 'startUnixMillis': '1', 'endUnixMillis': '2'}


def source_bytes(path, maximum):
    raw = Path(path).read_bytes()
    if len(raw) > maximum:
        raise ValueError('Synthetic source exceeds bound')
    return raw


def parse(raw):
    def fields(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=fields)


def synthetic_frame(raw=b''):
    return {'exposedBytes': str(len(raw)), 'exposedSha256': inventory.sha(raw),
            'eof': True, 'failed': False, 'overflow': False}


def synthetic_member(ordinal, producer):
    return {'version': 1, 'event': 'member', 'windowId': POLICY['windowId'],
            'policySha256': inventory.sha(inventory.policy_bytes(POLICY)),
            'producerSha256': producer, 'admissionOrdinal': str(ordinal),
            'completionOrdinal': '1', 'previousChainSha256': '0' * 64,
            'method': 'POST', 'pathSha256': inventory.sha(b'/synthetic-unknown'),
            'requestId': None, 'transportCallId': None, 'status': 200,
            'handlerReturned': True, 'requestConsumed': synthetic_frame(),
            'replyOffered': synthetic_frame(b'unclassified'), 'requestTrailers': False,
            'replyTrailers': False, 'typedEvidence': None}


def synthetic_messages(members, producer, incomplete=0):
    base = {'version': 1, 'windowId': POLICY['windowId'],
            'policySha256': inventory.sha(inventory.policy_bytes(POLICY)),
            'producerSha256': producer}
    values = [dict(base, event='begin', policy=POLICY)]
    chain = bytes(32)
    for index, member in enumerate(members):
        member = copy.deepcopy(member)
        member.update(completionOrdinal=str(index + 1), previousChainSha256=chain.hex())
        # These are explicitly synthetic writer bytes. The reader never
        # reserializes them to verify the actual producer's chain.
        raw = json.dumps(member, separators=(',', ':')).encode()
        chain = hashlib.sha256(chain + len(raw).to_bytes(8, 'big') + raw).digest()
        values.append(raw)
    values.append(dict(base, event='end', started=str(len(members)), terminal=str(len(members)),
                       pending='0', incomplete=str(incomplete), overflow=False,
                       chainSha256=chain.hex()))
    return [(inventory.MARKER + (value.decode() if isinstance(value, bytes)
             else json.dumps(value, separators=(',', ':'))), None) for value in values]


class InventoryReader(unittest.TestCase):
    def setUp(self):
        self.producer = inventory.producer(SOURCE, source_bytes)
        self.member = synthetic_member(1, self.producer)

    def validate(self, messages):
        return inventory.validate(messages, POLICY, self.producer, parse)

    def test_complete_counts_never_classify_unknown_body(self):
        result = self.validate(synthetic_messages([self.member], self.producer))
        self.assertTrue(result['inventoryComplete'])
        self.assertIsNone(result['nativeBulkBytes'])
        self.assertIsNone(inventory.source_asset(result['members'][0], SOURCE, source_bytes))

    def test_missing_duplicate_reordered_and_changed_bytes_refuse(self):
        messages = synthetic_messages([self.member, synthetic_member(2, self.producer)], self.producer)
        for changed in (messages[:1] + messages[2:], messages[:2] + messages[1:],
                        messages[:1] + [messages[2], messages[1]] + messages[3:]):
            with self.assertRaises(ValueError):
                self.validate(changed)
        changed = list(messages)
        # Change actual member bytes even though the semantic fields stay valid.
        changed[1] = (changed[1][0] + ' ', None)
        with self.assertRaises(ValueError):
            self.validate(changed)

    def test_trailers_unread_and_overflow_stay_incomplete(self):
        for field in ('requestTrailers', 'replyTrailers'):
            changed = copy.deepcopy(self.member)
            changed[field] = True
            self.assertFalse(self.validate(synthetic_messages([changed], self.producer, 1))['inventoryComplete'])
        changed = copy.deepcopy(self.member)
        changed['requestConsumed']['eof'] = False
        self.assertFalse(self.validate(synthetic_messages([changed], self.producer, 1))['inventoryComplete'])
        messages = synthetic_messages([self.member], self.producer)
        end = parse(messages[-1][0].split(inventory.MARKER)[1])
        end['overflow'] = True
        messages[-1] = (inventory.MARKER + json.dumps(end), None)
        self.assertFalse(self.validate(messages)['inventoryComplete'])

    def test_wrong_policy_source_and_false_end_refuse(self):
        messages = synthetic_messages([self.member], self.producer)
        for key in ('producerSha256', 'policySha256'):
            changed = list(messages)
            value = parse(changed[0][0].split(inventory.MARKER)[1])
            value[key] = 'f' * 64
            changed[0] = (inventory.MARKER + json.dumps(value), None)
            with self.assertRaises(ValueError):
                self.validate(changed)
        self.assertFalse(self.validate(messages[:-1])['inventoryComplete'])

    def test_unjoined_projection_label_never_makes_metadata(self):
        changed = copy.deepcopy(self.member)
        changed['typedEvidence'] = {'constructor': 'publication_manifest_append',
            'constructorSourceSha256': 'b' * 64, 'request': None,
            'reply': {'byteSize': '12', 'sha256': inventory.sha(b'unclassified')},
            'requiredProjection': 'bounded_original_and_current_sql_projection'}
        result = self.validate(synthetic_messages([changed], self.producer))
        self.assertTrue(result['inventoryComplete'])
        self.assertIsNone(result['nativeBulkBytes'])
        self.assertIsNone(inventory.source_asset(result['members'][0], SOURCE, source_bytes))


class SelectedInventorySeam(unittest.TestCase):
    def test_missing_instance_custody_stays_null_and_validates_original_manifest(self):
        raw_policy = inventory.policy_bytes(POLICY)
        sidecar = {'nativeLog': None, 'nativeProcess': None}
        calls = []
        readers = {
            'read_ref': lambda ref, maximum: raw_policy if ref == 'policy' else json.dumps(sidecar).encode(),
            'closed_json': parse,
            'assess': lambda selected, manifest: calls.append((selected, manifest)),
        }
        manifest = {'syntheticOriginalManifest': True}
        result = inventory.assess({'policy': 'policy', 'sidecar': 'sidecar'}, SOURCE,
                                  readers, source_bytes, manifest)
        self.assertEqual(calls, [(sidecar, manifest)])
        self.assertFalse(result['inventoryComplete'])
        self.assertIsNone(result['nativeBulkBytes'])
        self.assertIsNone(result['inboundObjectPayloadBytes'])
        self.assertIn('missing_actual_native_instance_executable_and_window_custody', result['missing'])

    def test_actual_assessment_slot_loads_exact_reader_and_keeps_original_manifest(self):
        # Compile the actual small invocation seam without importing an installed
        # package context or fabricating a measured runtime for this fixture.
        path = Path(__file__).parent / 'hosted_assessment.py'
        tree = ast.parse(path.read_bytes())
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'inbound_inventory')
        calls = []
        sidecar = {'nativeLog': None, 'nativeProcess': None}
        readers = {
            'read_ref': lambda ref, maximum: inventory.policy_bytes(POLICY)
                if ref == 'policy' else json.dumps(sidecar).encode(),
            'closed_json': parse,
            'assess': lambda selected, manifest: calls.append((selected, manifest)),
        }
        namespace = {'Path': Path, '__file__': str(path), 'MAX_JSON': 1024 * 1024,
                     'PACKAGE_READER': {'installed_bytes': source_bytes},
                     'SOURCE': SOURCE, 'READERS': readers}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), 'exec'), namespace)
        self.assertIsNone(namespace['inbound_inventory']({}, {'original': True}))
        manifest = {'original': True}
        result = namespace['inbound_inventory'](
            {'nativeInventory': {'policy': 'policy', 'sidecar': 'sidecar'}}, manifest)
        self.assertEqual(calls, [(sidecar, manifest)])
        self.assertFalse(result['inventoryComplete'])
        self.assertIsNone(result['nativeBulkBytes'])


class ImmutableCodecHandoff(unittest.TestCase):
    def setUp(self):
        self.member = synthetic_member(1, inventory.producer(SOURCE, source_bytes))
        self.member['requestId'] = 'a' * 32
        self.member['requestConsumed'] = synthetic_frame(b'synthetic request image')
        self.member['replyOffered'] = synthetic_frame(b'synthetic reply image')
        path = '/aos.hub.v1.PublishService/AppendRegistryPublicationManifest'
        self.member['pathSha256'] = inventory.sha(path.encode())
        files = ('crates/aos-hub-core/src/application_body_observation.rs',
                 'crates/aos-hub-core/src/application_body_observation/rpc.rs',
                 'crates/aos-hub-core/src/connect.rs')
        self.member['typedEvidence'] = {
            'constructor': 'publication_manifest_append',
            'constructorSourceSha256': inventory.sha(b''.join(source_bytes(SOURCE / name, 1024 * 1024)
                                                            for name in files)),
            'request': {'byteSize': self.member['requestConsumed']['exposedBytes'],
                        'sha256': self.member['requestConsumed']['exposedSha256']},
            'reply': {'byteSize': self.member['replyOffered']['exposedBytes'],
                      'sha256': self.member['replyOffered']['exposedSha256']},
            'requiredProjection': 'bounded_original_and_current_sql_projection',
        }
        image = lambda frame: {'byteSize': frame['exposedBytes'], 'sha256': frame['exposedSha256'],
                               'typedSemanticSha256': frame['exposedSha256']}
        self.row = {'requestIdSha256': inventory.sha(self.member['requestId'].encode()),
            'method': 'POST', 'procedure': path, 'phase': None,
            'authentication': 'not_checked_join_independent_authenticated_worker_receipt',
            'request': image(self.member['requestConsumed']), 'response': image(self.member['replyOffered']),
            'immutableProjection': {'version': 1, 'kind': 'publication_manifest_append',
                'originalRequestSha256': self.member['requestConsumed']['exposedSha256'],
                'sqlEvidenceSha256': 'b' * 64, 'matchedOriginalCount': '1',
                'requestControlBytes': self.member['requestConsumed']['exposedBytes'],
                'replyControlBytes': self.member['replyOffered']['exposedBytes'],
                'objectPayloadBytes': None,
                'sqlReaderAuthority': 'not_checked_join_measured_read_only_source_process_and_window',
                'missing': ['independent_sql_reader_custody_and_temporal_current_fences']}}
        # Only closed observational output is synthetic here. Actual DTO/page/
        # admission comparisons are exercised by the Rust projection tests.
        self.capture = {'requestId': self.member['requestId'], 'status': 200,
            'method': 'POST', 'procedure': path, 'phase': None,
            'bodies': {direction: {'file': 'synthetic-owned-image', 'sha256': frame['exposedSha256'],
                                  'byteSize': frame['exposedBytes']}
                       for direction, frame in (('request', self.member['requestConsumed']),
                                                ('response', self.member['replyOffered']))}}
        self.manifest = {'codecRevision': 'c' * 40, 'sourceDigest': 'd' * 64,
                         'captures': [self.capture]}
        self.report = {'version': 1, 'codecRevision': self.manifest['codecRevision'],
            'selectedSourceDigest': self.manifest['sourceDigest'], 'manifestSha256': 'e' * 64,
            'selectedBodyBytes': 1, 'maximumSelectedBodyBytes': 512 * 1024 * 1024,
            'maximumBodyBytes': 8 * 1024 * 1024, 'captures': [self.row]}

    def joined(self):
        return inventory.codec_projection(self.member, self.report, self.manifest, {}, SOURCE, source_bytes)

    def test_matching_codec_values_keep_control_bytes_and_sql_auth_unknown(self):
        result = self.joined()
        self.assertEqual(result['codecProjection']['requestControlBytes'], str(len(b'synthetic request image')))
        self.assertIsNone(result['objectPayloadBytes'])
        self.assertFalse(result['sourceCheckedIngress'])
        self.assertIn('independent_sql_reader_custody_and_temporal_current_fences', result['missing'])
        self.assertIn('independent_actual_authenticated_control_or_ingress_join', result['missing'])
        self.member['requestId'] = 'b' * 32
        self.assertIsNone(self.joined())
        self.report['selectedSourceDigest'] = 'f' * 64
        with self.assertRaises(ValueError):
            self.joined()

    def test_changed_runtime_source_body_owner_or_invented_zero_refuses(self):
        for mutate in (lambda: self.report.update(codecRevision='f' * 40),
                       lambda: self.row['response'].update(sha256='f' * 64),
                       lambda: self.report['captures'].append(copy.deepcopy(self.row)),
                       lambda: self.member['typedEvidence'].update(constructorSourceSha256='f' * 64),
                       lambda: self.row['immutableProjection'].update(objectPayloadBytes='0'),
                       lambda: self.capture.update(status=201),
                       lambda: self.capture.update(phase='complete'),
                       lambda: self.capture['bodies']['request'].update(sha256='f' * 64),
                       lambda: self.manifest['captures'].append(copy.deepcopy(self.capture)),
                       lambda: self.row['immutableProjection'].update(version=True),
                       lambda: self.report.update(version=True)):
            self.setUp()
            mutate()
            with self.assertRaises(ValueError):
                self.joined()


def actual_producer_case(path):
    class ActualProducer(unittest.TestCase):
        def test_real_rust_asset_record_and_raw_chain_are_connected(self):
            raw = Path(path).read_bytes()
            messages = [(inventory.MARKER + line.decode(), None) for line in raw.splitlines()]
            policy = parse(raw.splitlines()[0])['policy']
            result = inventory.validate(messages, policy, inventory.producer(SOURCE, source_bytes), parse)
            self.assertTrue(result['inventoryComplete'])
            self.assertEqual(len(result['members']), 1)
            projection = inventory.source_asset(result['members'][0], SOURCE, source_bytes)
            self.assertIsNotNone(projection)
            self.assertEqual(projection['class'], 'exact_source_embedded_public_asset')
            self.assertIsNone(result['nativeBulkBytes'])
            changed = copy.deepcopy(result['members'][0])
            changed['pathSha256'] = inventory.sha(b'/-/instance')
            self.assertIsNone(inventory.source_asset(changed, SOURCE, source_bytes))
            changed = copy.deepcopy(result['members'][0])
            changed['replyOffered']['exposedSha256'] = 'f' * 64
            self.assertIsNone(inventory.source_asset(changed, SOURCE, source_bytes))
    return ActualProducer



class SqlProjectionHandoff(unittest.TestCase):
    def setUp(self):
        self.producer = inventory.producer(SOURCE, source_bytes)
        self.member = synthetic_member(1, self.producer)
        self.member['typedEvidence'] = {
            'constructor': 'publication_manifest_append', 'constructorSourceSha256': 'b' * 64,
            'request': {'byteSize': '0', 'sha256': inventory.sha(b'')},
            'reply': {'byteSize': '12', 'sha256': inventory.sha(b'unclassified')},
            'requiredProjection': 'bounded_original_and_current_sql_projection',
        }
        paths = ('crates/aos-hub-core/src/application_body_observation/sql_projection.rs',
                 'crates/aos-hub-core/src/application_body_observation.rs',
                 'crates/aos-hub-core/src/application_body_observation/rpc.rs',
                 'crates/aos-hub-core/src/db/direct_upload.rs',
                 'crates/aos-hub-core/src/db/publication_admission.rs')
        self.operation = {'kind': 'manifest_append_retained_receipt', 'publicationId': 'synthetic-publication',
            'registryId': '1', 'leaseTokenSha256': 'd' * 64, 'manifestDigest': 'e' * 64,
            'chunkIndex': '3', 'chunkDigest': 'f' * 64, 'objectCount': '1',
            'observedSessionResourceVersion': '2', 'sourceBeforeUnixNanos': '100',
            'sourceAfterUnixNanos': '200', 'sourceElapsedNanos': '50'}
        self.child = {key: self.member[key] for key in inventory.BASE | {
            'admissionOrdinal', 'method', 'pathSha256', 'requestId', 'transportCallId', 'status', 'typedEvidence'}}
        self.child['event'] = 'sql_projection'
        self.child['projection'] = {'version': 1,
            'producerSha256': inventory.sha(b''.join(source_bytes(SOURCE / name, 1024 * 1024)
                                                     for name in paths)),
            'checkpoints': [self.operation]}
        self.raw = json.dumps(self.child, separators=(',', ':')).encode()
        self.member['sqlProjection'] = {'byteSize': str(len(self.raw)), 'sha256': inventory.sha(self.raw)}

    def test_optional_child_keeps_original_raw_chain_and_missing_authority(self):
        messages = synthetic_messages([self.member], self.producer)
        messages.insert(1, (inventory.SQL_MARKER + self.raw.decode(), None))
        result = inventory.validate(messages, POLICY, self.producer, parse)
        self.assertTrue(result['inventoryComplete'])
        projection = inventory.sql_child(result['members'][0], result['sqlChildren'], SOURCE, source_bytes)
        self.assertEqual(projection['checkpoints'], [self.operation])
        self.assertIsNone(projection['objectPayloadBytes'])
        self.assertEqual(projection['readerAuthority'], 'not_checked')
        old = synthetic_member(1, self.producer)
        self.assertIsNone(inventory.sql_child(old, [], SOURCE, source_bytes))

    def test_raw_child_duplicates_source_and_trailers_refuse(self):
        cases = [([], self.member), ([(self.child, self.raw)] * 2, self.member),
                 ([(self.child, self.raw + b' ')], self.member)]
        for children, member in cases:
            with self.assertRaises(ValueError):
                inventory.sql_child(member, children, SOURCE, source_bytes)
        for key in ('replyTrailers', 'requestTrailers'):
            member = copy.deepcopy(self.member); member[key] = True
            with self.assertRaises(ValueError):
                inventory.sql_child(member, [(self.child, self.raw)], SOURCE, source_bytes)
        changed = copy.deepcopy(self.child); changed['projection']['producerSha256'] = '0' * 64
        raw = json.dumps(changed, separators=(',', ':')).encode()
        member = copy.deepcopy(self.member)
        member['sqlProjection'] = {'byteSize': str(len(raw)), 'sha256': inventory.sha(raw)}
        with self.assertRaises(ValueError):
            inventory.sql_child(member, [(changed, raw)], SOURCE, source_bytes)

    def test_capped_direct_batch_has_no_child_and_never_infers_sixty_four_rows(self):
        member = copy.deepcopy(self.member)
        member.pop('sqlProjection')
        member['typedEvidence']['constructor'] = 'direct_logical_validated'
        self.assertIsNone(inventory.sql_child(member, [], SOURCE, source_bytes))
        self.assertIsNone(inventory.sql_reader_projection(None, None, None, {}, SOURCE, source_bytes, {}))
        changed = copy.deepcopy(self.child)
        changed['projection']['checkpoints'] *= 33
        raw = json.dumps(changed, separators=(',', ':')).encode()
        self.member['sqlProjection'] = {'byteSize': str(len(raw)), 'sha256': inventory.sha(raw)}
        with self.assertRaises(ValueError):
            inventory.sql_child(self.member, [(changed, raw)], SOURCE, source_bytes)

    def test_reader_time_rows_match_retained_retry_without_past_lease_claim(self):
        import importlib.util
        path = SOURCE / 'tests/fleet/_hub-native-sql-projection.py'
        spec = importlib.util.spec_from_file_location('synthetic_sql_fixture', path)
        collector = importlib.util.module_from_spec(spec); spec.loader.exec_module(collector)
        checkpoint = inventory.sql_child(self.member, [(self.child, self.raw)], SOURCE, source_bytes)
        pin = {'pid': 123, 'ownerUid': 1000, 'startTicks': '7', 'executableSha256': 'a' * 64}
        selection = {'deployment': 'synthetic', 'database': 'synthetic', 'role': 'synthetic_reader', 'psql': 'synthetic-psql',
            'databaseProcess': {**pin, 'pid': 124},
            'windowStartUnixNanos': '1', 'windowEndUnixNanos': '1000',
            'databaseBootId': 'synthetic-database',
            'collectorSourceSha256': inventory.sha(source_bytes(path, 1024*1024))}
        chunk = {'publicationId': self.operation['publicationId'], 'chunkIndex': 3,
                 'chunkDigest': 'f' * 64, 'objectCount': 1, 'acceptedAt': '1', 'registryId': '1',
                 'resourceVersion': '9', 'state': 'sealed', 'manifestDigest': 'e' * 64,
                 'leaseExpiresAt': None}
        rows = {'database': 'synthetic', 'databaseOid': '12345', 'serverPort': 5432, 'serverAddress': '127.0.0.1', 'user': 'synthetic_reader', 'backendPid': 125,
                'readOnly': 'on', 'isolation': 'repeatable read', 'snapshot': '10:20:',
                'snapshotAt': '2026-10-06 01:00:00+00', 'observedAt': '2026-10-06 01:00:01+00',
                'role': {'superuser': False, 'createDb': False, 'createRole': False, 'bypassRls': False},
                'privileges': [{'table': table, 'select': True, 'mutate': False}
                               for table in collector.NATIVE_SQL_TABLES], 'admissions': [], 'chunks': [chunk]}
        blobs = {'query': collector.native_sql_query(checkpoint['checkpoints'], 'synthetic', 'synthetic_reader').encode(),
                 'rows': json.dumps(rows).encode(), 'codec': json.dumps(chunk).encode()}
        reference = lambda key: {'file': key, 'sha256': inventory.sha(blobs[key]), 'byteSize': str(len(blobs[key]))}
        bundle = {'rows': rows, 'receipt': {'version': 2, 'query': reference('query'), 'rows': reference('rows'),
                  'stderrSha256': inventory.sha(b''), 'exitCode': 0, 'readerProcess': {**pin, 'pid': 126},
                  'backendProcess': {**pin, 'pid': 125, 'parentPid': 124}, 'redactedArgv': ['synthetic-psql', '-X', '--no-password', '-qAt', '-v', 'ON_ERROR_STOP=1'], 'psqlExecutableSha256': 'a' * 64, 'databaseUrlSha256': 'b' * 64, 'selection': selection,
                  'before': {'wallNs': '300', 'monotonicNs': '10'},
                  'after': {'wallNs': '400', 'monotonicNs': '20'},
                  'processesBefore': {'databaseProcess': selection['databaseProcess']},
                  'processesAfter': {'databaseProcess': selection['databaseProcess']}},
                  'codecImages': {'admissions': {'file': 'empty', 'sha256': inventory.sha(b''), 'byteSize': '0'},
                                  'chunks': [reference('codec')]},
                  'scope': 'synthetic reader-time records', 'objectPayloadBytes': None}
        native_context = {'process': pin, 'bootId': 'synthetic-native',
                          'database': 'synthetic', 'connectionFileSha256': 'c' * 64,
                          'port': 5432, 'resolvedAddresses': ['192.0.2.1']}
        database_context = {'process': selection['databaseProcess'], 'port': 5432,
                            'resolvedAddresses': ['192.0.2.1'], 'bootId': 'synthetic-database',
                            'postmasterFileSha256': 'd' * 64, 'dataDirectory': '/var/lib/hybrid-postgres'}
        def bracket(name, context, start):
            return {'guestName': name, 'observed': context,
                    'controllerBefore': {'wallNs': str(start), 'monotonicNs': str(start)},
                    'controllerAfter': {'wallNs': str(start+1), 'monotonicNs': str(start+1)}}
        bundle['controller'] = {
            'nativeBefore': bracket('synthetic-native-guest', native_context, 1),
            'databaseBefore': bracket('synthetic-db-guest', database_context, 3),
            'databaseAfter': bracket('synthetic-db-guest', database_context, 5),
            'nativeAfter': bracket('synthetic-native-guest', native_context, 7),
            'connectionMode': 'existing_select_only_role_over_database_loopback_trust',
            'collectorSourceSha256': selection['collectorSourceSha256'],
            'sourceChild': {key: checkpoint[key] for key in ('rawChildSha256', 'rawChildByteSize')},
            'receivedImages': [{'guestReference': reference(key), 'controllerReference': reference(key)}
                               for key in ('query', 'rows', 'codec')]}

        reader_image = {'kind': 'manifest_chunk', 'publicationId': chunk['publicationId'], 'chunkIndex': 3,
                        'chunkDigest': 'f' * 64, 'objectCount': 1, 'registryId': '1', 'manifestDigest': 'e' * 64}
        codec = {'codecProjection': {'sqlOriginals': [reader_image], 'sqlEvidenceSha256': inventory.sha(blobs['codec'])}}
        def read(ref, bound):
            raw = json.dumps({'version': 1, 'observations': [bundle], 'objectPayloadBytes': None, 'missing': []}).encode() if ref == 'bundle' else blobs[ref['file']]
            if len(raw) > bound:
                raise ValueError('Synthetic retained fixture exceeds bound')
            if isinstance(ref, dict) and (inventory.sha(raw) != ref['sha256'] or str(len(raw)) != ref['byteSize']):
                raise ValueError('Synthetic retained fixture changed')
            return raw
        readers = {'read_ref': read, 'closed_json': parse}
        result = inventory.sql_reader_projection(checkpoint, codec, 'bundle', readers,
                                                 SOURCE, source_bytes, {'nativeProcess': pin})
        self.assertIsNone(result['objectPayloadBytes'])
        self.assertIn('prior_operation_iam_or_lease_not_reconstructed_by_later_reader', result['missing'])
        self.assertEqual(result['matched'][0]['kind'], 'manifest_append_retained_receipt')
        for changed in ('role', 'query', 'original'):
            saved = copy.deepcopy(bundle); old_image = copy.deepcopy(reader_image)
            if changed == 'role':
                bundle['rows']['user'] = 'postgres'; blobs['rows'] = json.dumps(bundle['rows']).encode()
                bundle['receipt']['rows'] = reference('rows')
                bundle['controller']['receivedImages'][1] = {'guestReference': reference('rows'), 'controllerReference': reference('rows')}
            elif changed == 'query':
                blobs['query'] += b' '; bundle['receipt']['query'] = reference('query')
                bundle['controller']['receivedImages'][0] = {'guestReference': reference('query'), 'controllerReference': reference('query')}
            else:
                reader_image['chunkDigest'] = '0' * 64
            with self.assertRaises(ValueError):
                inventory.sql_reader_projection(checkpoint, codec, 'bundle', readers,
                                                 SOURCE, source_bytes, {'nativeProcess': pin})
            bundle = saved; reader_image.clear(); reader_image.update(old_image)
            blobs['rows'] = json.dumps(bundle['rows']).encode()
            blobs['query'] = collector.native_sql_query(checkpoint['checkpoints'], 'synthetic', 'synthetic_reader').encode()

if __name__ == '__main__':
    arguments = argparse.ArgumentParser()
    arguments.add_argument('--producer-fixture')
    arguments.add_argument('--immutable-handoff-only', action='store_true')
    arguments.add_argument('--sql-projection-only', action='store_true')
    selected = arguments.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        SqlProjectionHandoff if selected.sql_projection_only else ImmutableCodecHandoff)
    if not selected.immutable_handoff_only and not selected.sql_projection_only:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(InventoryReader))
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(SelectedInventorySeam))
    if selected.producer_fixture:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(actual_producer_case(selected.producer_fixture)))
    result = unittest.TextTestRunner().run(suite)
    raise SystemExit(not result.wasSuccessful())
