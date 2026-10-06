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


if __name__ == '__main__':
    arguments = argparse.ArgumentParser()
    arguments.add_argument('--producer-fixture')
    arguments.add_argument('--immutable-handoff-only', action='store_true')
    selected = arguments.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ImmutableCodecHandoff)
    if not selected.immutable_handoff_only:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(InventoryReader))
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(SelectedInventorySeam))
    if selected.producer_fixture:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(actual_producer_case(selected.producer_fixture)))
    result = unittest.TextTestRunner().run(suite)
    raise SystemExit(not result.wasSuccessful())
