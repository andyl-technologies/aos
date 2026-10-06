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
    selected = arguments.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(InventoryReader)
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(SelectedInventorySeam))
    if selected.producer_fixture:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(actual_producer_case(selected.producer_fixture)))
    result = unittest.TextTestRunner().run(suite)
    raise SystemExit(not result.wasSuccessful())
