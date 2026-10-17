"""Source-shaped raw encoding fixtures; no managed runtime or provider proof.

Policy bytes use the real Rust declared field order. Event JSON uses the actual
serde_json Value map's sorted keys, and the independent test chain applies the
producer's domain to exact encoded bytes. Selected source images are read from
the caller's pinned source, never from policy or an asserted expected digest.
"""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('outbound_reader', ROOT / 'native_outbound.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
SOURCE = Path(os.environ.get('AOS_NATIVE_OUTBOUND_TEST_SOURCE',
    str(ROOT.parents[2])))


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate test JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


class OutboundTests(unittest.TestCase):
    def setUp(self):
        self.policy = {'version': 1, 'runId': 'a' * 64, 'windowId': 'b' * 32,
                       'startUnixMillis': '1000', 'endUnixMillis': '2000'}
        self.producer = reader.producer(SOURCE, self.read_source)
        self.epoch = 'c' * 32

    @staticmethod
    def read_source(path, maximum):
        raw = Path(path).read_bytes()
        if len(raw) > maximum:
            raise ValueError('Test source exceeds actual selected bound')
        return raw

    def records(self, *, pending=False, unfinished=False, secret=False, epoch=None):
        offer = {'dispatchOrdinal': '1', 'owner': 'credential_custody' if secret else 'execute',
                 'transportCallId': None, 'requestSha256': None if secret else reader.sha(b'request'),
                 'offeredRequestBytes': '7'}
        terminal = {**offer, 'replyStatus': None if unfinished else 200,
                    'exposedReplySha256': None if secret else reader.sha(b'' if unfinished else b'reply'),
                    'exposedReplyBytes': '0' if unfinished else '5', 'replyEof': not unfinished,
                    'outcome': 'send_unfinished' if unfinished else 'reply_eof_unverified',
                    'elapsedMicros': '1', 'replyMacAuthentication': None, 'finalSqlAuthority': None}
        rows = [{'event': 'begin', 'policy': self.policy,
                 'scope': 'remote_storage_dispatch_roster'}, {'event': 'offered', **offer}]
        if not pending:
            rows.append({'event': 'terminal', **terminal})
        rows.append({'event': 'end', 'offered': '1', 'terminal': '0' if pending else '1',
                     'pending': '1' if pending else '0',
                     'incomplete': '1' if unfinished and not pending else '0',
                     'unfinishedSend': '1' if unfinished and not pending else '0',
                     'overflowOrFailure': False, 'chainSha256': ''})
        return self.encode(rows, epoch or self.epoch)

    def encode(self, rows, epoch=None):
        chain = bytes(32)
        result = []
        for index, value in enumerate(rows, 1):
            row = {**value, 'version': 1, 'runId': self.policy['runId'],
                   'windowId': self.policy['windowId'], 'processEpoch': epoch or self.epoch,
                   'policySha256': reader.sha(reader.policy_bytes(self.policy)),
                   'producerSha256': self.producer, 'eventOrdinal': str(index)}
            if row['event'] == 'end':
                row['chainSha256'] = chain.hex()
            raw = json.dumps(row, sort_keys=True, separators=(',', ':')).encode()
            if row['event'] not in ('end', 'late_terminal'):
                chain = hashlib.sha256(b'aos.native.remote-storage-window-chain.v1\0' + chain + raw).digest()
            result.append((reader.MARKER + raw.decode(), '1000000'))
        return result

    def rows(self, records):
        return [parse(message.split(reader.MARKER)[1]) for message, _ in records]

    def validate(self, records):
        return reader.validate(records, self.policy, self.producer, parse)

    def test_actual_source_roster_and_raw_encoding_close_only_dispatcher_scope(self):
        records = self.records()
        state = self.validate(records)[self.epoch]

        self.assertEqual(len(self.producer), 64)
        with self.assertRaises(ValueError):
            reader.validate(records, self.policy, 'f' * 64, parse)
        self.assertTrue(state['dispatcherWindowComplete'])
        self.assertIsNone(state['nativeBulkBytes'])
        self.assertIsNone(state['replyMacAuthentication'])
        self.assertIsNone(state['finalSqlAuthority'])
        self.assertIsNone(state['dispatches'][0]['offered']['transportCallId'])
        self.assertEqual(len(state['dispatches']), 1)  # No requirement to exercise every owner.

    def test_missing_offer_raw_mutation_and_counter_substitution_refuse(self):
        records = self.records()
        with self.assertRaises(ValueError):
            self.validate(records[:1] + records[2:])
        rows = self.rows(records)
        for change in ('foreign_offer', 'counter', 'chain'):
            mutated = copy.deepcopy(rows)
            if change == 'foreign_offer':
                mutated[2]['requestSha256'] = 'd' * 64
            elif change == 'counter':
                mutated[-1]['terminal'] = '2'
            else:
                # Mutate only raw offer; retain original end chain.
                message = records[1][0].replace('"offeredRequestBytes":"7"', '"offeredRequestBytes":"8"')
                with self.assertRaises(ValueError):
                    self.validate([records[0], (message, records[1][1]), *records[2:]])
                continue
            with self.assertRaises(ValueError):
                self.validate(self.encode(mutated))

    def test_missing_end_error_and_pending_remain_incomplete(self):
        for records in (self.records()[:-1], self.records(pending=True), self.records(unfinished=True)):
            state = self.validate(records)[self.epoch]
            self.assertFalse(state['dispatcherWindowComplete'])
            self.assertTrue(state['missing'])
            self.assertIsNone(state['nativeBulkBytes'])
        rows = self.rows(self.records())
        rows[-1]['overflowOrFailure'] = True
        self.assertFalse(self.validate(self.encode(rows))[self.epoch]['dispatcherWindowComplete'])

    def test_completed_history_above_pending_cap_preserves_complete_chain(self):
        template = self.rows(self.records())
        rows = [template[0]]
        for index in range(1, 8194):
            rows.append({**template[1], 'dispatchOrdinal': str(index)})
            rows.append({**template[2], 'dispatchOrdinal': str(index)})
        rows.append({**template[-1], 'offered': '8193', 'terminal': '8193'})

        state = self.validate(self.encode(rows))[self.epoch]
        self.assertTrue(state['dispatcherWindowComplete'])
        self.assertEqual(len(state['dispatches']), 8193)
        self.assertIsNone(state['nativeBulkBytes'])

    def test_late_eof_cannot_rewrite_pending_cutoff(self):
        rows = self.rows(self.records(pending=True))
        terminal = self.rows(self.records())[2]
        rows.append({**terminal, 'event': 'late_terminal'})
        state = self.validate(self.encode(rows))[self.epoch]

        self.assertFalse(state['dispatcherWindowComplete'])
        self.assertEqual(state['end']['pending'], '1')
        self.assertIsNone(state['dispatches'][0]['terminal'])
        self.assertEqual(state['lateTerminalOrdinals'], [1])

    def test_cross_epoch_stitching_unknown_owner_and_auth_assertion_refuse(self):
        rows = self.rows(self.records())
        for kind in ('epoch', 'owner', 'auth'):
            mutated = copy.deepcopy(rows)
            if kind == 'epoch':
                records = self.encode(mutated)
                row = parse(records[2][0].split(reader.MARKER)[1])
                row['processEpoch'] = 'e' * 32
                records[2] = (reader.MARKER + json.dumps(row, sort_keys=True, separators=(',', ':')), '1000000')
            else:
                if kind == 'owner':
                    mutated[1]['owner'] = 'unsupported'
                else:
                    mutated[2]['replyMacAuthentication'] = True
                records = self.encode(mutated)
            with self.assertRaises(ValueError):
                self.validate(records)

    def test_secret_control_length_only_refuses_hashes_or_extra_fields(self):
        self.assertTrue(self.validate(self.records(secret=True))[self.epoch]['dispatcherWindowComplete'])
        for field in ('exposedReplySha256', 'requestSha256', 'Authorization'):
            rows = self.rows(self.records(secret=True))
            rows[2][field] = 'f' * 64
            with self.assertRaises(ValueError):
                self.validate(self.encode(rows))

    def assessment(self, groups):
        policy_ref, sidecar_ref, log_ref = 'policy', 'sidecar', 'log'
        policy_raw = reader.policy_bytes(self.policy)
        images = {'policy': policy_raw,
                  'sidecar': json.dumps({'nativeLog': {'format': 'cloud_run', 'selection': log_ref}}).encode(),
                  'log': json.dumps({'outboundPolicy': policy_ref,
                                    'firstUnixMicros': '1000000', 'lastUnixMicros': '2000000'}).encode()}
        readers = {'read_ref': lambda reference, maximum: images[reference], 'closed_json': parse,
                   'assess': lambda *_: {'wholeIngressContextComplete': False},
                   'hosted_messages': lambda *_: {'messages': groups, 'missing': ['independent_image_export_time']}}
        return reader.assess({'policy': policy_ref, 'sidecar': sidecar_ref}, SOURCE,
                             readers, self.read_source, {})

    def test_shared_export_retains_unknowns_and_cross_instance_epoch_refuses(self):
        result = self.assessment({'instance-one': self.records()})
        self.assertFalse(result['inventoryComplete'])
        self.assertIsNone(result['nativeBulkBytes'])
        self.assertIn('independent_image_export_time', result['missing'])
        self.assertIn('full_native_egress_outside_remote_storage_dispatch_roster', result['missing'])
        with self.assertRaises(ValueError):
            self.assessment({'instance-one': self.records(), 'instance-two': self.records()})


if __name__ == '__main__':
    unittest.main()
