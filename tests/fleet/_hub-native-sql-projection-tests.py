"""Synthetic row/query refusals and actual local process/private-file custody.

These fixtures do not execute PostgreSQL or qualify a deployment. Database
identity and timestamp values below are explicitly synthetic reader records.
"""

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch


path = Path(__file__).with_name('_hub-native-sql-projection.py')
spec = importlib.util.spec_from_file_location('sql_projection_collector', path)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def fixture_rows():
    return {'database': 'synthetic', 'databaseOid': '12345', 'serverAddress': '127.0.0.1', 'serverPort': 5432, 'user': 'synthetic_reader', 'backendPid': 123,
            'readOnly': 'on', 'isolation': 'repeatable read', 'snapshot': '10:20:',
            'snapshotAt': '2026-10-06 01:00:00+00', 'observedAt': '2026-10-06 01:00:01+00',
            'role': {'superuser': False, 'createDb': False, 'createRole': False, 'bypassRls': False},
            'privileges': [{'table': table, 'select': True, 'mutate': False}
                           for table in collector.NATIVE_SQL_TABLES],
            'admissions': [{'sessionId': 'synthetic-session'}], 'chunks': []}


class Collector(unittest.TestCase):
    def setUp(self):
        self.checkpoints = [{'kind': 'admission_checked_transaction', 'sessionId': 'synthetic-session'}]
        self.selection = {'database': 'synthetic', 'role': 'synthetic_reader'}

    def test_exact_query_is_read_only_and_source_keys_are_bounded(self):
        query = collector.native_sql_query(self.checkpoints, 'synthetic-deployment', 'synthetic_reader')
        self.assertTrue(query.startswith('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;'))
        self.assertTrue(query.endswith('COMMIT;'))
        self.assertIn("session_id IN ('synthetic-session')", query)
        self.assertIn('pg_current_snapshot()', query)
        self.assertIn("'serverAddress',host(inet_server_addr())", query)
        self.assertNotIn('inet_server_addr()::text', query)
        self.assertNotIn('admission_json::json AS admission FROM', query)
        for changed in ([{'kind': 'other'}], self.checkpoints * 65,
                        [{'kind': 'admission_checked_transaction', 'sessionId': "x';DELETE"}]):
            with self.assertRaises(ValueError):
                collector.native_sql_query(changed, 'synthetic-deployment', 'synthetic_reader')

    def test_one_sixty_four_original_batch_is_collected_without_splitting(self):
        checkpoints = [{'kind': 'admission_checked_transaction',
                        'sessionId': 'synthetic-session-' + str(index)}
                       for index in range(64)]
        child = {'version': 1, 'event': 'sql_projection', 'status': 200,
                 'projection': {'version': 1, 'checkpoints': checkpoints}}
        raw = json.dumps(child).encode()
        batches = collector.native_sql_checkpoints([
            ('native_application_sql_projection ' + raw.decode(), None)])

        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0]['checkpoints'], checkpoints)
        query = collector.native_sql_query(checkpoints, 'synthetic', 'synthetic_reader')
        self.assertEqual(query.count('BEGIN TRANSACTION'), 1)
        for checkpoint in checkpoints:
            self.assertIn("'" + checkpoint['sessionId'] + "'", query)

        selected = fixture_rows()
        selected['admissions'] = [{'sessionId': item['sessionId']} for item in checkpoints]
        self.assertEqual(collector.native_sql_rows(json.dumps(selected).encode(),
                                                  self.selection, checkpoints), selected)
        for rows in (selected['admissions'][:-1], selected['admissions'] + [selected['admissions'][0]]):
            changed = {**selected, 'admissions': rows}
            with self.assertRaises(ValueError):
                collector.native_sql_rows(json.dumps(changed).encode(), self.selection, checkpoints)

        child['projection']['checkpoints'] = checkpoints + [checkpoints[0]]
        with self.assertRaises(ValueError):
            collector.native_sql_checkpoints([
                ('native_application_sql_projection ' + json.dumps(child), None)])
        with self.assertRaises(ValueError):
            collector.native_sql_checkpoints([
                ('native_application_sql_projection ' + ' ' * (96 * 1024 + 1), None)])

    def test_actual_role_database_snapshot_and_row_coverage_refuse_substitution(self):
        original = fixture_rows()
        self.assertEqual(collector.native_sql_rows(json.dumps(original).encode(),
            self.selection, self.checkpoints), original)
        changes = [('database', 'different'), ('user', 'postgres'), ('backendPid', True),
                   ('readOnly', 'off'), ('isolation', 'read committed'), ('snapshot', 'unknown'),
                   ('admissions', []), ('admissions', original['admissions'] * 2), ('chunks', [{}])]
        for key, value in changes:
            changed = copy.deepcopy(original); changed[key] = value
            with self.assertRaises(ValueError, msg=key):
                collector.native_sql_rows(json.dumps(changed).encode(), self.selection, self.checkpoints)
        for field in original['role']:
            changed = copy.deepcopy(original); changed['role'][field] = True
            with self.assertRaises(ValueError):
                collector.native_sql_rows(json.dumps(changed).encode(), self.selection, self.checkpoints)
        changed = copy.deepcopy(original); changed['privileges'][0]['mutate'] = True
        with self.assertRaises(ValueError):
            collector.native_sql_rows(json.dumps(changed).encode(), self.selection, self.checkpoints)

    def test_raw_output_framing_duplicates_and_hard_bound_refuse(self):
        raw = json.dumps(fixture_rows()).encode()
        for changed in (raw + b'\n' + raw, raw[:-1] + b',"database":"other"}', b'x' * (512 * 1024 + 1)):
            with self.assertRaises(ValueError):
                collector.native_sql_rows(changed, self.selection, self.checkpoints)

    def test_actual_local_process_and_owned_private_file_custody(self):
        pin = collector.native_sql_process(os.getpid())
        self.assertEqual(pin['ownerUid'], os.getuid())
        self.assertEqual(pin, collector.native_sql_process(os.getpid()))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'rows.private'
            path.write_bytes(b'actual private fixture'); path.chmod(0o600)
            self.assertEqual(collector.native_sql_private(path, 128), b'actual private fixture')
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                collector.native_sql_private(path, 128)
            path.chmod(0o600)
            link = Path(directory) / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError):
                collector.native_sql_private(link, 128)

    def test_unselected_or_missing_source_stays_unavailable(self):
        result = collector.capture_native_sql_projection(None, None, {}, [], {}, {}, 'synthetic')
        self.assertEqual(result['observations'], [])
        self.assertIsNone(result['objectPayloadBytes'])

    def test_live_local_backend_parent_is_measured_not_declared(self):
        parent = collector.native_sql_process(os.getpid())
        child = subprocess.Popen([sys.executable, '-c',
            "import sys; print('ready', flush=True); sys.stdin.read()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline(), 'ready\n')
            pin = collector.native_sql_backend(child.pid, parent)
            self.assertEqual(pin['parentPid'], parent['pid'])
            self.assertEqual(pin['executableSha256'], parent['executableSha256'])
            with self.assertRaises(ValueError):
                collector.native_sql_backend(child.pid, {**parent, 'pid': child.pid})
        finally:
            child.stdin.close()
            child.wait(timeout=5)
            child.stdout.close()

    def test_loopback_trust_never_selects_inherited_password_or_other_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {'PGPASSWORD': 'synthetic-not-a-credential', 'PGSERVICE': 'other'}):
                environment = collector.native_sql_environment(
                    b'postgresql://synthetic_reader@127.0.0.1:5432/postgres', 'synthetic_reader', root)
            self.assertNotIn('PGPASSWORD', environment)
            self.assertNotIn('PGSERVICE', environment)
            self.assertEqual(environment['PGSSLMODE'], 'disable')
            self.assertEqual(environment['PGPASSFILE'], str(root / 'password-not-selected'))
            for raw in (b'postgresql://postgres@127.0.0.1:5432/postgres',
                        b'postgresql://synthetic_reader@other:5432/postgres'):
                with self.assertRaises(ValueError):
                    collector.native_sql_environment(raw, 'synthetic_reader', root)

    def test_separate_guest_endpoint_and_process_lifetimes_refuse_substitution(self):
        native = {'bootId': 'synthetic-native', 'port': 5432, 'resolvedAddresses': ['192.0.2.1'], 'process': {'pid': 2}}
        database = {**native, 'bootId': 'synthetic-db', 'process': {'pid': 3}}
        collector.native_sql_topology(native, native, database, database)
        for changed in ({**database, 'bootId': native['bootId']},
                        {**database, 'resolvedAddresses': ['192.0.2.2']},
                        {**database, 'port': 5433}):
            with self.assertRaises(ValueError):
                collector.native_sql_topology(native, native, changed, changed)
        with self.assertRaises(ValueError):
            collector.native_sql_topology(native, {**native, 'process': {'pid': 5}}, database, database)

    def test_window_groups_never_silently_truncate_at_thirty_two(self):
        child = {'version': 1, 'event': 'sql_projection', 'status': 200,
                 'projection': {'version': 1, 'checkpoints': self.checkpoints}}
        messages = [('native_application_sql_projection ' + json.dumps(child), None)] * 33
        batches = collector.native_sql_checkpoints(messages)
        self.assertEqual(len(batches), 33)
        self.assertEqual(batches[0]['checkpoints'], self.checkpoints)
        self.assertEqual(batches[0]['rawChildSha256'], collector.native_sql_digest(json.dumps(child).encode()))
        with self.assertRaises(ValueError):
            collector.native_sql_checkpoints(messages, maximum=32)

    def test_dynamic_reader_retains_one_full_batch_and_refuses_missing_originals(self):
        checkpoints = [{'kind': 'dynamic', 'observation': {
            'operation': 'direct_authorize', 'sessionId': 'session-' + str(index)}}
            for index in range(64)]
        query = collector.native_sql_query(checkpoints, 'synthetic', 'synthetic_reader')
        self.assertEqual(query.count('BEGIN TRANSACTION'), 1)
        self.assertIn('direct_upload_completion_intents', query)
        self.assertIn('direct_upload_completion_receipts', query)
        self.assertNotIn('UPDATE ', query)
        rows = fixture_rows()
        rows['admissions'] = []
        rows['publications'] = []
        rows['dynamicSessions'] = [{'original': {'sessionId': 'session-' + str(index)}}
                                   for index in range(64)]
        rows['privileges'] = [{'table': table, 'select': True, 'mutate': False}
                              for table in collector.native_sql_tables(checkpoints)]
        self.assertEqual(collector.native_sql_rows(json.dumps(rows).encode(), self.selection, checkpoints), rows)
        for changed in (rows['dynamicSessions'][:-1], rows['dynamicSessions'] + [rows['dynamicSessions'][0]]):
            with self.assertRaises(ValueError):
                collector.native_sql_rows(json.dumps({**rows, 'dynamicSessions': changed}).encode(),
                                          self.selection, checkpoints)
        with self.assertRaises(ValueError):
            collector.native_sql_query(checkpoints + [checkpoints[0]], 'synthetic', 'synthetic_reader')
        with self.assertRaises(ValueError):
            collector.native_sql_query([{'kind': 'dynamic', 'observation': {
                'operation': 'other', 'sessionId': 'session-0'}}], 'synthetic', 'synthetic_reader')

    def test_dynamic_original_match_preserves_omitted_status_and_checked_replay_distinction(self):
        image = {'sha256': 'a' * 64, 'byteSize': '23'}
        source = {'operation': 'direct_authorize', 'sessionId': 'session',
                  'requestContext': image, 'selectedOriginal': image, 'action': 'complete',
                  'completeStep': 'promote', 'admission': image, 'baselinePermissions': image,
                  'returnedStatus': image, 'observedState': 'staged_verified', 'observedResourceVersion': '2'}
        values = {key: value for key, value in source.items()
                  if key not in ('returnedStatus', 'observedState', 'observedResourceVersion')}
        values.update(readerState='committed', readerResourceVersion='3')
        result = collector.native_sql_match_dynamic({'observation': source}, [{'kind': 'dynamic', 'values': values}])
        self.assertIn('compact_authorize_reply_omits_prior_full_status_and_version', result['missing'])
        with self.assertRaises(ValueError):
            collector.native_sql_match_dynamic({'observation': source}, [
                {'kind': 'dynamic', 'values': {**values, 'selectedOriginal': {'sha256': 'b' * 64, 'byteSize': '23'}}}])

        commit = {'operation': 'direct_commit', 'sessionId': 'session', 'deploymentSha256': 'c' * 64,
                  'admission': image, 'completeOriginal': image, 'completionEvidence': image,
                  'finalGuards': image, 'expectedResourceVersion': '2', 'resultingResourceVersion': '3',
                  'retainedOriginal': False}
        retained = {key: value for key, value in commit.items()
                    if key not in ('expectedResourceVersion', 'resultingResourceVersion', 'retainedOriginal')}
        retained.update(receiptResultingResourceVersion='3', replyResourceVersion='3')
        collector.native_sql_match_dynamic({'observation': commit}, [{'kind': 'dynamic', 'values': retained}])
        replay = {**commit, 'expectedResourceVersion': '3', 'resultingResourceVersion': None, 'retainedOriginal': True}
        collector.native_sql_match_dynamic({'observation': replay}, [{'kind': 'dynamic', 'values': retained}])
        with self.assertRaises(ValueError):
            collector.native_sql_match_dynamic({'observation': {**commit, 'expectedResourceVersion': '3'}},
                                              [{'kind': 'dynamic', 'values': retained}])

    def test_dynamic_codec_image_requires_actual_reader_family_bytes(self):
        row = {'original': {'sessionId': 'session'}, 'completeIntent': None, 'completionReceipt': None}
        raw = json.dumps(row).encode() + b'\n'
        reference = {'file': 'private-row', 'sha256': collector.native_sql_digest(raw), 'byteSize': str(len(raw))}
        empty = {'file': 'private-empty', 'sha256': collector.native_sql_digest(b''), 'byteSize': '0'}
        images = {'admissions': empty, 'chunks': [], 'publications': [], 'dynamicSessions': reference}
        rows = {'admissions': [], 'chunks': [], 'publications': [], 'dynamicSessions': [row]}
        self.assertEqual(collector.native_sql_codec_image(images, rows, reference['sha256'],
            lambda selected, maximum: raw), raw)
        with self.assertRaises(ValueError):
            collector.native_sql_codec_image(images, {**rows, 'dynamicSessions': []}, reference['sha256'],
                                            lambda selected, maximum: raw)


if __name__ == '__main__':
    unittest.main()
