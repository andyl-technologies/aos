"""Synthetic hosted receiver contracts; these fixtures authenticate no provider."""

import copy
import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest

import hosted_custody as custody
import native_inventory as inventory


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate synthetic JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


class HostedCustody(unittest.TestCase):
    def setUp(self):
        self.owner = tempfile.TemporaryDirectory(prefix='aos-hosted-custody-synthetic-')
        self.addCleanup(self.owner.cleanup)
        self.root = Path(self.owner.name)
        self.ordinal = 0
        self.readers = {'read_ref': self.read, 'closed_json': parse}
        self.runtime = {'runtimeCodecRevision': 'synthetic-not-installed',
                        'nativeExecutableSha256': 'a' * 64,
                        'workerSourceDigest': 'b' * 64, 'sourceArchiveSha256': 'c' * 64}

    def ref(self, value):
        raw = value if isinstance(value, bytes) else json.dumps(value, separators=(',', ':')).encode()
        self.ordinal += 1
        path = self.root / str(self.ordinal)
        path.write_bytes(raw)
        path.chmod(0o600)
        return {'file': str(path), 'byteSize': str(len(raw)), 'sha256': custody.sha(raw)}

    def read(self, reference, maximum):
        raw = Path(reference['file']).read_bytes()
        if (len(raw) > maximum or str(len(raw)) != reference['byteSize']
                or custody.sha(raw) != reference['sha256']):
            raise ValueError('Synthetic private byte image differs')
        return raw

    def exchange(self, operation, request, response):
        request, response = self.ref(request), self.ref(response)
        receipt = {'syntheticOnly': True, 'operation': operation,
                   'requestSha256': request['sha256'], 'responseSha256': response['sha256']}
        return {'request': request, 'response': response, 'collectorReceipt': self.ref(receipt)}

    @staticmethod
    def synthetic_verifier(operation, request, response, receipt, scope):
        """Model the code-only verifier interface, never real export custody."""
        proof = parse(receipt)
        valid = (proof.get('querySha256') == custody.sha(request)
                 and proof.get('rowsSha256') == custody.sha(response)) if operation == 'cloud_sql_reader' else (
            proof == {'syntheticOnly': True, 'operation': operation,
                      'requestSha256': custody.sha(request), 'responseSha256': custody.sha(response)})
        if not valid:
            raise ValueError('Synthetic verifier refused substituted export')
        return {'operation': operation, 'requestSha256': custody.sha(request),
                'responseSha256': custody.sha(response), 'receiptSha256': custody.sha(receipt), 'scope': scope}

    def logs(self):
        spec = {'version': 1, 'kind': 'cloud_run', 'runtime': self.runtime,
                'project': 'synthetic-project', 'location': 'synthetic-region',
                'serviceName': 'projects/synthetic-project/locations/synthetic-region/services/synthetic-service',
                'revisionName': 'projects/synthetic-project/locations/synthetic-region/services/synthetic-service/revisions/synthetic-revision',
                'imageDigest': 'sha256:' + 'd' * 64,
                'policy': self.ref(b'{"version":1,"windowId":"' + b'e' * 32
                    + b'","startUnixMillis":"1000","endUnixMillis":"2000"}'),
                'instances': ['synthetic-instance'], 'firstUnixMicros': '1000000',
                'lastUnixMicros': '2000000'}
        policy = self.read(spec['policy'], 1024).decode()
        spec['service'] = self.exchange('cloud_run_service', {'name': spec['serviceName']},
            {'name': spec['serviceName'], 'uid': 'synthetic-service-uid',
             'latestReadyRevision': spec['revisionName']})
        spec['revision'] = self.exchange('cloud_run_revision', {'name': spec['revisionName']},
            {'name': spec['revisionName'], 'uid': 'synthetic-revision-uid', 'service': spec['serviceName'],
             'containers': [{'image': 'synthetic.example/native@' + spec['imageDigest'],
                 'env': [{'name': 'AOS_NATIVE_BODY_INVENTORY', 'value': policy}]}]})
        request = {'resourceNames': ['projects/synthetic-project'],
                   'filter': custody.log_filter(spec), 'orderBy': 'timestamp asc', 'pageSize': 1000}
        entry = {'resource': {'type': 'cloud_run_revision', 'labels': {
            'project_id': spec['project'], 'location': spec['location'],
            'service_name': 'synthetic-service', 'revision_name': 'synthetic-revision'}},
            'labels': {'instanceId': 'synthetic-instance'}, 'insertId': 'synthetic-entry',
            'timestamp': '1970-01-01T00:00:01.123456789Z',
            'textPayload': 'synthetic unclassified message'}
        spec['pages'] = [self.exchange('logging_entries_list', request,
            {'entries': [], 'nextPageToken': 'synthetic-next'}),
            self.exchange('logging_entries_list', dict(request, pageToken='synthetic-next'), {'entries': [entry]})]
        return spec

    def test_matched_export_preserves_raw_message_and_missing_authority(self):
        result = custody.cloud_run(self.logs(), self.readers, self.runtime, self.synthetic_verifier)
        self.assertEqual(result['messages'], {'synthetic-instance': [
            ('synthetic unclassified message', '1123456')]})
        self.assertTrue(result['missing'])
        self.assertIsNone(result['nativeBulkBytes'])

    def test_json_cannot_assert_authenticated_transport(self):
        spec = self.logs()
        result = custody.cloud_run(spec, self.readers, self.runtime)
        self.assertIsNone(result['messages'])
        self.assertIn('missing_source_bound_authenticated_export_collector', result['missing'])
        spec['authenticated'] = True
        with self.assertRaises(ValueError):
            custody.cloud_run(spec, self.readers, self.runtime, self.synthetic_verifier)

    def test_missing_page_duplicate_or_foreign_instance_refuses(self):
        spec = self.logs()
        with self.assertRaises(ValueError):
            custody.cloud_run(dict(spec, pages=spec['pages'][:1]), self.readers, self.runtime, self.synthetic_verifier)
        for mutate in ('duplicate', 'foreign', 'filtered', 'wrong_token'):
            changed = copy.deepcopy(spec)
            request = parse(self.read(changed['pages'][1]['request'], 64 * 1024))
            response = parse(self.read(changed['pages'][1]['response'], custody.MAX_PAGE))
            if mutate == 'duplicate':
                response['entries'] *= 2
            elif mutate == 'foreign':
                response['entries'][0]['labels']['instanceId'] = 'another-instance'
            elif mutate == 'filtered':
                request['filter'] += ' AND textPayload:"begin"'
            else:
                request['pageToken'] = 'different-token'
            changed['pages'][1] = self.exchange('logging_entries_list', request, response)
            with self.assertRaises(ValueError, msg=mutate):
                custody.cloud_run(changed, self.readers, self.runtime, self.synthetic_verifier)

    def test_export_substitution_and_current_tuple_mismatch_refuse(self):
        spec = self.logs()
        foreign = copy.deepcopy(spec)
        foreign['revision']['response'] = self.ref({'name': spec['revisionName'], 'uid': 'changed'})
        with self.assertRaises(ValueError):
            custody.cloud_run(foreign, self.readers, self.runtime, self.synthetic_verifier)
        with self.assertRaises(ValueError):
            custody.cloud_run(spec, self.readers, dict(self.runtime, nativeExecutableSha256='f' * 64),
                              self.synthetic_verifier)

    def test_actual_chain_reader_keeps_instances_separate_and_detects_missing_member(self):
        spec = self.logs()
        policy = parse(self.read(spec['policy'], 1024))
        base = {'version': 1, 'windowId': policy['windowId'],
                'policySha256': custody.sha(self.read(spec['policy'], 1024)),
                'producerSha256': 'f' * 64}
        frame = {'exposedBytes': '0', 'exposedSha256': custody.sha(b''),
                 'eof': True, 'failed': False, 'overflow': False}
        member = dict(base, event='member', admissionOrdinal='1', completionOrdinal='1',
            previousChainSha256='0' * 64, method='POST', pathSha256='a' * 64,
            requestId=None, transportCallId=None, status=200, handlerReturned=True,
            requestConsumed=frame, replyOffered=frame, requestTrailers=False,
            replyTrailers=False, typedEvidence=None)
        raw = json.dumps(member, separators=(',', ':')).encode()
        chain = hashlib.sha256(bytes(32) + len(raw).to_bytes(8, 'big') + raw).hexdigest()
        values = [dict(base, event='begin', policy=policy), member,
                  dict(base, event='end', started='1', terminal='1', pending='0',
                       incomplete='0', overflow=False, chainSha256=chain)]
        request = parse(self.read(spec['pages'][0]['request'], 64 * 1024))
        template = parse(self.read(spec['pages'][1]['response'], custody.MAX_PAGE))['entries'][0]
        entries = []
        for index, value in enumerate(values):
            entry = copy.deepcopy(template)
            entry['insertId'] = str(index)
            entry['textPayload'] = inventory.MARKER + json.dumps(value, separators=(',', ':'))
            entries.append(entry)
        spec['pages'] = [self.exchange('logging_entries_list', request, {'entries': entries})]
        result = custody.cloud_run(spec, self.readers, self.runtime, self.synthetic_verifier)
        messages = result['messages']['synthetic-instance']
        checked = inventory.validate(messages, policy, 'f' * 64, parse)
        self.assertTrue(checked['inventoryComplete'])
        self.assertIsNone(checked['nativeBulkBytes'])
        with self.assertRaises(ValueError):
            inventory.validate([messages[0], messages[2]], policy, 'f' * 64, parse)

    def sql(self):
        path = Path(__file__).resolve().parents[1] / '_hub-native-sql-projection.py'
        contract = runpy.run_path(str(path))
        checkpoint = {'rawChildSha256': '1' * 64, 'rawChildByteSize': '100', 'checkpoints': [
            {'kind': 'manifest_append_checked_transaction', 'publicationId': 'synthetic-publication',
             'chunkIndex': '0'}]}
        spec = {'version': 1, 'kind': 'cloud_sql', 'runtime': self.runtime,
            'instanceName': 'projects/synthetic-project/instances/synthetic-database',
            'connectionName': 'synthetic-project:synthetic-region:synthetic-database',
            'database': 'synthetic_database', 'role': 'synthetic_reader',
            'serverAddress': '192.0.2.1', 'serverPort': 5432, 'deployment': 'synthetic-deployment',
            'collectorSourceSha256': '2' * 64, 'psqlExecutableSha256': '3' * 64,
            'firstUnixNanos': '1000000000', 'lastUnixNanos': '2000000000',
            'sourceChild': {key: checkpoint[key] for key in ('rawChildSha256', 'rawChildByteSize')}}
        spec['instance'] = self.exchange('cloud_sql_instance', {'name': spec['instanceName']},
            {'name': 'synthetic-database', 'project': 'synthetic-project',
             'connectionName': spec['connectionName'], 'ipAddresses': [{'ipAddress': '192.0.2.1'}]})
        row = {'publicationId': 'synthetic-publication', 'chunkIndex': 0, 'syntheticOnly': True}
        rows = {'database': spec['database'], 'databaseOid': '1', 'user': spec['role'],
            'serverAddress': spec['serverAddress'], 'serverPort': 5432, 'backendPid': 20,
            'readOnly': 'on', 'isolation': 'repeatable read', 'snapshot': '1:2:',
            'snapshotAt': '1970-01-01 00:00:01+00', 'observedAt': '1970-01-01 00:00:02+00',
            'role': {key: False for key in ('superuser', 'createDb', 'createRole', 'bypassRls')},
            'privileges': [{'table': key, 'select': True, 'mutate': False}
                for key in contract['NATIVE_SQL_TABLES']], 'admissions': [], 'chunks': [row]}
        query = contract['native_sql_query'](checkpoint['checkpoints'], spec['deployment'], spec['role']).encode()
        spec['query'], spec['rows'] = self.ref(query), self.ref(rows)
        pin = {'pid': 10, 'ownerUid': 1000, 'startTicks': '1',
               'executableSha256': spec['psqlExecutableSha256']}
        spec['readerReceipt'] = self.ref({'version': 1, 'exitCode': 0,
            'querySha256': spec['query']['sha256'], 'rowsSha256': spec['rows']['sha256'],
            'readerBefore': pin, 'readerAfter': pin,
            'collectorSourceSha256': spec['collectorSourceSha256'],
            'psqlExecutableSha256': spec['psqlExecutableSha256'],
            'backend': {'pid': rows['backendPid'], 'connectionName': spec['connectionName'],
                        'database': spec['database'], 'role': spec['role'], 'snapshot': rows['snapshot']},
            'beforeUnixNanos': '1100000000', 'afterUnixNanos': '1900000000',
            'sourceChild': spec['sourceChild']})
        codec_image = self.ref(row)
        spec['codecImages'] = {'admissions': self.ref(b''), 'chunks': [codec_image]}
        codec = {'codecProjection': {'sqlEvidenceSha256': codec_image['sha256']}}
        return spec, checkpoint, codec, contract

    def test_managed_snapshot_matches_images_without_prior_authority_or_bulk_total(self):
        spec, checkpoint, codec, contract = self.sql()
        result = custody.cloud_sql(spec, checkpoint, codec, self.readers, contract,
                                   self.runtime, self.synthetic_verifier)
        self.assertEqual(result['readerSnapshot'], '1:2:')
        self.assertIsNone(result['objectPayloadBytes'])
        self.assertTrue(result['missing'])
        # The VM default remains exact loopback, with no fabricated rewrite.
        with self.assertRaises(ValueError):
            contract['native_sql_rows'](self.read(spec['rows'], 512 * 1024), spec, checkpoint['checkpoints'])

    def test_managed_endpoint_null_privileges_or_substituted_query_refuses(self):
        for field, value in (('serverAddress', None), ('user', 'another_reader'),
                             ('readOnly', 'off'), ('backendPid', True)):
            spec, checkpoint, codec, contract = self.sql()
            rows = parse(self.read(spec['rows'], 512 * 1024))
            rows[field] = value
            spec['rows'] = self.ref(rows)
            with self.assertRaises(ValueError, msg=field):
                custody.cloud_sql(spec, checkpoint, codec, self.readers, contract,
                                   self.runtime, self.synthetic_verifier)
        spec, checkpoint, codec, contract = self.sql()
        spec['query'] = self.ref(b'SELECT 1;')
        with self.assertRaises(ValueError):
            custody.cloud_sql(spec, checkpoint, codec, self.readers, contract,
                               self.runtime, self.synthetic_verifier)

    def test_managed_reader_lifetime_backend_or_window_substitution_refuses(self):
        for mutate in ('process', 'backend', 'window', 'source'):
            spec, checkpoint, codec, contract = self.sql()
            receipt = parse(self.read(spec['readerReceipt'], 64 * 1024))
            if mutate == 'process':
                receipt['readerAfter']['startTicks'] = '2'
            elif mutate == 'backend':
                receipt['backend']['connectionName'] = 'synthetic-project:synthetic-region:another-database'
            elif mutate == 'window':
                receipt['afterUnixNanos'] = '3000000000'
            else:
                receipt['collectorSourceSha256'] = '4' * 64
            spec['readerReceipt'] = self.ref(receipt)
            with self.assertRaises(ValueError, msg=mutate):
                custody.cloud_sql(spec, checkpoint, codec, self.readers, contract,
                                   self.runtime, self.synthetic_verifier)


if __name__ == '__main__':
    unittest.main()
