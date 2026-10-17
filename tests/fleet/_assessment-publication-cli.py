# Production CLI publication reads against a closed Connect-JSON fixture.
# The database, publication guards and IAM are qualified independently.

import base64
import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

root = Path(sys.argv[1])
binary = Path(sys.argv[2])
calls = []
document = {}


def digest(domain, value):
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    return 'sha256:' + hashlib.sha256(domain.encode() + bytes([0]) + encoded).hexdigest()


def unknown_outputs(catalog_digit='a'):
    scope = 'public-fixture-registry-incarnation'
    publication = {
        'release': {
            'release': '1.0.0',
            'sourceCommit': 'public-fixture-commit',
            'verifiedTagOid': 'public-fixture-tag',
        },
        'catalogDigest': 'sha256:' + catalog_digit * 64,
        'snapshotId': 'public-fixture-snapshot',
        'manifestDigest': 'sha256:' + 'b' * 64,
    }
    commitment = digest('aos.assessment-publication-context/v1', [scope, publication])
    outputs = []
    for platform in ['x86_64-linux', 'aarch64-linux']:
        name = 'fixture'
        version = '1.2.0'
        path = '/nix/store/' + 'a' * 32 + '-fixture-1.2.0'
        outputs.append({
            'outputRef': digest('aos.assessment-unsupported-output/v1', [commitment, name, version, platform, path]),
            'packageName': name,
            'version': version,
            'platform': platform,
            'storePath': path,
        })
    outputs.sort(key=lambda output: output['outputRef'])
    return {
        'schema': 'aos.assessment-publication-status/v1',
        'resourceScope': scope,
        'asOf': '2026-10-10T00:00:00Z',
        'availability': {
            'state': 'unassessable',
            'publication': publication,
            'unsupportedCount': len(outputs),
        },
        'publicationDigest': commitment,
        'unsupportedOutputs': outputs,
    }


class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def do_POST(self):
        assert self.path == '/aos.hub.v1.AssessmentService/GetPublicationStatus'
        assert self.headers['Authorization'] == 'Bearer public-fixture-token'
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert set(request) == {'registrySlug', 'documentJson'}
        assert request['registrySlug'] == 'fixture'
        query = json.loads(base64.b64decode(request['documentJson']))
        assert query['schema'] == 'aos.assessment-publication-query/v1'
        calls.append(query)
        encoded = json.dumps({
            'documentJson': base64.b64encode(json.dumps(document).encode()).decode(),
        }).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory(prefix='aos-assessment-publication-cli-') as directory:
        environment = os.environ.copy()
        environment.update({
            'XDG_CONFIG_HOME': str(Path(directory) / 'config'),
            'XDG_STATE_HOME': str(Path(directory) / 'state'),
            'AOS_ROOT': str(root),
        })

        def run(arguments=(), okay=True):
            result = subprocess.run([
                str(binary), '--json', 'hub', 'maintain', 'publication',
                '--registry', 'fixture', '--hub', f'http://127.0.0.1:{server.server_port}',
                '--token', 'public-fixture-token', *arguments,
            ], cwd=root, env=environment, capture_output=True, text=True, timeout=30)
            assert (result.returncode == 0) == okay, (result.stdout, result.stderr)
            if okay:
                response = json.loads(result.stdout)
                assert response['kind'] == 'assessment-publication'
                assert response['data'] == document
                return response['data']

        document = {
            'schema': 'aos.assessment-publication-status/v1',
            'resourceScope': 'public-fixture-registry-incarnation',
            'asOf': '2026-10-10T00:00:00Z',
            'availability': {'state': 'no-publication'},
            'unsupportedOutputs': [],
        }
        run()
        release = unknown_outputs()['availability']['publication']['release']
        for state in ['awaiting-projection', 'invalid-projection']:
            document['availability'] = {'state': state, 'release': release}
            run()

        complete = unknown_outputs()
        document = copy.deepcopy(complete)
        document['unsupportedOutputs'] = complete['unsupportedOutputs'][:1]
        document['nextOutput'] = document['unsupportedOutputs'][0]['outputRef']
        first = run(['--limit', '1'])
        continuation = [
            '--limit', '1', '--after-output', first['nextOutput'],
            '--publication-digest', first['publicationDigest'],
            '--resource-scope', first['resourceScope'],
        ]
        document = copy.deepcopy(complete)
        document['unsupportedOutputs'] = complete['unsupportedOutputs'][1:]
        run(continuation)
        assert calls[-1]['afterOutput'] == first['nextOutput']
        assert calls[-1]['publicationDigest'] == first['publicationDigest']

        count = len(calls)
        run(['--after-output', first['nextOutput']], okay=False)
        assert len(calls) == count
        document = unknown_outputs('c')
        document['unsupportedOutputs'] = document['unsupportedOutputs'][:1]
        run(continuation, okay=False)
        document = copy.deepcopy(complete)
        run(['--limit', '1'], okay=False)
        document['unsupportedOutputs'][0]['version'] = '9.9.9'
        run(okay=False)

        document = copy.deepcopy(complete)
        document['availability'].update({
            'state': 'ready', 'inventoryDigest': 'sha256:' + 'd' * 64, 'declaredOutputs': 1,
        })
        run()
        document['availability']['activeInventoryRevision'] = 1
        run()
        print('PASS: actual CLI publication availability, exact pages and response refusal')
finally:
    server.shutdown()
    server.server_close()
