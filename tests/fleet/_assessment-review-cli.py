# Exercises the production CLI against a closed Connect-JSON protocol fixture.
# Database admission and IAM are qualified independently. This boundary fixture
# verifies exact requests, retained confirmation and refusal before HTTP.

import base64
import copy
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import threading

root = Path(sys.argv[1])
binary = Path(sys.argv[2])
calls = []
retained = {}


class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert self.headers['Authorization'] == 'Bearer public-fixture-token'
        calls.append((self.path, request))

        kind = 'schedule' if self.path.endswith('Schedule') else 'subscription'
        if '/PlanWrite' in self.path:
            assert set(request) == {
                'registrySlug', 'documentJson', 'expectedResourceVersion', 'idempotencyKey'
            }, request
            document = json.loads(base64.b64decode(request['documentJson']))
            assert request['expectedResourceVersion'] == str(document['expectedRevision'])
            assert request['registrySlug'] == 'fixture'
            retained[kind] = copy.deepcopy(document)
            response = {'plan': {
                'planId': f'exact-{kind}',
                'confirmationHash': 'a' * 64,
                'expiresAt': '1790000000',
                'effects': [json.dumps(document)],
                'warnings': [],
            }}
        else:
            assert set(request) == {'planId', 'confirmationHash', 'idempotencyKey'}, request
            assert request['planId'] == f'exact-{kind}' and request['confirmationHash'] == 'a' * 64
            assert request['idempotencyKey'] == 'exact-apply'
            document = copy.deepcopy(retained[kind])
            document['schema'] = f'aos.assessment-{kind}/v1'
            document['revision'] = document.pop('expectedRevision') + 1
            document['authorityExpiresAt'] = '2027-01-01T00:00:00Z'
            if kind == 'schedule':
                document['nextDueAt'] = '2026-10-10T00:00:00Z'
            response = {'documentJson': base64.b64encode(json.dumps(document).encode()).decode()}

        encoded = json.dumps(response).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    with tempfile.TemporaryDirectory(prefix='aos-assessment-review-cli-') as directory:
        state = Path(directory)
        environment = os.environ.copy()
        environment.update({
            'XDG_CONFIG_HOME': str(state / 'config'),
            'XDG_STATE_HOME': str(state / 'state'),
            'AOS_ROOT': str(root),
        })

        def run(arguments, okay=True):
            command = [
                str(binary), '--json', 'hub', 'maintain', *arguments,
                '--hub', f'http://127.0.0.1:{server.server_port}',
                '--token', 'public-fixture-token',
            ]
            result = subprocess.run(
                command, env=environment, cwd=root, text=True,
                capture_output=True, timeout=30,
            )
            if okay:
                assert result.returncode == 0, result.stderr
                return json.loads(result.stdout)
            assert result.returncode != 0

        schedule = {'schema': 'aos.assessment-schedule-write/v1',
         'resourceScope': 'registry-instance-1',
         'scheduleId': 'security-updates',
         'expectedRevision': 0,
         'enabled': True,
         'configuration': {'schema': 'aos.assessment-schedule-configuration/v1',
                           'packages': ['fixture/example'],
                           'profiles': ['updates'],
                           'freshness': 'offline',
                           'cadenceSeconds': 60,
                           'reviewExpiresAt': '2027-01-01T00:00:00Z',
                           'limits': {'subjects': 10000,
                                      'components': 100000,
                                      'edges': 100000,
                                      'providerRequests': 4096,
                                      'tasks': 8192,
                                      'normalizedBytes': 268435456,
                                      'wallSeconds': 3600}}}

        subscription = {'schema': 'aos.assessment-subscription-write/v1',
         'resourceScope': 'registry-instance-1',
         'subscriptionId': 'security-updates',
         'expectedRevision': 0,
         'enabled': True,
         'configuration': {'schema': 'aos.assessment-notification-configuration/v1',
                           'events': ['scan-completed'],
                           'families': ['vulnerability'],
                           'threshold': 'all-attention',
                           'frequency': {'kind': 'immediate'},
                           'destinationReference': 'webhook:42',
                           'destinationRevision': 1,
                           'destinationDigest': 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                           'reviewExpiresAt': '2027-01-01T00:00:00Z'}}

        for kind, document in [('schedule', schedule), ('subscription', subscription)]:
            path = state / f'{kind}.json'
            path.write_text(json.dumps(document))
            before = len(calls)
            plan = run([kind, '--registry', 'fixture', '--request', str(path), '--idempotency-key', 'exact-plan'])
            assert len(calls) == before + 1, 'planning must not apply'
            assert plan['kind'] == 'assessment-configuration-plan'
            assert retained[kind] == document

            # The input file cannot replace the already reviewed configuration.
            altered = copy.deepcopy(document)
            altered['enabled'] = False
            path.write_text(json.dumps(altered))
            apply_arguments = [
                f'apply-{kind}', '--plan-id', plan['data']['planId'],
                '--confirmation-hash', plan['data']['confirmationHash'],
                '--idempotency-key', 'exact-apply',
            ]
            applied = run(apply_arguments)
            assert applied['data']['enabled'] is True, 'apply must use retained configuration'
            assert applied['data']['configuration'] == document['configuration']
            assert applied['data']['revision'] == 1
            assert len(calls) == before + 2

            # Incomplete confirmation or mutable input fails before HTTP.
            run([f'apply-{kind}', '--plan-id', f'exact-{kind}', '--idempotency-key', 'exact-apply'], okay=False)
            run([*apply_arguments, '--request', str(path)], okay=False)
            assert len(calls) == before + 2, 'invalid apply inputs must not make HTTP calls'
        print('PASS: actual CLI plan/apply RPC separation, exact frozen configuration, and refusal before HTTP')
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
