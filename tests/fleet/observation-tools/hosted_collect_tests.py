"""Exercise local synthetic TLS and actual supervisor refusals, not a provider.

The focused gate selects AOS Python/OpenSSL and an immutable copy of the actual
collector. Certificates and authorization inputs below are disposable fixtures.
No Google API, database, resource, credential, or runtime is accessed.
"""

import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

import hosted_collect as collector


def pin(path):
    path = Path(path).resolve(strict=True)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'file': str(path), 'sha256': digest, 'byteSize': str(path.stat().st_size)}


class CollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='aos-hosted-collector-synthetic-')
        cls.root = Path(cls.temporary.name)
        cls.openssl = Path(os.environ['AOS_HOSTED_COLLECT_TEST_OPENSSL']).resolve(strict=True)
        if not str(cls.openssl).startswith('/nix/store/'):
            raise ValueError('Synthetic gate requires selected AOS OpenSSL')
        cls.certificate, cls.key = cls.root / 'certificate.pem', cls.root / 'key.pem'
        process = subprocess.run([str(cls.openssl), 'req', '-x509', '-newkey', 'rsa:2048',
            '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
            '-keyout', str(cls.key), '-out', str(cls.certificate)],
            stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=20)
        if process.returncode:
            raise ValueError('Synthetic certificate creation failed')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.requests = []
        self.status = 200
        self.body = b'{"syntheticOnly":true}'
        self.length = len(self.body)
        parent = self

        class Reply(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                parent.requests.append(self.rfile.read(int(self.headers['Content-Length'])))
                self.send_response(parent.status)
                self.send_header('Content-Length', str(parent.length))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(parent.body)
                self.close_connection = True

        self.server = HTTPServer(('127.0.0.1', 0), Reply)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certificate, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.host = 'localhost:' + str(self.server.server_port)
        self.deadline = {'monotonic': time.monotonic() + 10, 'unix': time.time() + 10}

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())

    def read(self, host=None, maximum=1024):
        return collector.https_read(host or self.host, '/synthetic-read', 'POST', b'{}',
                                    'synthetic-not-a-credential', self.certificate,
                                    self.deadline, maximum)

    def test_checked_local_tls_consumes_exact_body_and_preserves_wire_request(self):
        raw, transport = self.read()
        self.assertEqual(raw, self.body)
        self.assertEqual(self.requests, [b'{}'])
        self.assertEqual(transport['wireRequestSha256'], collector.sha(b'{}'))
        self.assertEqual(transport['responseBytes'], str(len(raw)))
        self.assertTrue(transport['eof'])
        self.assertNotIn('Authorization', json.dumps(transport))

    def test_wrong_hostname_status_partial_body_and_overflow_refuse(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.read('127.0.0.1:' + str(self.server.server_port))
        self.assertEqual(self.requests, [])
        for status in (302, 401, 500):
            self.status = status
            with self.assertRaises(ValueError):
                self.read()
        self.status = 200
        self.length += 1
        with self.assertRaises((ValueError, http.client.IncompleteRead, ssl.SSLError)):
            self.read()
        self.length -= 1
        with self.assertRaises(ValueError):
            self.read(maximum=1)

    def test_original_cutoff_refuses_before_request(self):
        self.deadline['monotonic'] = time.monotonic() - 1
        with self.assertRaises(ValueError):
            self.read()
        self.assertEqual(self.requests, [])

    def test_exact_readonly_route_map_refuses_other_hosts_or_mutations(self):
        scope = {'serviceName': 'projects/synthetic-project/locations/synthetic-region/services/synthetic-service'}
        route = collector.destination('cloud_run_service', {'name': scope['serviceName']}, scope)
        self.assertEqual(route, ('run.googleapis.com', '/v2/' + scope['serviceName'], 'GET', b''))
        for operation, request in (('service_delete', {'name': scope['serviceName']}),
                                   ('cloud_run_service', {'name': 'https://unselected.example'}),
                                   ('cloud_run_service', {'name': scope['serviceName'], 'authenticated': True})):
            with self.assertRaises(ValueError):
                collector.destination(operation, request, scope)

    def test_disk_receipt_cannot_install_authenticated_observation(self):
        self.assertIsNone(collector.unavailable_verifier('cloud_run_service', b'{}', b'{}',
            b'{"authenticated":true}', {}))
        with self.assertRaises(ValueError):
            collector.immutable(pin(self.certificate))

    def test_private_retention_is_create_only_and_preserves_exact_images(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            refs = collector.retain_images(root, b'{}', self.body, b'{"syntheticOnly":true}')
            self.assertEqual(Path(refs['response']['file']).read_bytes(), self.body)
            self.assertEqual(refs['response']['sha256'], collector.sha(self.body))
            self.assertEqual(Path(refs['response']['file']).stat().st_nlink, 1)
            with self.assertRaises(FileExistsError):
                collector.retain_images(root, b'changed', b'changed', b'changed')
            self.assertEqual(Path(refs['request']['file']).read_bytes(), b'{}')

    def test_actual_installed_supervisor_refuses_before_network_and_retains_failure(self):
        installed = Path(os.environ['AOS_HOSTED_COLLECT_TEST_PACKAGE']).resolve(strict=True)
        path = installed / 'hosted_collect.py'
        spec = importlib.util.spec_from_file_location('synthetic_installed_collector', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        deadline = {'monotonic': time.monotonic() + 15, 'unix': time.time() + 15}
        supervisor = module.Supervisor(pin(Path(os.environ['AOS_HOSTED_COLLECT_TEST_PYTHON'])),
            pin(path), pin(installed / 'synthetic-ca.pem'), deadline)
        request = b'{"name":"projects/synthetic-project/locations/synthetic-region/services/synthetic-service"}'
        scope = {'serviceName': json.loads(request)['name']}
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / 'synthetic-invalid-input'
            token.write_bytes(b'not a token')
            token.chmod(0o600)
            descriptor = os.open(token, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(ValueError):
                    supervisor.collect('cloud_run_service', request, scope, descriptor, 1024)
            finally:
                os.close(descriptor)
        failures = supervisor.failures()
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]['requestSha256'], module.sha(request))
        self.assertEqual(failures[0]['outcome'], 'refused_or_unknown')
        self.assertEqual(failures[0]['observedExitCode'], 1)
        self.assertIsNone(supervisor.verify('cloud_run_service', request, b'{}',
            b'{"authenticated":true}', scope))
        with self.assertRaises(FileNotFoundError):
            module.pin_process(failures[0]['child']['pid'])


if __name__ == '__main__':
    unittest.main()
