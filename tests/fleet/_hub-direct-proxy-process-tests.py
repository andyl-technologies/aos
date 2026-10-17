"""Exact Linux Nginx title observations without a runtime serving claim."""

import ast
import base64
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).with_name('_hub-direct-storage-boundary.py')
SCOPE = {}
exec(compile(SOURCE.read_bytes(), str(SOURCE), 'exec'), SCOPE)
exec(SCOPE['DIRECT_NGINX_PROCESS_OBSERVATION'], SCOPE)


class NginxProcessObservationTests(unittest.TestCase):
    def setUp(self):
        self.arguments = ['/nix/store/fixture-nginx/bin/nginx', '-e', '/private/bootstrap.log',
            '-c', '/private/nginx.conf', '-p', '/private/', '-g', 'daemon off;']
        self.title = SCOPE['nginx_master_title'](self.arguments).encode()

    def test_complete_master_title_keeps_invocation_and_exact_raw_bytes(self):
        raw = self.title + b'\0' * 17
        observed = SCOPE['nginx_observed_command'](raw, self.arguments)

        self.assertEqual(observed['invocationArguments'], self.arguments)
        self.assertEqual(observed['expectedMasterTitle'], self.title.decode())
        self.assertEqual(observed['commandLineSha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(observed['commandLineBytes'], str(len(raw)))
        self.assertEqual(observed['invocationObservationMode'], 'nginx_linux_master_title')

    def test_original_argv_truncated_title_or_nonzero_suffix_refuses(self):
        for raw in (b'\0'.join(value.encode() for value in self.arguments) + b'\0',
                self.title[:-1] + b'\0', self.title, self.title + b'\0extra\0',
                b'nginx: worker process\0', self.title + b'\0' * 65536):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                SCOPE['nginx_observed_command'](raw, self.arguments)

    def test_foreign_configuration_or_foreground_option_refuses(self):
        for changed in (self.arguments[:-1] + ['daemon on;'],
                self.arguments[:4] + ['/other/nginx.conf'] + self.arguments[5:]):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                SCOPE['nginx_observed_command'](self.title + b'\0', changed)

    def test_padding_changes_keep_a_distinct_lifetime_identity(self):
        first = SCOPE['nginx_observed_command'](self.title + b'\0', self.arguments)
        second = SCOPE['nginx_observed_command'](self.title + b'\0\0', self.arguments)

        self.assertEqual(first['expectedMasterTitle'], second['expectedMasterTitle'])
        self.assertNotEqual(first['commandLineSha256'], second['commandLineSha256'])
        self.assertNotEqual(first['commandLineBytes'], second['commandLineBytes'])


class GuestProgramRenderingTests(unittest.TestCase):
    def setUp(self):
        self.renderer = {}
        lifecycle = SOURCE.with_name('_hub-direct-worker-lifecycle.py')
        exec(compile(lifecycle.read_bytes(), str(lifecycle), 'exec'), self.renderer)

        self.managed = {}
        managed = SOURCE.with_name('_hub-managed-storage-window.py')
        exec(compile(managed.read_bytes(), str(managed), 'exec'), self.managed)
        self.managed['DIRECT_NGINX_PROCESS_OBSERVATION'] = SCOPE['DIRECT_NGINX_PROCESS_OBSERVATION']

        self.python = '/nix/store/fixture-python/bin/python3'
        self.native = object()
        self.worker = object()
        self.pin = {name: 'fixture' for name in self.managed['MANAGED_PROCESS_PIN_FIELDS']}
        self.pin.update(version=1, pid=123, ownerUid=0,
            invocationObservationMode='nginx_linux_master_title',
            arguments=['/nix/store/fixture-nginx/bin/nginx', '-c', '/private/nginx.conf'],
            configurationFile='/private/nginx.conf', configurationSha256='a' * 64)

    def capture_programs(self, scope, action):
        """Compile actual renderer output without executing a guest command."""
        captured = []

        def private_command(machine, command, timeout=60):
            header, program = command.split('\n', 1)
            self.assertEqual(header, self.python + " - <<'DIRECT_PRIVATE_ACTION'")
            ending = '\nDIRECT_PRIVATE_ACTION\n'
            self.assertTrue(program.endswith(ending))
            program = program.removesuffix(ending)

            # Keep the same private renderer and verify its final shell payload.
            # Executing the payload would inspect processes or start a proxy.
            tree = ast.parse(program)
            compile(tree, '<captured-private-guest-program>', 'exec')
            definitions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
            self.assertEqual(definitions, {'nginx_master_title', 'nginx_observed_command'})
            selected = next(node for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'selected'
                    for target in node.targets))
            encoded = selected.value.args[0].args[0].value
            document = json.loads(base64.b64decode(encoded, validate=True))
            captured.append({'machine': machine, 'timeout': timeout, 'selected': document})
            return '{}'

        with patch.dict(self.renderer, private_guest_command=private_command), patch.dict(scope,
                direct_guest_python=self.renderer['direct_guest_python'],
                retain_direct_flow=lambda *arguments: None):
            action()
        return captured

    def test_proxy_startup_compiles_the_actual_private_guest_program(self):
        tools = {'python': self.python, 'nginx': '/nix/store/fixture-nginx/bin/nginx'}
        captured = self.capture_programs(SCOPE, lambda: SCOPE['start_direct_boundary_proxy'](
            self.worker, tools, '/private/proxy', '/private/source.conf', ['/private/bodies']))

        self.assertEqual(len(captured), 1)
        self.assertIs(captured[0]['machine'], self.worker)
        self.assertEqual(captured[0]['timeout'], 45)
        self.assertEqual(captured[0]['selected'], {'root': '/private/proxy',
            'configuration': '/private/source.conf', 'bodyRoots': ['/private/bodies'],
            'nginx': tools['nginx'], 'prepareOnly': False})

    def test_proxy_lifetimes_compile_for_both_selected_machines(self):
        tools = {'python': self.python,
            'storageBoundaryInstallation': {'nativeProxy': self.pin, 'workerProxy': self.pin}}
        captured = self.capture_programs(SCOPE, lambda: SCOPE['observe_direct_boundary_lifetimes'](
            self.native, self.worker, tools, 'baseline-start'))

        self.assertEqual([row['machine'] for row in captured], [self.native, self.worker])
        self.assertEqual([row['timeout'] for row in captured], [30, 30])
        self.assertTrue(all(row['selected'] == self.pin for row in captured))

    def test_managed_process_compiles_the_actual_private_guest_program(self):
        captured = self.capture_programs(self.managed, lambda: self.managed['observe_managed_process'](
            self.worker, {'python': self.python}, self.pin))

        self.assertEqual(len(captured), 1)
        self.assertIs(captured[0]['machine'], self.worker)
        self.assertEqual(captured[0]['timeout'], 30)
        self.assertEqual(captured[0]['selected'], self.pin)



if __name__ == '__main__':
    unittest.main()
