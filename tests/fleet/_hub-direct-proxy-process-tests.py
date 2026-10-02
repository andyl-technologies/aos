"""Exact Linux Nginx title observations without a runtime serving claim."""

import hashlib
from pathlib import Path
import unittest


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



if __name__ == '__main__':
    unittest.main()
