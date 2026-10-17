"""Actual child process custody for separate Native helper observations."""

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


specification = importlib.util.spec_from_file_location(
    'cleanup_observation_runtime', Path(__file__).with_name('_hub-managed-cleanup-runtime.py'))
runtime = importlib.util.module_from_spec(specification)
specification.loader.exec_module(runtime)


class InvocationCustody(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='managed-cleanup-process-test-')
        self.root = Path(self.directory.name)
        self.child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        # This is the real executable selected for this source-only child test.
        with Path('/proc/self/exe').open('rb') as source:
            self.executable_sha = hashlib.file_digest(source, 'sha256').hexdigest()

    def tearDown(self):
        if self.child.poll() is None:
            self.child.kill()
        self.child.wait()
        self.directory.cleanup()

    def test_actual_child_lifetime_and_raw_private_metadata_are_retained(self):
        pin = runtime.helper_process(self.child, self.root, self.executable_sha)
        self.assertEqual(pin['pid'], self.child.pid)
        self.assertEqual(pin['ownerUid'], os.getuid())
        self.assertEqual(pin['executableSha256'], self.executable_sha)
        self.assertEqual(runtime.process_identity(pin), Path('/proc') / str(self.child.pid))
        for field, digest in (('commandLine', 'commandLineSha256'), ('environment', 'environmentSha256')):
            body = runtime.private(pin[field]['path'], 65536)
            self.assertEqual(hashlib.sha256(body).hexdigest(), pin[digest])
            self.assertEqual(pin[field]['sha256'], pin[digest])
            self.assertEqual(len(body), pin[field]['byteSize'])

    def test_wrong_selected_executable_refuses_before_metadata_receipts(self):
        with self.assertRaisesRegex(ValueError, 'executable differs'):
            runtime.helper_process(self.child, self.root, '0' * 64)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_other_process_cannot_borrow_the_selected_child_lifetime(self):
        pin = runtime.helper_process(self.child, self.root, self.executable_sha)
        changed = {**pin, 'startTicks': str(int(pin['startTicks']) + 1)}
        with self.assertRaisesRegex(ValueError, 'lifetime differs'):
            runtime.process_identity(changed)


if __name__ == '__main__':
    unittest.main()
