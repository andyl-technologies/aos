"""Observe actual local owned PID exits and preserve producer failures."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_guest(machine, python, source, selected, **options):
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        exec(compile(textwrap.dedent(source), 'actual-local-fixture-process', 'exec'),
            {'selected': selected, 'json': json})
    return stream.getvalue()


def process_pin(child):
    proc = Path('/proc') / str(child.pid)
    fields = (proc / 'stat').read_text().rpartition(') ')[2].split()
    with (proc / 'exe').open('rb') as executable:
        digest = hashlib.file_digest(executable, 'sha256').hexdigest()
    return {'pid': child.pid, 'startTicks': fields[19], 'ownerUid': proc.stat().st_uid,
        'executableSha256': digest,
        'commandLineSha256': hashlib.sha256((proc / 'cmdline').read_bytes()).hexdigest(),
        'environmentSha256': hashlib.sha256((proc / 'environ').read_bytes()).hexdigest()}


class ExternalTeardownTests(unittest.TestCase):
    def test_pidfd_exit_and_changed_executable_refusal_use_the_actual_owned_child(self):
        process = load('_hub-external-oci-process')
        process.direct_guest_python = local_guest
        with tempfile.TemporaryDirectory() as root:
            child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                pin = process_pin(child)
                with self.assertRaises(ValueError):
                    process.stop_external_oci_process(None, {'python': sys.executable}, root,
                        {**pin, 'executableSha256': '0' * 64}, 'changed-original')
                self.assertIsNone(child.poll())
                self.assertFalse((Path(root) / 'changed-original-stop.json').exists())

                receipt = process.stop_external_oci_process(None, {'python': sys.executable}, root,
                    pin, 'owned-original')

                self.assertTrue(receipt['pidfdReadable'])
                self.assertEqual(receipt['pid'], child.pid)
                self.assertFalse(receipt['persistenceRemoved'])
                self.assertEqual(child.wait(timeout=5), -15)
                self.assertEqual(json.loads((Path(root) / 'owned-original-stop.json').read_bytes()), receipt)
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=5)

    def test_exit_failure_is_retained_without_masking_the_active_producer_exception(self):
        teardown = load('_hub-external-oci-teardown')
        retained = []
        teardown.stop_external_oci_process = lambda *arguments: (_ for _ in ()).throw(ValueError('controlled refusal'))
        teardown.retain_direct_flow = lambda name, value: retained.append((name, value))
        coordinates = {'runId': 'a' * 32, 'nativeRoot': '/private/native',
            'workerRoot': '/private/worker', 'clientRoot': '/private/client'}
        ownership = {'prepared': {'coordinates': coordinates}, 'processes': {'worker': {'pid': 1}}}
        error = RuntimeError('original producer failure')

        report = teardown.teardown_external_oci_pair(None, object(), object(), {}, ownership, error)

        self.assertEqual(report['unresolvedExits'][0]['role'], 'worker')
        self.assertEqual(str(error), 'original producer failure')
        self.assertEqual(len(error.__notes__), 1)
        self.assertEqual(len(retained), 1)
        self.assertIsNone(report['providerEffectsSettled'])
        with self.assertRaises(RuntimeError):
            teardown.teardown_external_oci_pair(None, object(), object(), {}, ownership)


if __name__ == '__main__':
    unittest.main()
