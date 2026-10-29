"""Actual local Unix-socket stored-byte custody and independent checkpoint gates."""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import textwrap
import threading
import unittest


sys.dont_write_bytecode = True

MODULE = Path(__file__).with_name('_hub-external-mirror-functional.py')
spec = importlib.util.spec_from_file_location('mirror_client', MODULE)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class SocketInstallationTests(unittest.TestCase):
    def exchange(self, change=None, pin_change=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'control.socket'
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            listener.listen(1)
            listener.settimeout(3)
            body = b'{"functional":"signed test-only bytes"}'
            process_root = Path('/proc') / str(os.getpid())
            process = {
                'pid': os.getpid(), 'startTicks': (process_root / 'stat').read_text().rsplit(')', 1)[1].split()[19],
                'ownerUid': process_root.stat().st_uid,
                'executableSha256': hashlib.sha256((process_root / 'exe').read_bytes()).hexdigest(),
                'commandLineSha256': hashlib.sha256((process_root / 'cmdline').read_bytes()).hexdigest(),
            }
            if pin_change:
                pin_change(process)
            selected = {'process': process, 'socket': str(path), 'artifactBase64': base64.b64encode(body).decode(),
                'artifactSha256': hashlib.sha256(body).hexdigest(), 'key': 'controlled-external-mirror-v1:' + 'ab' * 32}
            received = []
            errors = []

            def serve():
                try:
                    with listener.accept()[0] as connection:
                        connection.settimeout(3)
                        raw = bytearray()
                        while True:
                            chunk = connection.recv(4096)
                            if not chunk:
                                break
                            raw.extend(chunk)
                        # A response is unavailable until the client half-closes.
                        received.append(bytes(raw))
                        request = json.loads(raw)
                        reply = {'version': 1, 'status': 'stored', 'key': request['key'],
                            'artifactSha256': request['artifactSha256'], 'byteSize': str(len(body)),
                            'runnerPid': os.getpid(), 'runnerStartTicks': selected['process']['startTicks'],
                            'artifactBase64': request['artifactBase64']}
                        if change:
                            change(reply)
                        connection.sendall(json.dumps(reply).encode() + b'\n')
                except (TimeoutError, OSError) as error:
                    errors.append(error)

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                namespace = {'selected': selected, '__name__': '__guest__'}
                import contextlib
                import io
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exec(compile(textwrap.dedent(client.MIRROR_FUNCTIONAL_STORE_PROGRAM), '<actual-guest-program>', 'exec'), namespace)
                result = json.loads(stdout.getvalue())
                self.assertEqual(received[0], Path(result['request']['file']).read_bytes())
                self.assertEqual(result['request']['sha256'], hashlib.sha256(received[0]).hexdigest())
                self.assertEqual(result['storedBytes']['artifactBase64'], selected['artifactBase64'])
                self.assertEqual(result['response']['sha256'], hashlib.sha256(Path(result['response']['file']).read_bytes()).hexdigest())
                return result
            finally:
                thread.join(4)
                listener.close()
                self.assertFalse(thread.is_alive())

    def test_actual_half_close_dispatch_and_exact_private_readback(self):
        self.exchange()

    def test_substituted_stored_bytes_refuse(self):
        with self.assertRaisesRegex(ValueError, 'readback or lifetime differs'):
            self.exchange(change=lambda reply: reply.update(artifactBase64=base64.b64encode(b'foreign').decode()))

    def test_extra_reply_field_refuses(self):
        with self.assertRaisesRegex(ValueError, 'readback or lifetime differs'):
            self.exchange(change=lambda reply: reply.update(businessAccepted=True))

    def test_changed_live_process_pin_refuses_before_socket(self):
        with self.assertRaisesRegex(ValueError, 'process changed'):
            self.exchange(pin_change=lambda pin: pin.update(startTicks='1'))

    def test_sign_requires_independent_explicit_candidate_sha_before_transport(self):
        with self.assertRaisesRegex(ValueError, 'review SHA is absent'):
            client.sign_mirror_functional(None, {}, 'selection', 'candidate', '', 'seed', 'public', 'output')


class BoundedReviewerInvocationTests(unittest.TestCase):
    def test_actual_child_output_is_bounded_before_retention(self):
        import contextlib
        import io

        def guest(machine, python, program, selected, timeout):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exec(compile(textwrap.dedent(program), '<actual-reviewer-program>', 'exec'), {'selected': selected})
            return stdout.getvalue()

        original = getattr(client, 'direct_guest_python', None)
        client.direct_guest_python = guest
        try:
            with tempfile.TemporaryDirectory() as directory:
                output = str(Path(directory) / 'result')
                with self.assertRaisesRegex(ValueError, 'bounded envelope'):
                    client._run_mirror_functional(None, {'python': sys.executable, 'reviewer': sys.executable},
                        ['-c', "print('x' * 100000)"], output)
                self.assertLessEqual(Path(output + '.review.stdout').stat().st_size, 65536)
                self.assertLessEqual(Path(output + '.review.stderr').stat().st_size, 65536)
        finally:
            if original is None:
                del client.direct_guest_python
            else:
                client.direct_guest_python = original


if __name__ == '__main__':
    unittest.main()
