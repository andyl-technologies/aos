"""Actual process custody tests without invoking physical cleanup or Rust auth."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


specification = importlib.util.spec_from_file_location(
    "cleanup_authentication_listener", Path(__file__).with_name("_hub-managed-cleanup-loss.py"))
listener = importlib.util.module_from_spec(specification)
specification.loader.exec_module(listener)


class AuthenticationCustody(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="aos-cleanup-auth-custody-test-")
        self.root = Path(self.directory.name)
        os.chmod(self.root, 0o700)
        with Path("/proc/self/exe").open("rb") as executable:
            self.executable_sha = hashlib.file_digest(executable, "sha256").hexdigest()
        self.input_ref = listener.retain(self.root / "input.private.json", b"{}")

    def tearDown(self):
        self.directory.cleanup()

    def invoke(self, source, expected=None):
        # This is a genuine separate child with no provider, SQL or Rust-helper
        # authority. Its argv explicitly records the Python source-only test.
        startup = """
import json,os,time
from pathlib import Path
root=Path(os.environ['AOS_MANAGED_CLEANUP_STARTUP_ROOT'])
nonce=os.environ['AOS_MANAGED_CLEANUP_STARTUP_NONCE']
ready={'version':1,'nonce':nonce,'pid':os.getpid(),'scope':'managed_cleanup_before_input'}
writing=root/'authentication-ready-writing.private.json'
fd=os.open(writing,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
os.write(fd,json.dumps(ready).encode());os.close(fd)
os.rename(writing,root/'authentication-ready.private.json')
release=root/'authentication-release.private.json'
stop=time.monotonic()+10
while not release.exists():
    if time.monotonic()>stop: raise RuntimeError('test startup release timed out')
    time.sleep(.001)
assert json.loads(release.read_bytes())=={'version':1,'nonce':nonce}
"""
        arguments = [sys.executable, "-c", startup + "\n" + source]
        return listener.observe_authentication_process(
            {"nativeHelperSha256": expected or self.executable_sha}, self.root,
            self.input_ref, arguments, dict(os.environ, AOS_CUSTODY_TEST="source-only"))

    def test_actual_child_identity_raw_metadata_and_stdout_are_retained(self):
        reference, invocation = self.invoke("print('actual child output')")
        self.assertTrue(invocation["completeProcessCustody"])
        self.assertEqual(invocation["exitCode"], 0)
        self.assertEqual(invocation["scope"], "managed_cleanup_upstream_authentication_helper")
        self.assertIsNone(invocation["nativeTransportObservation"])
        pin = invocation["helperProcess"]
        self.assertEqual(pin["ownerUid"], os.getuid())
        self.assertEqual(pin["executableSha256"], self.executable_sha)
        command = Path(pin["commandLine"]["path"]).read_bytes()
        environment = Path(pin["environment"]["path"]).read_bytes()
        self.assertEqual(hashlib.sha256(command).hexdigest(), pin["commandLineSha256"])
        self.assertEqual(hashlib.sha256(environment).hexdigest(), pin["environmentSha256"])
        self.assertIn(b"AOS_CUSTODY_TEST=source-only\0", environment)
        self.assertEqual(Path(invocation["stdout"]["path"]).read_bytes(), b"actual child output\n")
        self.assertEqual(hashlib.sha256(Path(reference["path"]).read_bytes()).hexdigest(), reference["sha256"])
        self.assertLess(int(invocation["started"]["monotonicNs"]), int(invocation["finished"]["monotonicNs"]))
        self.assertIsNone(invocation["output"])
        self.assertTrue(invocation["completeOutputCollection"])
        self.assertEqual(invocation["outputOverflow"], {"stdout": False, "stderr": False})
        self.assertIsNotNone(invocation["startupReady"])
        self.assertIsNotNone(invocation["startupRelease"])

    def test_wrong_executable_pin_retains_incomplete_process_and_owned_failure(self):
        _, invocation = self.invoke("print('must not execute')", expected="0" * 64)
        self.assertFalse(invocation["completeProcessCustody"])
        self.assertIsNone(invocation["helperProcess"])
        self.assertEqual(invocation["failureKind"], "ValueError")
        self.assertNotEqual(invocation["exitCode"], 0)
        self.assertIsNone(invocation["nativeTransportObservation"])

    def test_actual_nonzero_child_exit_has_custody_but_never_authentication_success(self):
        _, invocation = self.invoke("import sys; print('refused',file=sys.stderr); sys.exit(7)")
        self.assertTrue(invocation["completeProcessCustody"])
        self.assertEqual(invocation["exitCode"], 7)
        self.assertEqual(Path(invocation["stderr"]["path"]).read_bytes(), b"refused\n")
        self.assertIsNone(invocation["nativeTransportObservation"])

    def test_private_output_is_a_hashed_upstream_metadata_reference_only(self):
        path = str(self.root / "authenticated.json")
        source = ("import os; "
                  f"fd=os.open({path!r},os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); "
                  "os.write(fd,b'{\"sourceOnlyTest\":true}'); os.close(fd)")
        _, invocation = self.invoke(source)
        body = Path(invocation["output"]["path"]).read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(), invocation["output"]["sha256"])
        self.assertEqual(len(body), invocation["output"]["byteSize"])
        self.assertIsNone(invocation["outputErrorKind"])
        self.assertIsNone(invocation["nativeTransportObservation"])

    def test_overflow_retains_bounded_prefix_and_refuses_positive_custody(self):
        _, invocation = self.invoke("import sys; sys.stdout.write('x'*100000);sys.stdout.flush()")
        self.assertFalse(invocation["completeProcessCustody"])
        self.assertFalse(invocation["completeOutputCollection"])
        self.assertEqual(invocation["failureKind"], "OutputOverflow")
        self.assertTrue(invocation["outputOverflow"]["stdout"])
        self.assertEqual(len(Path(invocation["stdout"]["path"]).read_bytes()), 65536)
        self.assertIsNotNone(invocation["helperProcess"])

    def test_short_lived_child_without_handshake_never_borrows_an_exited_pin(self):
        _, invocation = listener.observe_authentication_process(
            {"nativeHelperSha256": self.executable_sha}, self.root, self.input_ref,
            [sys.executable, "-c", "print('finished without handshake')"], dict(os.environ))
        self.assertFalse(invocation["completeProcessCustody"])
        self.assertIsNone(invocation["helperProcess"])
        self.assertIsNone(invocation["startupReady"])
        self.assertEqual(invocation["failureKind"], "ValueError")


if __name__ == "__main__":
    unittest.main()
