"""Exercise real manifest setup ordering without transport or provider effects."""

import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("queue_setup", Path(__file__).with_name("_hub-direct-queue-fault-setup.py"))
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class PublicationSetupTests(unittest.TestCase):
    def test_ready_publisher_unlink_race_returns_pending_then_strict_same_owned_final(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = Path('/proc') / str(os.getpid())
            fields = (proc / 'stat').read_text().rpartition(') ')[2].split()
            pin = {"pid": os.getpid(), "ownerUid": proc.stat().st_uid, "startTicks": fields[19],
                   "commandLineSha256": hashlib.sha256((proc / 'cmdline').read_bytes()).hexdigest(),
                   "environmentSha256": hashlib.sha256((proc / 'environ').read_bytes()).hexdigest(),
                   "executableSha256": hashlib.sha256((proc / 'exe').read_bytes()).hexdigest()}
            configuration = root / 'configuration.json'
            configuration.write_bytes(b'{"version":1}')
            configuration.chmod(0o600)
            listener = Path(__file__).with_name('_hub-direct-queue-fault-get.mjs')
            listener_sha = hashlib.sha256(listener.read_bytes()).hexdigest()
            ready = {"version": 1, "pid": pin["pid"], "ownerUid": pin["ownerUid"],
                     "startTicks": pin["startTicks"], "listenerSourceSha256": listener_sha,
                     "listenAddress": "127.0.0.1:3904", "upstreamAddress": "127.0.0.1:3903",
                     "controlSocket": str(root / 'control.sock')}
            pending = root / 'ready.pending'
            pending.write_bytes(json.dumps(ready).encode())
            pending.chmod(0o600)
            os.link(pending, root / 'ready.json')
            installation = {"root": str(root), "process": pin, "configurationFile": str(configuration),
                            "configurationSha256": hashlib.sha256(configuration.read_bytes()).hexdigest(),
                            "listenerFile": str(listener), "listenerSourceSha256": listener_sha}
            def guest(machine, python, code, selected, timeout):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    try:
                        exec(compile(textwrap.dedent(code), 'selected-ready-reader', 'exec'),
                             {"json": json, "selected": selected})
                    except SystemExit as terminal:
                        if terminal.code != 0:
                            raise
                return out.getvalue()
            owners = {"direct_guest_python": guest}
            original_lstat = Path.lstat
            def unlink_before_stat(path):
                if path == pending:
                    pending.unlink()
                return original_lstat(path)

            with patch.object(Path, 'lstat', unlink_before_stat):
                self.assertEqual(setup.get_owner_command(None, {"python": "selected"}, owners,
                    installation, None), {"status": "pending"})
            self.assertEqual(setup.get_owner_command(None, {"python": "selected"}, owners,
                installation, None), ready)

    def peer(self):
        calls = []
        objects = setup.source_declaration("a" * 64)
        digest = setup.manifest_digest(objects)
        session = {"publicationId": "b" * 32, "leaseToken": "c" * 32,
                   "manifestDigest": digest, "objectCount": 2, "admittedObjectCount": 0,
                   "nextChunkIndex": 0, "state": "accepting"}
        sealed = {"publicationId": session["publicationId"], "registry": "fixture/registry",
                  "generation": "queue-fault-" + "a" * 64, "refsDigest": "a" * 64,
                  "manifestDigest": digest, "state": "preparing",
                  "placements": [{"placementId": "13", "required": True}],
                  "objects": [{**item, "objectId": str(index + 1), "verified": False}
                              for index, item in enumerate(objects)]}

        def call(route, request):
            calls.append((route, request))
            if route.endswith("BeginRegistryPublicationManifest"):
                return copy.deepcopy(session)
            if route.endswith("AppendRegistryPublicationManifest"):
                return {**session, "admittedObjectCount": 2, "nextChunkIndex": 1}
            return copy.deepcopy(sealed)

        return call, calls, sealed

    def test_actual_manifest_before_direct_with_genuine_owner_and_no_commit(self):
        call, calls, _ = self.peer()
        retained = []
        def dispatch(route, request):
            self.assertTrue(retained[-1][0].endswith("-request.json"))
            return call(route, request)

        result = setup.prepare_publication(dispatch, lambda *item: retained.append(item),
                                           "fixture/registry", "a" * 64)
        self.assertEqual([route.split("/")[1] for route, _ in calls], [
            "BeginRegistryPublicationManifest", "AppendRegistryPublicationManifest",
            "SealRegistryPublicationManifest"])
        self.assertEqual(result["target"]["publicationId"], "b" * 32)
        self.assertEqual(result["target"]["surfaceObjectId"], "1")
        self.assertEqual(result["byteSize"], "8388608")
        self.assertIsNone(result["qualification"])

    def test_unknown_append_keeps_original_and_never_seals_or_reissues(self):
        call, calls, _ = self.peer()
        retained = []
        def dispatch(route, request):
            if route.endswith("AppendRegistryPublicationManifest"):
                calls.append((route, request))
                raise TimeoutError("controlled lost reply")
            return call(route, request)

        with self.assertRaises(TimeoutError):
            setup.prepare_publication(dispatch, lambda *item: retained.append(item),
                                      "fixture/registry", "a" * 64)
        self.assertEqual(len(calls), 2)
        self.assertTrue(retained[-1][0].endswith("AppendRegistryPublicationManifest-request.json"))

    def test_substituted_owner_inventory_and_already_verified_refuse(self):
        for mutate in (
                lambda value: value.update(publicationId="d" * 32),
                lambda value: value["objects"][0].update(sha256="e" * 64),
                lambda value: value["objects"][0].update(verified=True),
                lambda value: value.update(placements=[])):
            call, _, sealed = self.peer()
            mutate(sealed)
            with self.assertRaises(ValueError):
                setup.prepare_publication(call, lambda *item: None, "fixture/registry", "a" * 64)

    def test_distinct_runs_preserve_full_original_and_new_path(self):
        left, right = setup.source_declaration("a" * 64), setup.source_declaration("b" * 64)
        self.assertEqual(left[0]["sha256"], right[0]["sha256"])
        self.assertEqual(left[0]["byteSize"], right[0]["byteSize"])
        self.assertNotEqual(left[0]["path"], right[0]["path"])
        self.assertNotEqual(setup.manifest_digest(left), setup.manifest_digest(right))


if __name__ == "__main__":
    unittest.main()
