"""Focused custody/scope/unknown tests for the standalone staged window."""

import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch
import subprocess
import sys
import tempfile
import unittest


source = Path(sys.argv.pop(1)).resolve(strict=True)
spec = importlib.util.spec_from_file_location("staged_window", source)
window = importlib.util.module_from_spec(spec)
spec.loader.exec_module(window)


class StagedWindowTests(unittest.TestCase):
    def test_private_reference_refuses_mutated_or_public_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "selection.json"
            file.write_bytes(b'{"version":1}')
            file.chmod(0o600)
            reference = {"file": str(file), "sha256": window.digest(file.read_bytes()), "byteSize": "13"}
            self.assertEqual(window.referenced(reference, 65536), file.read_bytes())
            file.write_bytes(b'{"version":2}')
            with self.assertRaises(ValueError):
                window.referenced(reference, 65536)
            file.chmod(0o644)
            with self.assertRaises(ValueError):
                window.private_bytes(file, 65536)

    def test_atomic_publication_waits_for_stable_single_link_and_never_replaces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            temporary = root / "temporary.json"
            final = root / "original.json"
            raw = b'{"kind":"synthetic_complete_image"}'
            window.write_private(root, temporary.name, raw)
            os.link(temporary, final)

            def validate(value):
                if value != raw:
                    raise ValueError("substituted publication")

            self.assertIsNone(window.publication_bytes(final, 65536, validate))
            temporary.write_bytes(b"{}")
            with self.assertRaises(ValueError):
                window.publication_bytes(final, 65536, validate)
            temporary.write_bytes(raw)
            temporary.unlink()
            self.assertEqual(window.publication_bytes(final, 65536, validate), raw)
            with self.assertRaises(FileExistsError):
                window.publish_private(root, final.name, b"{}")
            self.assertEqual(final.read_bytes(), raw)
            reference = window.publish_private(root, "new.json", raw)
            self.assertEqual(window.referenced(reference, 65536), raw)
            self.assertEqual((root / "new.json").stat().st_nlink, 1)

    def test_scope_results_keep_missing_race_and_resource_proofs_unknown(self):
        scopes = {}
        for scope in sorted(window.SCOPES):
            scopes[scope] = {"scope": scope, "status": "incomplete", "results": [
                {"phase": phase, "raceQualification": None, "cleanupSettlement": None}
                for phase in ["complete", "abort"]]}
        report = window.summarize(scopes, window.SCOPES)
        self.assertEqual(report["status"], "incomplete")
        self.assertIsNone(report["raceQualification"])
        self.assertEqual(report["windowsAAndC"], "not_executed")
        scopes["managed_r2"]["results"][0]["raceQualification"] = True
        with self.assertRaises(ValueError):
            window.summarize(scopes, window.SCOPES)

    def test_selected_scopes_do_not_substitute_for_each_other(self):
        with self.assertRaises(ValueError):
            window.summarize({}, {"managed_r2"})
        with self.assertRaises(ValueError):
            window.summarize({"external_s3": {"scope": "managed_r2", "status": "incomplete"}}, {"external_s3"})

    def test_owned_cleanup_stops_a_real_child_without_replaying_it(self):
        child = subprocess.Popen([sys.executable, "-B", "-E", "-c", "import time; time.sleep(30)"],
                                 start_new_session=True)
        identity = window.child_identity(child.pid)
        try:
            self.assertEqual(identity["uid"], str(os.getuid()))
            outcome = window.stop_owned(child, identity)
            self.assertEqual(outcome["status"], "stopped")
            self.assertIsNotNone(child.poll())
        finally:
            if child.poll() is None:
                window.stop_owned(child, identity)

    def test_identity_sampling_failure_still_stops_owned_child(self):
        child = subprocess.Popen([sys.executable, "-B", "-E", "-c", "import time; time.sleep(30)"],
                                 start_new_session=True)
        try:
            with patch.object(window, "child_identity", side_effect=OSError("synthetic sampling refusal")):
                with self.assertRaises(OSError):
                    try:
                        window.child_identity(child.pid)
                    finally:
                        window.stop_owned(child, None)
            self.assertIsNotNone(child.poll())
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)

    def prepared_fixture(self, root):
        def image(name, raw):
            reference = window.write_private(root, name, raw)
            return {"file": name, "bytes": reference["byteSize"], "sha256": reference["sha256"]}

        actor = window.write_private(root, "actor.json", b'{"kind":"synthetic_actor_no_auth_proof"}')
        runtime = window.write_private(root, "runtime.json", b'{"kind":"synthetic_not_installed"}')
        selection = {"runId": "11" * 32, "scope": "external_s3", "cutoffUnixMs": 1234,
                     "placement": {"placementId": "1"}, "preComplete": {"actorWhoami": actor, "runtimePins": runtime}}
        source = b"x" * (8 * 1024 * 1024)
        body = {"operationId": "22" * 32, "items": [{"session": {"sessionId": "synthetic", "logicalFingerprint": "33" * 32},
                "operationId": "44" * 32, "expectedResourceVersion": "7", "manifests": [{"placement": selection["placement"],
                "manifestDigest": "55" * 32, "partCount": 1}]}]}
        body_ref = image("complete-request.json", json.dumps(body, separators=(",", ":")).encode())
        prepared = {"version": 1, "state": "prepared_unsent", "method": "CompleteBatch",
                    "controlPath": "/aos.hub.v1.DirectUploadService/CompleteBatch", "runId": selection["runId"],
                    "scope": selection["scope"], "cutoffUnixMs": 1234,
                    "clock": {"bootId": "synthetic-boot", "cutoffUptimeMs": 1234}, "session": body["items"][0]["session"],
                    "intent": {"expectedSha256": window.digest(source)}, "placement": selection["placement"],
                    "expectedResourceVersion": "7", "sourceSha256": window.digest(source), "actorWhoami": actor,
                    "runtimePins": runtime, "refs": {"source": image("source.bin", source),
                    "selectionValues": image("selected-values.json", json.dumps(selection, separators=(",", ":")).encode()),
                    "beginReply": image("begin.json", b'{"kind":"synthetic_reply_no_control_auth"}'),
                    "reportReply": image("report.json", b'{"kind":"synthetic_reply_no_control_auth"}'),
                    "completeBody": body_ref,
                    "pendingReceipt": image("pending.json", json.dumps({"method": "CompleteBatch", "request": body_ref,
                                                                          "cutoffUnixMs": 1234}, separators=(",", ":")).encode())}}
        prepared["refs"]["beginBody"] = image("begin-request.json", json.dumps({"operationId": "66" * 32,
                                                "items": [prepared["intent"]]}, separators=(",", ":")).encode())
        prepared["status"] = {"session": prepared["session"], "intent": prepared["intent"],
                              "placements": [prepared["placement"]], "resourceVersion": "7", "state": "creating"}
        return selection, prepared, json.dumps(prepared, separators=(",", ":")).encode()

    def test_handoff_preserves_saved_body_and_requires_actual_observation_refs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selection, prepared, raw = self.prepared_fixture(root)
            self.assertEqual(window.checked_prepared(raw, root, selection), prepared)
            observations = {"admissionObservation": window.write_private(root, "admission.json", b'{"synthetic":true}'),
                            "wrapperObservation": window.write_private(root, "wrapper.json", b'{"synthetic":true}')}
            continuation = window.continuation_record(prepared, raw, observations)
            self.assertEqual(continuation["completeBodySha256"], prepared["refs"]["completeBody"]["sha256"])
            self.assertEqual(continuation["preparedSha256"], window.digest(raw))
            self.assertEqual(continuation["actorWhoami"], selection["preComplete"]["actorWhoami"])
            with self.assertRaises(ValueError):
                window.continuation_record(prepared, raw, {"ready": True})

    def test_capability_prepared_matches_actual_derived_original_and_raw_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selection, prepared, _ = self.prepared_fixture(root)
            placement = {"placementId": "17", "placementFingerprint": "77" * 32, "placementResourceVersion": "2",
                         "writeSpecVersion": "3", "bindingId": "4", "bindingResourceVersion": "5",
                         "bindingWriteRevision": "6", "profileFingerprint": "88" * 32,
                         "privatePolicyDigest": "99" * 32, "checksumAlgorithm": "sha256"}
            target = {"kind": "publication_object", "publicationId": "synthetic-publication",
                      "surfaceObjectId": "23", "path": "complete.nar"}
            capabilities = {"version": 1, "capability": "aos.direct.multipart.v1", "transferMode": "direct_required",
                            "target": {"kind": "publication", "publicationId": target["publicationId"]},
                            "deploymentId": "synthetic-deployment", "principalId": "ab" * 32,
                            "configGeneration": "2", "validUntil": "9999", "maximumControlBytes": 262144,
                            "maximumBatchItems": 64, "maximumBatchParts": 64, "minimumObjectBytes": "1",
                            "maximumObjectBytes": "17179869184", "minimumPartBytes": "5242880",
                            "maximumPartBytes": "67108864", "profiles": [{**{key: value for key, value in placement.items() if key != "placementFingerprint"},
                                          "providerOrigin": "https://selected.example"}]}
            cap_raw = json.dumps(capabilities, separators=(",", ":")).encode()
            selection.pop("placement")
            selection.update({"providerOrigin": "https://selected.example",
                              "targets": {"complete": {"target": target, "finalReadUrl": None}},
                              "capabilities": window.write_private(root, "capabilities-original.json", cap_raw)})
            prepared["placement"] = placement
            prepared["intent"]["target"] = target
            prepared["status"].update({"intent": prepared["intent"], "placements": [placement]})
            for key, name, value in [
                ("selectionValues", "selected-values.json", selection),
                ("beginBody", "begin-request.json", {"operationId": "66" * 32, "items": [prepared["intent"]]}),
            ]:
                raw = json.dumps(value, separators=(",", ":")).encode()
                (root / name).write_bytes(raw)
                prepared["refs"][key].update({"bytes": str(len(raw)), "sha256": window.digest(raw)})
            body_ref = prepared["refs"]["completeBody"]
            body = json.loads((root / body_ref["file"]).read_bytes())
            body["items"][0]["manifests"][0]["placement"] = placement
            raw = json.dumps(body, separators=(",", ":")).encode()
            (root / body_ref["file"]).write_bytes(raw)
            body_ref.update({"bytes": str(len(raw)), "sha256": window.digest(raw)})
            pending_ref = prepared["refs"]["pendingReceipt"]
            pending = {"method": "CompleteBatch", "request": body_ref, "cutoffUnixMs": 1234}
            raw = json.dumps(pending, separators=(",", ":")).encode()
            (root / pending_ref["file"]).write_bytes(raw)
            pending_ref.update({"bytes": str(len(raw)), "sha256": window.digest(raw)})
            cap_ref = window.write_private(root, "capabilities-image.json", cap_raw)
            prepared["refs"]["capabilities"] = {"file": "capabilities-image.json", "bytes": cap_ref["byteSize"],
                                                "sha256": cap_ref["sha256"]}
            prepared_raw = json.dumps(prepared).encode()
            self.assertEqual(window.checked_prepared(prepared_raw, root, selection), prepared)
            changed = json.loads(prepared_raw)
            changed["placement"]["bindingResourceVersion"] = "9"
            changed["status"]["placements"] = [changed["placement"]]
            with self.assertRaises(ValueError):
                window.checked_prepared(json.dumps(changed).encode(), root, selection)
            (root / "capabilities-original.json").write_bytes(b"{}")
            with self.assertRaises(ValueError):
                window.checked_prepared(prepared_raw, root, selection)

    def test_external_owner_is_explicit_and_preserves_same_original_continuation(self):
        self.assertFalse(window.handoff_owner(None, False))
        self.assertTrue(window.handoff_owner(None, True))
        self.assertTrue(window.handoff_owner(lambda *_: None, False))
        for callback, external in [(lambda *_: None, True), (None, 1), ("ready", False)]:
            with self.assertRaises(ValueError):
                window.handoff_owner(callback, external)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selection, prepared, raw = self.prepared_fixture(root)
            observations = {"admissionObservation": window.write_private(root, "admission.json", b'{"synthetic":true}'),
                            "wrapperObservation": window.write_private(root, "wrapper.json", b'{"synthetic":true}')}
            continuation = window.continuation_record(prepared, raw, observations)
            destination = root / "pre-complete-continuation.json"
            window.write_private(root, destination.name, json.dumps(continuation).encode())
            self.assertEqual(window.checked_external_continuation(prepared, raw, root), continuation)
            for field, value in [("version", True), ("preparedSha256", "00" * 32),
                                 ("completeBodySha256", "00" * 32), ("expectedResourceVersion", "8")]:
                destination.write_text(json.dumps({**continuation, field: value}))
                with self.assertRaises(ValueError):
                    window.checked_external_continuation(prepared, raw, root)

    def test_handoff_refuses_changed_body_source_actor_and_boolean_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selection, prepared, raw = self.prepared_fixture(root)
            for field, value in [("status", {**prepared["status"], "resourceVersion": "8"}), ("version", True), ("session", {"sessionId": "substituted", "logicalFingerprint": "33" * 32}),
                                 ("sourceSha256", "00" * 32), ("actorWhoami", {"file": "changed", "sha256": "00" * 32, "byteSize": "1"})]:
                changed = {**prepared, field: value}
                with self.assertRaises(ValueError):
                    window.checked_prepared(json.dumps(changed).encode(), root, selection)
            request = root / prepared["refs"]["completeBody"]["file"]
            request.write_bytes(b"{}")
            with self.assertRaises(ValueError):
                window.checked_prepared(raw, root, selection)

    def test_accepted_original_requires_actual_pending_reply_and_same_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selection, prepared, raw = self.prepared_fixture(root)
            prepared_ref = window.write_private(root, "pre-complete-prepared.json", raw)
            observations = {"admissionObservation": window.write_private(root, "admission.json", b'{"synthetic":true}'),
                            "wrapperObservation": window.write_private(root, "wrapper.json", b'{"synthetic":true}')}
            window.publish_private(root, "pre-complete-continuation.json",
                json.dumps(window.continuation_record(prepared, raw, observations)).encode())
            body = json.loads((root / prepared["refs"]["completeBody"]["file"]).read_bytes())
            status = {**prepared["status"], "state": "completing_staging"}
            reply = {"operationId": body["operationId"], "sessions": [status], "grants": [], "errors": []}
            prefix = prepared["refs"]["completeBody"]["file"].removesuffix("-request.json")
            reply_ref = window.write_private(root, f"{prefix}-reply.json", json.dumps(reply).encode())
            response = {"status": 200, "request": prepared["refs"]["completeBody"],
                        "reply": {"file": Path(reply_ref["file"]).name, "bytes": reply_ref["byteSize"], "sha256": reply_ref["sha256"]}}
            response_ref = window.write_private(root, f"{prefix}-response.json", json.dumps(response).encode())
            accepted = {"version": 1, "prepared": prepared_ref, "firstResponse": response_ref}
            self.assertEqual(window.checked_accepted(accepted, selection), prepared)
            for changed in [{"status": 503}, {"status": True},
                            {"request": {**response["request"], "sha256": "00" * 32}}]:
                value = {**response, **changed}
                raw_response = json.dumps(value).encode()
                Path(response_ref["file"]).write_bytes(raw_response)
                current = {**accepted, "firstResponse": {**response_ref,
                           "byteSize": str(len(raw_response)), "sha256": window.digest(raw_response)}}
                with self.assertRaises(ValueError):
                    window.checked_accepted(current, selection)
            for changed in [{"errors": [{"unknown": True}]}, {"sessions": []},
                            {"sessions": [{**status, "session": {**status["session"], "logicalFingerprint": "00" * 32}}]},
                            {"sessions": [{**status, "state": "blocked_unknown"}]}]:
                raw_reply = json.dumps({**reply, **changed}).encode()
                Path(reply_ref["file"]).write_bytes(raw_reply)
                value = {**response, "reply": {**response["reply"], "bytes": str(len(raw_reply)), "sha256": window.digest(raw_reply)}}
                raw_response = json.dumps(value).encode()
                Path(response_ref["file"]).write_bytes(raw_response)
                current = {**accepted, "firstResponse": {**response_ref,
                           "byteSize": str(len(raw_response)), "sha256": window.digest(raw_response)}}
                with self.assertRaises(ValueError):
                    window.checked_accepted(current, selection)

    def test_closed_version_and_create_only_evidence(self):
        with self.assertRaises(ValueError):
            window.closed({"version": 1, "extra": True}, {"version"})
        with tempfile.TemporaryDirectory() as directory:
            selection = Path(directory) / "bool-version.json"
            selection.write_text(json.dumps({"version": True, "node": None, "driver": None,
                                             "scopeSelections": [], "cutoffUnixMs": 0}))
            selection.chmod(0o600)
            with self.assertRaises(ValueError):
                window.run(str(selection), str(Path(directory) / "unused"))
            self.assertFalse((Path(directory) / "unused").exists())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = window.write_private(root, "pending.json", b'{"pending":true}')
            self.assertEqual(reference["sha256"], window.digest(b'{"pending":true}'))
            with self.assertRaises(FileExistsError):
                window.write_private(root, "pending.json", b'{}')


if __name__ == "__main__":
    unittest.main()
