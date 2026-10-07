"""Controlled adapter refusals; no provider, issuer or Native qualification."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("staged_matrix", Path(__file__).with_name("_hub-direct-staged-matrix.py"))
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        os.chmod(self.root, 0o700)

    def write(self, name, raw):
        file = self.root / name
        with file.open("xb") as output:
            output.write(raw)
        os.chmod(file, 0o600)
        return {"file": name, "bytes": str(len(raw)), "sha256": hashlib.sha256(raw).hexdigest()}

    def original(self):
        source = b"controlled source only"
        session = {"sessionId": "actual-session", "logicalFingerprint": "b" * 64}
        placement = {"placementId": "1", "bindingId": "2"}
        item = {"session": session, "operationId": "c" * 64, "expectedResourceVersion": "7",
                "manifests": [{"placement": placement, "manifestDigest": "d" * 64, "partCount": 1}]}
        body = json.dumps({"operationId": "e" * 64, "items": [item]}).encode()
        intent = {"expectedSha256": hashlib.sha256(source).hexdigest()}
        boot_id, uptime_ms = matrix._current_boot_clock()
        return {"version": 1, "state": "prepared_unsent", "method": "CompleteBatch",
                "controlPath": "/aos.hub.v1.DirectUploadService/CompleteBatch", "runId": "a" * 64,
                "scope": "external_s3", "cutoffUnixMs": int(time.time() * 1000) + 10000,
                "clock": {"bootId": boot_id, "cutoffUptimeMs": int(uptime_ms) + 10000},
                "session": session, "intent": intent,
                "status": {"session": session, "intent": intent, "placements": [placement],
                           "state": "creating", "resourceVersion": "7"},
                "placement": placement, "expectedResourceVersion": "7",
                "sourceSha256": hashlib.sha256(source).hexdigest(), "actorWhoami": {}, "runtimePins": {},
                "refs": {"source": self.write("source", source),
                         "completeBody": self.write("complete-CompleteBatch-request.json", body),
                         "beginBody": self.write("begin-request.json", json.dumps({"operationId": "f" * 64, "items": [intent]}).encode()),
                         "selectionValues": self.write("selectionValues", json.dumps({"placement": placement}).encode()),
                         **{name: self.write(name, b"{}") for name in
                            ("beginReply", "reportReply", "pendingReceipt")}}}

    def test_real_handoff_shape_and_original_substitution_refusals(self):
        prepared = self.original()
        self.assertEqual(matrix.prepared_complete(prepared, self.root)["operationId"], "c" * 64)
        matrix.within_original(prepared, time.monotonic() + 5)
        for count in (0, int(prepared["refs"]["completeBody"]["bytes"]), True,
                      "01", "+1", " 1", "1.0", "", "9" * 1000):
            changed = copy.deepcopy(prepared)
            changed["refs"]["completeBody"]["bytes"] = count
            with self.subTest(count=count), self.assertRaises(ValueError):
                matrix.prepared_complete(changed, self.root)
        for field, value in (("session", {"sessionId": "other", "logicalFingerprint": "b" * 64}),
                             ("expectedResourceVersion", "8"), ("placement", {"placementId": "9"}),
                             ("sourceSha256", "f" * 64), ("version", True)):
            changed = copy.deepcopy(prepared)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                matrix.prepared_complete(changed, self.root)
        for clock in ({"bootId": prepared["clock"]["bootId"]},
                      {"bootId": prepared["clock"]["bootId"], "cutoffUptimeMs": True}):
            changed = copy.deepcopy(prepared)
            changed["clock"] = clock
            with self.subTest(clock=clock), self.assertRaises(ValueError):
                matrix.prepared_complete(changed, self.root)
        for sample in (("00000000-0000-0000-0000-000000000000", 0),
                       (prepared["clock"]["bootId"], prepared["clock"]["cutoffUptimeMs"])):
            with self.subTest(sample=sample), patch.object(matrix, "_current_boot_clock", return_value=sample), self.assertRaises(RuntimeError):
                matrix.within_original(prepared, time.monotonic() + 5)

        # These are controlled callback checks: no guest operation is run. The
        # selected production adapter must retain actual CLIENT custody itself.
        guest_root = "/var/lib/hybrid-client/queue-faults/" + "a" * 64 + "/prepared/output/external_s3"
        images = {file.name: file.read_bytes() for file in self.root.iterdir()}
        calls = []

        class ClientIO:
            def read_reference(owner, reference, root, maximum):
                self.assertEqual(root, guest_root)
                calls.append(("read", reference["file"], maximum))
                return images[Path(reference["file"]).name]

            def within_original(owner, original, deadline):
                self.assertIs(original, prepared)
                calls.append(("clock", deadline))
                return None

        io = ClientIO()
        with patch.object(matrix.Path, "stat", side_effect=AssertionError("controller stat forbidden")), \
                patch.object(matrix, "_current_boot_clock", side_effect=AssertionError("controller proc forbidden")):
            matrix.prepared_complete(prepared, guest_root, client_io=io)
            matrix.within_original(prepared, 10, client_io=io)
        self.assertIn(("clock", 10), calls)

        reference = prepared["refs"]["source"]
        observation = {"file": reference["file"], "sha256": reference["sha256"], "byteSize": reference["bytes"]}
        images[reference["file"]] = b"changed guest body"
        with self.assertRaises(ValueError):
            matrix.read_reference(observation, guest_root, 8 * 1024 * 1024, client_io=io)
        with patch.object(io, "within_original", return_value={"ready": True}), self.assertRaises(ValueError):
            matrix.within_original(prepared, 10, client_io=io)

    def test_changed_private_source_and_escaped_reference_refuse(self):
        prepared = self.original()
        absent_begin = copy.deepcopy(prepared)
        del absent_begin["refs"]["beginBody"]
        with self.assertRaises(ValueError):
            matrix.prepared_complete(absent_begin, self.root)
        changed_begin = copy.deepcopy(prepared)
        changed_begin["refs"]["beginBody"] = self.write("other-begin.json", json.dumps({"operationId": "f" * 64, "items": []}).encode())
        with self.assertRaises(ValueError):
            matrix.prepared_complete(changed_begin, self.root)

        capabilities = b'{"controlled":"raw public capability image"}'
        image = self.write("capabilities-copy.json", capabilities)
        selected = {"capabilities": {"file": str(self.root / image["file"]), "sha256": image["sha256"],
                                     "byteSize": str(image["bytes"])}}
        discovered = copy.deepcopy(prepared)
        discovered["refs"]["capabilities"] = image
        discovered["refs"]["selectionValues"] = self.write("selected-capabilities.json", json.dumps(selected).encode())
        matrix.prepared_complete(discovered, self.root)
        no_image = copy.deepcopy(discovered)
        del no_image["refs"]["capabilities"]
        with self.assertRaises(ValueError):
            matrix.prepared_complete(no_image, self.root)
        changed_selected = copy.deepcopy(discovered)
        selected["capabilities"]["sha256"] = "a" * 64
        changed_selected["refs"]["selectionValues"] = self.write("changed-selected-capabilities.json", json.dumps(selected).encode())
        with self.assertRaises(ValueError):
            matrix.prepared_complete(changed_selected, self.root)
        (self.root / "source").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            matrix.prepared_complete(prepared, self.root)
        escaped = {"file": str(self.root / "../source"), "byteSize": "0", "sha256": "a" * 64}
        with self.assertRaises((ValueError, FileNotFoundError)):
            matrix.read_reference(escaped, self.root)

    def test_provider_arm_binds_kind_original_and_unextended_cutoff(self):
        prepared = self.original()
        original = prepared["refs"]["completeBody"]
        selected = {"version": 1, "kind": "source_complete", "method": "POST", "target": "/bucket/key?uploadId=id",
                    "host": "selected-provider", "requestSha256": "f" * 64, "requestBytes": "10",
                    "rawHeadersSha256": "e" * 64, "cutoffUnixMs": prepared["cutoffUnixMs"],
                    "originalSha256": original["sha256"],
                    "originalReference": {"file": original["file"], "sha256": original["sha256"],
                                          "byteSize": str(original["bytes"])},
                    "expected": {"bucket": "bucket", "key": "key", "uploadId": "id"}}

        def saved(name, value):
            written = self.write(name, json.dumps(value).encode())
            return {"file": written["file"], "sha256": written["sha256"], "byteSize": str(written["bytes"])}

        case = "source_complete_reply_lost"
        matrix.provider_arm(prepared, saved("arm", selected), self.root, case)
        for count in (int(original["bytes"]), True, "01", "9" * 1000):
            changed = copy.deepcopy(prepared)
            changed["refs"]["completeBody"]["bytes"] = count
            with self.subTest(count=count), self.assertRaises(ValueError):
                matrix.provider_arm(changed, saved("bad-count-" + type(count).__name__ + "-" + str(len(str(count))), selected),
                                    self.root, case)
        for index, (field, value) in enumerate((("kind", "destination_complete"),
                                               ("originalSha256", "a" * 64),
                                               ("cutoffUnixMs", prepared["cutoffUnixMs"] + 1))):
            changed = copy.deepcopy(selected)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                matrix.provider_arm(prepared, saved("changed-arm-" + str(index), changed), self.root, case)

        changed = copy.deepcopy(selected)
        other = self.write("other-original", b"another original")
        changed["originalReference"] = {"file": other["file"], "sha256": other["sha256"],
                                        "byteSize": str(other["bytes"])}
        with self.assertRaises(ValueError):
            matrix.provider_arm(prepared, saved("changed-body-arm", changed), self.root, case)

    def test_original_error_survives_cleanup_and_retention_failures(self):
        original = RuntimeError("producer original")
        calls = []

        class Sql:
            selection = {}

            def remove_fault(self):
                calls.append("cleanup")
                raise OSError("cleanup failure")

        def driver(prepare):
            # Mark an attempted install through the actual callback, then fail
            # validation; the producer error below is the active outer failure.
            try:
                prepare({}, self.root, time.monotonic() + 1)
            except ValueError:
                pass
            calls.append("driver")
            raise original

        def retain(_):
            calls.append("retain")
            raise OSError("retention failure")

        with self.assertRaises(RuntimeError) as caught:
            matrix.run_prepared_case(driver, None, retain, case="native_receipt_insert_refused", scratch_sql=Sql(),
                                     continue_original=lambda *_: None, commit_original=lambda *_: None)
        self.assertIs(caught.exception, original)
        self.assertEqual(calls, ["driver", "cleanup", "retain"])

    def test_cleanup_failure_after_driver_return_is_not_silenced(self):
        prepared = self.original()
        written = self.write("observation", b"{}")
        observed = {"file": written["file"], "sha256": written["sha256"], "byteSize": str(written["bytes"])}

        class Sql:
            selection = {"sessionId": prepared["session"]["sessionId"],
                         "logicalFingerprint": prepared["session"]["logicalFingerprint"],
                         "operationId": "c" * 64, "expectedResourceVersion": "7"}

            def install_fault(self):
                pass

            def remove_fault(self):
                raise OSError("cleanup failed")

        saved = []

        def driver(prepare):
            prepare(prepared, self.root, time.monotonic() + 5)
            return None

        with self.assertRaises(OSError):
            matrix.run_prepared_case(driver, lambda *_: {"admissionObservation": observed, "wrapperObservation": observed}, saved.append,
                                     case="native_receipt_insert_refused", scratch_sql=Sql(),
                                     continue_original=lambda *_: None, commit_original=lambda *_: None)
        self.assertEqual(saved[0]["cleanup"], "unknown")
        self.assertIsNone(saved[0]["phaseQualification"])

    def test_receipt_fault_requires_commit_and_remains_installed_through_it(self):
        with self.assertRaises(ValueError):
            matrix.run_prepared_case(None, None, None, case="native_receipt_insert_refused")

        prepared = self.original()
        calls = []
        records = []
        reference = self.write("observation", b"{}")
        observation = {"file": reference["file"], "sha256": reference["sha256"],
                       "byteSize": str(reference["bytes"])}
        item = matrix.prepared_complete(prepared, self.root)

        class Sql:
            selection = {"sessionId": prepared["session"]["sessionId"],
                         "logicalFingerprint": prepared["session"]["logicalFingerprint"],
                         "operationId": item["operationId"], "expectedResourceVersion": "7"}

            def install_fault(self):
                calls.append("install")

            def remove_fault(self):
                calls.append("cleanup")

        def observe(phase, _):
            calls.append(phase)
            return {"admissionObservation": observation, "wrapperObservation": observation}

        def driver(prepare):
            prepare(prepared, self.root, time.monotonic() + 5)
            calls.append("complete")
            return "controlled complete outcome"

        original = RuntimeError("controlled receipt INSERT refusal")

        def as_observation(reference):
            return {"file": str(self.root / reference["file"]), "sha256": reference["sha256"],
                    "byteSize": str(reference["bytes"])}

        prepared_ref = as_observation(self.write("pre-complete-prepared.json", json.dumps(prepared).encode()))
        response_name = "complete-CompleteBatch-response.json"
        response = {"status": 200, "request": prepared["refs"]["completeBody"],
                    "reply": {"file": "controlled-reply.json", "bytes": "2", "sha256": "a" * 64}}
        response_ref = as_observation(self.write(response_name, json.dumps(response).encode()))
        accepted = {"version": 1, "originals": [{"scope": prepared["scope"], "prepared": prepared_ref,
                                                   "firstResponse": response_ref}]}
        accepted_ref = as_observation(self.write("accepted-originals.json", json.dumps(accepted).encode()))
        progressed = {"status": "incomplete", "publicationCommit": "not_invoked"}
        guest_root = "/var/lib/hybrid-client/queue-faults/" + "a" * 64 + "/prepared/output/external_s3"
        guest_prepared_ref = dict(prepared_ref, file=guest_root + "/pre-complete-prepared.json")
        guest_response_ref = dict(response_ref, file=guest_root + "/" + response_name)
        guest_accepted = {"version": 1, "originals": [{"scope": prepared["scope"], "prepared": guest_prepared_ref,
                                                        "firstResponse": guest_response_ref}]}
        guest_accepted_raw = json.dumps(guest_accepted).encode()
        guest_accepted_ref = {"file": guest_root + "/accepted-originals.json",
                              "sha256": hashlib.sha256(guest_accepted_raw).hexdigest(),
                              "byteSize": str(len(guest_accepted_raw))}
        images = {file.name: file.read_bytes() for file in self.root.iterdir()}
        images["accepted-originals.json"] = guest_accepted_raw
        guest_calls = []

        class ClientIO:
            def read_reference(owner, reference, root, maximum):
                self.assertEqual(root, guest_root)
                guest_calls.append("read")
                return images[Path(reference["file"]).name]

            def within_original(owner, original, deadline):
                self.assertIs(original, prepared)
                self.assertEqual(deadline, 17)
                guest_calls.append("clock")

            def continue_acknowledged(owner, selection_file, accepted_file, fresh_output):
                self.assertEqual(selection_file, "/var/lib/hybrid-client/queue-faults/original/selection.json")
                self.assertEqual(accepted_file, guest_accepted_ref["file"])
                self.assertEqual(fresh_output, "/var/lib/hybrid-client/queue-faults/original/accepted/output")
                guest_calls.append("continue")
                return progressed

        io = ClientIO()
        with self.assertRaises(ValueError):
            matrix.continue_acknowledged_original(None, "unused", guest_accepted_ref, guest_root,
                                                  "unused", prepared=prepared, client_io=io)
        self.assertEqual(guest_calls, [])
        with patch.object(matrix.Path, "stat", side_effect=AssertionError("controller stat forbidden")), \
                patch.object(matrix, "_current_boot_clock", side_effect=AssertionError("controller proc forbidden")):
            actual = matrix.continue_acknowledged_original(None,
                "/var/lib/hybrid-client/queue-faults/original/selection.json", guest_accepted_ref, guest_root,
                "/var/lib/hybrid-client/queue-faults/original/accepted/output", prepared=prepared,
                client_io=io, deadline_monotonic_seconds=17)
        self.assertIs(actual, progressed)
        self.assertEqual(guest_calls[-2:], ["clock", "continue"])


        class SelectedSupervisor:
            def continue_acknowledged(owner, selection_file, accepted_file, fresh_output):
                self.assertEqual(selection_file, "actual-selected-selection-file")
                self.assertEqual(accepted_file, str(self.root / "accepted-originals.json"))
                self.assertEqual(fresh_output, "actual-fresh-observation-output")
                calls.append("progress")
                return progressed

        def progress(actual, complete, root):
            self.assertIs(actual, prepared)
            self.assertEqual(complete, "controlled complete outcome")
            return matrix.continue_acknowledged_original(SelectedSupervisor(), "actual-selected-selection-file",
                accepted_ref, root, "actual-fresh-observation-output", prepared=actual)

        def commit(actual, result):
            self.assertIs(actual, prepared)
            self.assertIs(result, progressed)
            calls.append("commit")
            raise original

        with self.assertRaises(RuntimeError) as caught:
            matrix.run_prepared_case(driver, observe, records.append, case="native_receipt_insert_refused",
                                     scratch_sql=Sql(), continue_original=progress, commit_original=commit)
        self.assertIs(caught.exception, original)
        self.assertEqual(calls, ["before", "install", "complete", "progress", "commit", "after", "cleanup"])
        self.assertIsNone(records[0]["commit"])
        self.assertIsNone(records[0]["phaseQualification"])

        calls.clear()
        records.clear()
        unknown = RuntimeError("controlled next reply unknown")

        def lost_next_reply(*_):
            calls.append("progress")
            raise unknown

        with self.assertRaises(RuntimeError) as caught:
            matrix.run_prepared_case(driver, observe, records.append, case="native_receipt_insert_refused",
                                     scratch_sql=Sql(), continue_original=lost_next_reply, commit_original=commit)
        self.assertIs(caught.exception, unknown)
        self.assertEqual(calls, ["before", "install", "complete", "progress", "after", "cleanup"])

        # These catalogue/HTTP images and the selected supervisor above are
        # controlled substitutes. Only the real selected Native entry point
        # validates raw pending replies and enforces its durable dispatch marker.
        for status in (500, None):
            response["status"] = status
            file = self.root / response_name
            raw = json.dumps(response).encode()
            file.write_bytes(raw)
            accepted["originals"][0]["firstResponse"] = {"file": str(file), "sha256": hashlib.sha256(raw).hexdigest(),
                                                         "byteSize": str(len(raw))}
            changed = as_observation(self.write("accepted-refusal-" + str(status), json.dumps(accepted).encode()))
            calls.clear()
            with self.subTest(status=status), self.assertRaises(ValueError):
                matrix.continue_acknowledged_original(SelectedSupervisor(), "actual-selected-selection-file",
                    changed, self.root, "actual-fresh-observation-output", prepared=prepared)
            self.assertEqual(calls, [])

    def test_unavailable_case_does_not_dispatch(self):
        for case in matrix.UNAVAILABLE:
            with self.subTest(case=case), self.assertRaises(ValueError):
                matrix.pre_complete_case({}, self.root, time.monotonic() + 1, case=case, observe=None)
        for callbacks in ({"continue_original": lambda *_: None}, {"commit_original": lambda *_: None}):
            with self.subTest(case="source_complete_reply_lost", callbacks=callbacks), self.assertRaises(ValueError):
                matrix.run_prepared_case(None, None, None, case="source_complete_reply_lost", **callbacks)
        for callbacks in ({}, {"continue_original": lambda *_: None}, {"commit_original": lambda *_: None}):
            with self.subTest(case="native_receipt_insert_refused", callbacks=callbacks), self.assertRaises(ValueError):
                matrix.run_prepared_case(None, None, None, case="native_receipt_insert_refused", **callbacks)
        for callbacks in ({}, {"continue_original": lambda *_: None, "commit_original": lambda *_: None}):
            with self.subTest(callbacks=callbacks), self.assertRaises(ValueError):
                matrix.run_prepared_case(None, None, None, case="destination_complete_reply_lost", **callbacks)

        # This isolates callback ordering; the actual provider arm and pending
        # reply validation remain required caller inputs, not this substitute.
        prepared = self.original()
        calls = []
        records = []

        def driver(prepare):
            prepare(prepared, self.root, time.monotonic() + 5)
            calls.append("first-ack")
            return "controlled known pending ACK"

        unknown = RuntimeError("controlled destination Complete reply lost")

        def destination_progress(*_):
            calls.append("progress")
            raise unknown

        with patch.object(matrix, "pre_complete_case", return_value={}), self.assertRaises(RuntimeError) as caught:
            matrix.run_prepared_case(driver, lambda *_: {}, records.append,
                                     case="destination_complete_reply_lost", continue_original=destination_progress)
        self.assertIs(caught.exception, unknown)
        self.assertEqual(calls, ["first-ack", "progress"])
        self.assertIsNone(records[0]["commit"])
        self.assertIsNone(records[0]["objectProgression"])

        calls.clear()
        records.clear()
        with patch.object(matrix, "pre_complete_case", return_value={}):
            matrix.run_prepared_case(driver, lambda *_: {}, records.append,
                                     case="destination_complete_reply_lost", continue_original=lambda *_: "controlled progression")
        self.assertEqual(calls, ["first-ack"])
        self.assertIsNone(records[0]["commit"])

    def test_failed_restart_is_retained_without_second_launch(self):
        calls = []
        records = []
        original = RuntimeError("actual start outcome unknown")

        class Sql:
            selection = {"databaseName": "selected-scratch"}

            def restore(self, _):
                calls.append("restore")

        def start():
            calls.append("start")
            raise original

        with self.assertRaises(RuntimeError) as caught:
            matrix.restore_scratch(Sql(), {}, lambda: calls.append("stop"), start,
                                   lambda _: None, records.append)
        self.assertIs(caught.exception, original)
        self.assertEqual(calls, ["stop", "restore", "start"])
        self.assertIsNone(records[0]["restart"])
        self.assertIsNone(records[0]["remoteDrain"])

    def test_unchanged_credential_is_not_a_rotation(self):
        credential = {"bindingId": "binding", "generation": "1", "purpose": "write",
                      "credentialFingerprint": "f" * 64, "secretVersionRef": "old"}
        with self.assertRaises(ValueError):
            matrix.rotate_credential(None, {"stableId": "binding"}, credential,
                                     "new", "f" * 64, None, "rotation")


if __name__ == "__main__":
    unittest.main()
