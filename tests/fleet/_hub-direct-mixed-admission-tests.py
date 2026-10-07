"""Controlled commitment and ownership regressions; no fleet/provider effects."""

import copy
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("mixed", Path(__file__).with_name("_hub-direct-mixed-admission.py"))
mixed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mixed)


class MixedAdmission(unittest.TestCase):
    def setUp(self):
        self.source = {"sha256": "a" * 64, "byte_size": 2147483648}
        self.identity = {"sourceDigest": "b" * 64, "scriptVersion": "fixture-current", "publicOrigin": "https://worker.fleet.test"}
        self.original = {"runId": "c" * 64, **self.identity, "objects": [
            {"objectId": "d" * 64, "metadata": False, "expectedSha256": self.source["sha256"], "byteSize": "2147483648"}]}
        self.closed = {"job": {"fixture": "independently selected controlled job"}}
        self.attempt = {"nonce": "e" * 64, "startedAtMillis": "1000", "providerBefore": {"isolateId": "controlled"}}
        self.capture = {**self.identity, "requestSha256": "f" * 64, "result": {
            "original": self.original, "objectId": "d" * 64, "closed": self.closed,
            "attempts": [{"attempt": self.attempt, "receipt": None}], "nextAttempt": None}}
        self.auth = {"status": 200, "requestSha256": "f" * 64, "responseSha256": "1" * 64}
        self.ready = {"version": 1, "cohortNonce": "2" * 64, "runId": self.original["runId"],
            "sourceDigest": self.identity["sourceDigest"], "scriptVersion": self.identity["scriptVersion"],
            "originalSha256": mixed.mixed_document_digest(self.original), "objectId": "d" * 64,
            "expectedSourceSha256": self.source["sha256"], "expectedSourceBytes": "2147483648",
            "closedSha256": mixed.mixed_document_digest(self.closed),
            "jobProjectionSha256": mixed.mixed_document_digest(self.closed["job"]),
            "attemptNonce": self.attempt["nonce"], "attemptSha256": mixed.mixed_document_digest(self.attempt),
            "inspectionSha256": "1" * 64, "inspectionFile": "00033-inspect-capture.json"}
        self.owner = {"pid": 22, "startTicks": "123", "ownerUid": 0, "configurationSha256": "3" * 64,
            "listenerSourceSha256": "4" * 64, "listenAddress": "127.0.0.1:3902", "upstreamAddress": "127.0.0.1:3900"}
        self.selection = {"target": "/fleet/stage/payload", "host": "s3.fleet.test", "etag": '"strong"',
            "sourceSha256": self.source["sha256"], "sourceBytes": "2147483648"}
        self.arm = {"cohortNonce": self.ready["cohortNonce"], "bindings": mixed.mixed_bindings(self.ready),
            "selectionContextSha256": "5" * 64, "expectedSourceSha256": self.source["sha256"],
            "expectedSourceBytes": "2147483648", "expectedPrefixSha256": "6" * 64}
        self.held = {"state": "held", "endedAtUnixMillis": None, "terminalCause": None,
            "receiptFile": {"sha256": "7" * 64}, "receipt": {"owner": self.owner,
                "cohortNonce": self.ready["cohortNonce"], "bindings": self.arm["bindings"],
                "selectionContextSha256": "5" * 64, "sourceSha256": self.source["sha256"],
                "sourceBytes": "2147483648", "prefixFile": {"sha256": "6" * 64, "byteSize": "65536"},
                "identity": {"method": "GET", "range": None, "target": self.selection["target"],
                    "host": self.selection["host"], "ifMatch": self.selection["etag"]},
                "selectedAtUnixMillis": 100, "heldAtUnixMillis": 101, "cutoffUnixMillis": 35100,
                "downstreamOfferedBytes": "0", "upstreamComplete": False, "remoteDrain": None}}
        self.metadata = {"sha256": "8" * 64, "byte_size": 262144}
        self.finish = {"version": 1, "runId": self.ready["runId"], "readySha256": mixed.mixed_document_digest(self.ready),
            "record": {"object": {"metadata": True}, "receipt": {"verificationReplayed": False,
                "proof": {"sha256": "8" * 64, "byte_size": "262144"}, "objects": {"bulkActive": 1},
                "attempt": {"providerBefore": {"isolateId": "same", "dispatches": 0, "metadataAdmissionsDuringBulk": 0}},
                "providerAfter": {"isolateId": "same", "dispatches": 1, "metadataAdmissionsDuringBulk": 1}}}}

    def validate(self, ready=None, capture=None, auth=None):
        return mixed.validate_mixed_ready(ready or self.ready, capture or self.capture, auth or self.auth,
            self.original["runId"], self.source, self.identity)

    def test_authentic_unfinished_begin_is_joined_but_does_not_claim_capacity(self):
        self.assertIs(self.validate(), self.capture["result"])
        self.assertNotIn("objects", self.attempt)

    def test_arm_requires_no_previous_begin_and_exact_closed_job(self):
        arm_ready = {name: value for name, value in self.ready.items() if name in mixed.MIXED_ARM_FIELDS}
        capture = copy.deepcopy(self.capture)
        capture["result"]["attempts"] = []
        self.assertEqual(mixed.validate_mixed_arm(arm_ready, capture, self.auth, self.original["runId"],
            self.source, self.identity), capture["result"])
        capture["result"]["attempts"] = [{"attempt": self.attempt, "receipt": None}]
        with self.assertRaises(ValueError):
            mixed.validate_mixed_arm(arm_ready, capture, self.auth, self.original["runId"], self.source, self.identity)

    def test_begin_nonce_closed_job_original_and_source_mismatch_refuse(self):
        for name in ("attemptNonce", "closedSha256", "jobProjectionSha256", "originalSha256", "sourceDigest"):
            ready = copy.deepcopy(self.ready); ready[name] = "0" * 64
            with self.subTest(name=name), self.assertRaises(ValueError): self.validate(ready=ready)

    def test_wrong_authentication_and_completed_receipt_refuse(self):
        for name, value in (("status", 409), ("responseSha256", "0" * 64), ("requestSha256", "0" * 64)):
            with self.subTest(name=name), self.assertRaises(ValueError): self.validate(auth={**self.auth, name: value})
        capture = copy.deepcopy(self.capture); capture["result"]["attempts"][0]["receipt"] = {}
        with self.assertRaises(ValueError): self.validate(capture=capture)

    def test_bool_version_and_extra_ready_field_refuse(self):
        with self.assertRaises(ValueError): self.validate(ready={**self.ready, "version": True})
        with self.assertRaises(ValueError): self.validate(ready={**self.ready, "accepted": True})

    def test_actual_held_receipt_owner_prefix_incarnation_are_required(self):
        self.assertEqual(mixed.validate_mixed_held(self.held, self.selection, self.arm, self.owner), "7" * 64)
        for change in ("owner", "prefix", "etag", "target", "offered", "cutoff", "cohort"):
            value = copy.deepcopy(self.held)
            if change == "owner": value["receipt"]["owner"]["startTicks"] = "124"
            elif change == "prefix": value["receipt"]["prefixFile"]["sha256"] = "0" * 64
            elif change == "etag": value["receipt"]["identity"]["ifMatch"] = '"different"'
            elif change == "target": value["receipt"]["identity"]["target"] += "/different"
            elif change == "offered": value["receipt"]["downstreamOfferedBytes"] = "1"
            elif change == "cutoff": value["receipt"]["cutoffUnixMillis"] += 1
            else: value["receipt"]["cohortNonce"] = "0" * 64
            with self.subTest(change=change), self.assertRaises(ValueError):
                mixed.validate_mixed_held(value, self.selection, self.arm, self.owner)

    def test_terminal_state_never_releases_metadata(self):
        for state in ("cutoff", "disconnected", "refused", "resuming", "eof", "cancelled"):
            with self.subTest(state=state), self.assertRaises(ValueError):
                mixed.validate_mixed_held({**self.held, "state": state}, self.selection, self.arm, self.owner)

    def test_release_commits_exact_ready_and_actual_held_file_not_sorted_reencoding(self):
        value = mixed.mixed_release_document(self.ready, "7" * 64)
        self.assertEqual(value["readySha256"], mixed.mixed_document_digest(self.ready))
        self.assertEqual(value["heldReceiptSha256"], self.held["receiptFile"]["sha256"])

    def test_metadata_positive_requires_real_fresh_bulk_admission_and_consumption(self):
        self.assertIs(mixed.validate_mixed_metadata_finish(self.finish, self.ready, self.metadata), self.finish["record"])
        for change in ("replay", "bulk", "counter", "source", "isolate"):
            finish = copy.deepcopy(self.finish); receipt = finish["record"]["receipt"]
            if change == "replay": receipt["verificationReplayed"] = True
            elif change == "bulk": receipt["objects"]["bulkActive"] = 0
            elif change == "counter": receipt["providerAfter"]["metadataAdmissionsDuringBulk"] = 0
            elif change == "source": receipt["proof"]["sha256"] = "0" * 64
            else: receipt["providerAfter"]["isolateId"] = "different"
            with self.subTest(change=change), self.assertRaises(ValueError):
                mixed.validate_mixed_metadata_finish(finish, self.ready, self.metadata)

    def test_barrier_commands_reject_unsupported_file_before_guest_transport(self):
        with self.assertRaises(ValueError): mixed.publish_mixed_barrier(None, {}, "/unused", "another.json", {}, cutoff=time.monotonic() + 1)


class SupervisorOwnership(unittest.TestCase):
    def run_owner(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / ("prequalification-" + "a" * 64)
            root.mkdir(mode=0o700)
            driver = root / "controlled-driver.py"
            driver.write_text("import time; time.sleep(" + ("0.2" if mode == "positive" else "60") + ")")
            driver.chmod(0o600)
            arguments = [sys.executable, "-B", str(driver)]
            # Production assumes arguments[1] is the driver. Keep that exact
            # invocation shape for this controlled source-built Python child.
            arguments = [sys.executable, str(driver)]
            owner = subprocess.Popen([sys.executable, "-B", "-c", mixed.MIXED_SUPERVISOR,
                str(root), json.dumps(arguments), "6"], start_new_session=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 2
                while not (root / "mixed-child.json").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                child = json.loads((root / "mixed-child.json").read_bytes())
                self.assertEqual(child["processGroup"], owner.pid)
                if mode == "cancel": owner.send_signal(signal.SIGTERM)
                stdout, stderr = owner.communicate(timeout=8)
                self.assertEqual(owner.returncode, 0, stderr.decode())
                self.assertEqual(stdout, b"")
                outcome = json.loads((root / "mixed-outcome.json").read_bytes())
                self.assertTrue(outcome["childReaped"])
                with self.assertRaises(ProcessLookupError): os.kill(child["pid"], 0)
                return outcome
            finally:
                if owner.poll() is None:
                    os.killpg(owner.pid, signal.SIGKILL)
                    owner.wait()

    def test_real_positive_child_is_reaped_and_actual_exit_is_retained(self):
        outcome = self.run_owner("positive")
        self.assertEqual(outcome["exitCode"], 0)
        self.assertFalse(outcome["cancelled"])
        self.assertFalse(outcome["timedOut"])

    def test_real_owner_cancellation_reaps_inheriting_child(self):
        outcome = self.run_owner("cancel")
        self.assertTrue(outcome["cancelled"])
        self.assertNotEqual(outcome["exitCode"], 0)

    def test_real_original_budget_timeout_reaps_without_padding(self):
        outcome = self.run_owner("timeout")
        self.assertTrue(outcome["timedOut"])
        self.assertFalse(outcome["cancelled"])
        self.assertNotEqual(outcome["exitCode"], 0)

    def test_original_owner_failure_survives_cleanup_and_retention_errors(self):
        original = ValueError("controlled original predicate")
        process = {"pid": 1, "startTicks": "selected", "ownerUid": os.getuid()}
        tools = {"python": sys.executable, "providerHoldInstallation": {}}
        with patch.object(mixed, "direct_guest_python", create=True, return_value=""), \
                patch.object(mixed, "launch_managed_process", create=True, return_value=process), \
                patch.object(mixed, "mixed_guest_snapshot", side_effect=original), \
                patch.object(mixed, "stop_mixed_supervisor", side_effect=RuntimeError("cleanup")), \
                patch.object(mixed, "retain_direct_flow", create=True, side_effect=OSError("retention")):
            with self.assertRaises(ValueError) as raised:
                mixed.run_mixed_prequalification(None, None, tools,
                    "/var/lib/hybrid-worker/operator/prequalification-" + "a" * 64, "a" * 64,
                    [], "", [], {}, {"configurationSha256": "b" * 64}, 600)
        self.assertIs(raised.exception, original)
        self.assertTrue(any("RuntimeError" in note for note in original.__notes__))
        self.assertTrue(any("OSError" in note for note in original.__notes__))


class OriginalCleanupBounds(unittest.TestCase):
    def test_exhausted_cutoff_rejects_new_control_before_any_guest_call(self):
        tools = {"providerHoldInstallation": {"root": "/var/lib/hybrid-s3/read-timeout",
            "ready": {"controlSocket": "/var/lib/hybrid-s3/read-timeout/control.sock"}}}
        with patch.object(mixed, "direct_guest_python", create=True) as guest:
            with self.assertRaises(TimeoutError):
                mixed.mixed_owner_command(None, tools, {}, cutoff=time.monotonic() - 1)
            guest.assert_not_called()

    def test_cleanup_passes_only_remaining_time_not_a_fresh_ten_or_five_seconds(self):
        observed = []
        def guest(_machine, _python, _body, selected, timeout):
            observed.append((selected, timeout)); return '{}'
        with patch.object(mixed, "direct_guest_python", create=True, side_effect=guest):
            mixed.stop_mixed_supervisor(None, {"python": sys.executable}, {}, cutoff=time.monotonic() + 0.5)
        selected, timeout = observed[0]
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 0.5)
        self.assertEqual(timeout, selected["seconds"])

    def test_already_observed_exit_zero_carries_owner_failure_even_if_final_snapshot_fails(self):
        process = {"pid": 1, "startTicks": "selected", "ownerUid": os.getuid()}
        tools = {"python": sys.executable, "providerHoldInstallation": {}}
        completed = {"exitCode": 0, "childReaped": True, "supervisorFailure": None,
                     "timedOut": False, "cancelled": False}
        mixed.assert_mixed_supervisor_completion(completed)
        refused = ({"childReaped": False}, {"supervisorFailure": "OSError"},
                   {"timedOut": True}, {"cancelled": True})
        for changes in ({}, *refused):
            with self.subTest(changes=changes):
                receipt = {**completed, **changes}
                if changes:
                    with self.assertRaisesRegex(ValueError, "completed supervisor custody"):
                        mixed.assert_mixed_supervisor_completion(receipt)
                snapshot = {"child": None, "mixed-arm-ready.json": None,
                            "mixed-admission-ready.json": None,
                            "mixed-admission-metadata-finish.json": None,
                            "outcome": {"value": receipt}}
                with patch.object(mixed, "direct_guest_python", create=True, return_value=""), \
                        patch.object(mixed, "launch_managed_process", create=True, return_value=process), \
                        patch.object(mixed, "mixed_guest_snapshot", side_effect=[snapshot, OSError("final read")]), \
                        patch.object(mixed, "stop_mixed_supervisor", return_value={"groupDrain": None}), \
                        patch.object(mixed, "retain_direct_flow", create=True):
                    result = mixed.run_mixed_prequalification(None, None, tools,
                        "/var/lib/hybrid-worker/operator/prequalification-" + "a" * 64, "a" * 64,
                        [], "", [], {}, {"configurationSha256": "b" * 64}, 600)
                self.assertEqual(result["exitCode"], 0)
                self.assertEqual(result["ownerFailure"], "ValueError")

    def test_nonreaped_supervisor_never_claims_exit_or_reap_and_all_waits_are_bounded(self):
        class Child:
            pid = os.getpid()
            returncode = None
            def __init__(self): self.waits = []
            def poll(self): return None
            def terminate(self): pass
            def kill(self): pass
            def wait(self, timeout):
                self.waits.append(timeout)
                raise subprocess.TimeoutExpired("controlled", timeout)
        child = Child()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / ("prequalification-" + "a" * 64); root.mkdir(mode=0o700)
            driver = root / "driver.py"; driver.write_text("# controlled source")
            clock = iter([0.0, 2.0, 2.0, 3.0, 4.0, 4.0])
            with patch.object(sys, "argv", ["supervisor", str(root), json.dumps([sys.executable, str(driver)]), "6"]), \
                    patch.object(subprocess, "Popen", return_value=child), \
                    patch.object(time, "monotonic", side_effect=lambda: next(clock)), \
                    patch.object(signal, "signal"):
                exec(compile(mixed.MIXED_SUPERVISOR, "controlled-supervisor", "exec"), {})
            outcome = json.loads((root / "mixed-outcome.json").read_bytes())
        self.assertFalse(outcome["childReaped"])
        self.assertIsNone(outcome["exitCode"])
        self.assertEqual(len(child.waits), 2)
        self.assertTrue(all(0 <= value <= 2 for value in child.waits))

    def test_actual_emitted_snapshot_reads_fixed_authentication_capture_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "evidence").mkdir(mode=0o700)
            files = {"mixed-outcome.json": {"exitCode": 1},
                "evidence/mixed-arm-ready.json": {"inspectionFile": "00033-inspect-capture.json"},
                "evidence/00033-inspect-capture.json": {"fixture": "bounded actual reader"},
                "evidence/00033-inspect-authentication.json": {"status": 200}}
            for name, value in files.items():
                target = root / name; target.write_text(json.dumps(value)); target.chmod(0o600)
            def guest(_machine, python, body, selected, timeout):
                program = "import json\nselected=" + repr(selected) + "\n" + __import__('textwrap').dedent(body)
                result = subprocess.run([python, "-B", "-c", program], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=True)
                return result.stdout.decode()
            process_directory = Path("/proc") / str(os.getpid())
            process_fields = (process_directory / "stat").read_text().rpartition(") ")[2].split()
            process = {"pid": os.getpid(), "startTicks": process_fields[19],
                       "ownerUid": process_directory.stat().st_uid}
            with patch.object(mixed, "direct_guest_python", create=True, side_effect=guest):
                result = mixed.mixed_guest_snapshot(None, {"python": sys.executable}, str(root), process, cutoff=time.monotonic() + 5)
            self.assertEqual(result["mixed-arm-ready.json"]["capture"]["value"], {"fixture": "bounded actual reader"})


if __name__ == "__main__":
    unittest.main()
