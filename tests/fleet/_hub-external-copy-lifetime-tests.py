"""Controlled caller/decoder tests, with no actual Worker/provider qualification."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("copy_lifetime", Path(__file__).with_name(
    "_hub-external-copy-lifetime.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

CAPTURE = "1" * 32
DIGEST = "2" * 64
TRACE = "00000000-0000-4000-8000-000000000001"
POOL = {"isolateId": TRACE, "maximum": 3, "active": 1, "bulkActive": 1,
        "metadataActive": 0, "peakActive": 2, "metadataAdmissionsDuringBulk": 0,
        "dispatches": 1}


def log(events):
    rows = [{"version": 1, "scope": "external_copy_local_lifetime", "capture_id": CAPTURE,
             "trace_id": TRACE, "ordinal": index + 1, "original_sha256": DIGEST,
             "request_sha256": "3" * 64, "role": "source_guard", "observed_at": 100,
             "event": event} for index, event in enumerate(events)]
    return "\n".join(helper.PREFIX + json.dumps(row) for row in rows)


def progress(eof=False):
    original = {"topology": {"operation_id": "real-operation", "destination": {
                    "stable_id": "registry:fixture/placement:cancel-target"}},
                "destination": {"prefix": "actual-target", "resource_version": "9"},
                "path": "nar/actual.nar"}
    return {"receipt": {"file": "retained-window"}, "original": original,
            "originalValidationReceipt": {
                "version": 1, "scope": "intrinsic_unauthenticated_pending_copy_request",
                "originalSha256": DIGEST, "request": {"original": original, "control": "advance"}},
            "workerLogText": log([{"kind": "entry", "pool": POOL},
                {"kind": "admission", "owned_slots": 1, "pool": POOL},
                {"kind": "source_progress", "bytes": 65536, "eof": eof}]),
            "originalSha256": DIGEST, "captureId": CAPTURE}


class Controls:
    def __init__(self):
        self.calls = []
        self.cancelled = False

    def call(self, service, method, request):
        self.calls.append((service, method, request))
        if method == "GetPlacement":
            return {"placement": {"prefix": "actual-target", "resourceVersion": "9"}}
        if method == "ListObjectPresence":
            return {"presences": [{"placementName": "cancel-target", "objectRef": "nar/actual.nar",
                                    "state": "missing"}]}
        if method == "CancelOperation":
            self.cancelled = True
        return {"operation": {"operationId": "real-operation"}}

    def operation(self, operation_id):
        return {"operation": {"operationId": operation_id,
                              "state": "cancelled" if self.cancelled else "running"},
                "resourceVersion": "7"}

    def wait_operation(self, operation_id, states):
        assert states == {"cancelled"}
        return {"operation": {"operationId": operation_id, "state": "cancelled"},
                "resourceVersion": "8"}


class LifetimeTests(unittest.TestCase):
    def test_missing_terminal_stays_incomplete_and_cleanup_never_means_remote_drain(self):
        selected = helper.select_copy_lifetime_traces(progress()["workerLogText"], CAPTURE, DIGEST)
        self.assertFalse(selected["traces"][0]["closedLocalBracket"])
        events = [{"kind": "entry", "pool": POOL}, {"kind": "cleanup", "cause": "native_signal",
            "owned_capacity_released": True, "source_gate_released": True,
            "native_cleanup_invocations": 1, "pool": POOL},
            {"kind": "terminal", "outcome": "incoming_abort", "healthy": True, "pool": POOL}]
        selected = helper.select_copy_lifetime_traces(log(events), CAPTURE, DIGEST)
        self.assertTrue(selected["traces"][0]["closedLocalBracket"])
        self.assertIsNone(selected["traces"][0]["remoteDrain"])

    def test_closed_event_fields_and_pool_identity_are_required(self):
        for event in ({"kind": "source_progress", "bytes": True, "eof": False},
                      {"kind": "entry", "pool": {**POOL, "scriptVersion": "fake-isolate"}},
                      {"kind": "terminal", "outcome": "drained", "healthy": True, "pool": POOL}):
            with self.assertRaises(ValueError):
                helper.select_copy_lifetime_traces(log([event]), CAPTURE, DIGEST)

    def test_real_apply_is_inside_window_and_cancel_uses_current_cas(self):
        controls, retained, windows = Controls(), [], []
        result = helper.run_external_copy_cancellation(controls,
            {"planId": "plan", "confirmationHash": "confirmation", "effects": [{}]}, "fresh-copy",
            surface={"registrySlug": "fixture"}, destination_name="cancel-target",
            begin_window=lambda label: windows.append(("begin", label)) or {"label": label},
            await_source_progress=lambda token, operation_id: progress(),
            finish_window=lambda token, label: windows.append(("finish", label)) or {"terminal": None},
            retain=lambda label, value: retained.append((label, copy.deepcopy(value))))
        self.assertEqual(windows, [("begin", "fresh-copy"), ("finish", "fresh-copy")])
        self.assertEqual(controls.calls[0][1], "ReplicatePlacement")
        cancel = [call for call in controls.calls if call[1] == "CancelOperation"]
        self.assertEqual(cancel, [("OperationService", "CancelOperation", {
            "operationId": "real-operation", "expectedResourceVersion": "7",
            "idempotencyKey": "fresh-copy-cancel"})])
        self.assertIsNone(result["providerSettlement"])
        self.assertIsNone(result["remoteDrain"])
        self.assertEqual(retained[-1][0], "fresh-copy-cancelled")

    def test_eof_or_foreign_original_never_reaches_cancel(self):
        for selected in (progress(eof=True), progress()):
            if selected["workerLogText"] == progress()["workerLogText"]:
                selected["original"]["topology"]["operation_id"] = "another-operation"
            controls, retained = Controls(), []
            with self.assertRaises(ValueError):
                helper.run_external_copy_cancellation(controls,
                    {"planId": "plan", "confirmationHash": "confirmation", "effects": [{}]}, "fresh-copy",
                    surface={"registrySlug": "fixture"}, destination_name="cancel-target",
                    begin_window=lambda label: {"label": label},
                    await_source_progress=lambda token, operation_id: selected,
                    finish_window=lambda *args: self.fail("invalid selection must not finish positively"),
                    retain=lambda label, value: retained.append(label))
            self.assertEqual(len(controls.calls), 1)
            self.assertIn("fresh-copy-source-progress", retained)


if __name__ == "__main__":
    unittest.main()
