"""Controlled source-only ordinary prefix/call/custody refusal regressions."""

import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
NAMESPACE = {"__name__": "storage_execute_fixture", "__file__": str(ROOT / "_hub-storage-work-execute-observation.py"),
             "os": os, "stat": stat, "re": re, "hashlib": hashlib}
for leaf in ("_hub-direct-review.py", "_hub-storage-capture.py", "_hub-storage-work-execute-observation.py"):
    exec(compile((ROOT / leaf).read_bytes(), str(ROOT / leaf), "exec"), NAMESPACE)
flow = ast.parse((ROOT / "_hub-direct-flow.py").read_text())
function = next(node for node in flow.body if isinstance(node, ast.FunctionDef) and node.name == "direct_selected_bytes")
exec(compile(ast.Module(body=[function], type_ignores=[]), str(ROOT / "_hub-direct-flow.py"), "exec"), NAMESPACE)


def digest(body):
    return hashlib.sha256(body).hexdigest()


class ExecuteFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="aos-execute-observation-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.request, self.reply = b'{"actual":"plan"}', b'{"kind":"not_found"}'
        self.call = "a" * 32
        self.plan = "b" * 32
        self.source = "c" * 64
        self.codec_source = "d" * 64
        self.attempt = {
            "version": 1, "invocationId": "e" * 32, "transportCallId": self.call,
            "attempt": 1, "planId": self.plan, "operation": "head", "endpointScheme": "https",
            "offeredRequestSha256": digest(self.request), "offeredRequestBytes": str(len(self.request)),
            "replyStatus": 200, "exposedReplySha256": digest(self.reply), "exposedReplyBytes": str(len(self.reply)),
            "replyEof": True, "unreadResponse": False, "outcome": "typed_result_checked",
            "elapsedMicros": "10", "observedAtUnixMicros": "100", "replyMacAuthentication": None,
        }
        self.original = self.capture("original", "")
        self.received = self.capture("received", "original")
        fields = {"request_signature": {"sha256": "f" * 64, "byteSize": 64},
                  "path_and_query": {"sha256": digest(NAMESPACE["EXECUTE_ROUTE"].encode()),
                                     "byteSize": len(NAMESPACE["EXECUTE_ROUTE"])} }
        self.original_headers = {"original": {"requestId": "original", "transportCallId": self.call,
            "method": "POST", "phase": "", "status": 200,
            "queryClass": "absent", "files": copy.deepcopy(fields)}}
        self.received_headers = {"received": {"requestId": "received", "originalRequestId": "original",
            "transportCallId": self.call, "method": "POST", "phase": "", "status": 200,
            "queryClass": "absent", "files": copy.deepcopy(fields)}}
        self.codec = {"requestId": "original", "sourceDigest": self.source,
            "codecSourceSha256": self.codec_source, "requestSha256": digest(self.request),
            "replySha256": digest(self.reply), "exchangeIdSha256": digest(self.plan.encode()),
            "originalContextSha256": digest(self.request), "operation": "head",
            "class": "storage_work_not_found_metadata", "payload": {
                "requestRawObjectBytes": "0", "replyRawObjectBytes": "0",
                "selectedDataBytes": "0", "semanticOciProjectionBytes": "0"}}
        self.records = {"version": 1, "attempts": [{"value": self.attempt}], "finalContexts": []}

    def body(self, name, body):
        path = self.root / name
        path.write_bytes(body)
        path.chmod(0o600)
        return {"file": str(path), "sha256": digest(body), "byteSize": len(body)}

    def capture(self, name, original):
        return {"requestId": name, "originalRequestId": original,
            "procedure": NAMESPACE["EXECUTE_ROUTE"], "method": "POST", "phase": "", "status": 200,
            "responseContentType": "application/json", "responseContentEncoding": "",
            "bodies": {"request": self.body(name + "-request", self.request),
                       "response": self.body(name + "-reply", self.reply)}}

    def join(self):
        return NAMESPACE["join_storage_work_execute"]([self.original], [self.received],
            self.original_headers, self.received_headers, self.records, [self.codec], self.source, self.codec_source)

    def test_complete_transport_does_not_invent_final_authority(self):
        report = self.join()
        self.assertEqual(len(report["joined"]), 1)
        self.assertTrue(report["joined"][0]["fullReplyConsumed"])
        self.assertIsNone(report["joined"][0]["finalContext"])
        self.assertIsNone(report["nativeBulkBytes"])
        self.assertIsNone(report["joined"][0]["currentActorEvidence"])

    def test_actual_prefix_can_partition_metadata_without_claiming_native_acceptance(self):
        self.attempt.update(exposedReplyBytes="5", exposedReplySha256=digest(self.reply[:5]),
            replyEof=False, outcome="response_read_failed")
        row = self.join()["joined"][0]
        self.assertFalse(row["fullReplyConsumed"])
        self.assertEqual(row["nativeExposedReplyBytes"], "5")
        self.assertIsNone(row["finalContext"])

    def test_partial_content_cannot_borrow_the_full_typed_payload_count(self):
        self.attempt.update(exposedReplyBytes="5", exposedReplySha256=digest(self.reply[:5]),
            replyEof=False, outcome="response_read_failed")
        self.codec["payload"]["selectedDataBytes"] = "2"
        report = self.join()
        self.assertEqual(report["joined"], [])
        self.assertEqual(report["unresolvedNativeRequestIds"], ["original"])
        self.assertEqual(report["unassignedAttemptCallIds"], [self.call])

    def test_unread_known_refusal_keeps_zero_exposed_bytes_separate_from_upstream(self):
        reply = b"storage work failed"
        for row in (self.original, self.received):
            row.update(status=503, responseContentType="text/plain; charset=utf-8")
            row["bodies"]["response"] = self.body(row["requestId"] + "-refused", reply)
        self.original_headers["original"]["status"] = 503
        self.received_headers["received"]["status"] = 503
        self.attempt.update(replyStatus=503, exposedReplyBytes="0", exposedReplySha256=digest(b""),
            replyEof=False, unreadResponse=True, outcome="http_status_retry")
        self.codec.update(replySha256=digest(reply), **{"class": "storage_work_refusal_metadata"})
        row = self.join()["joined"][0]
        self.assertEqual(row["nativeExposedReplyBytes"], "0")
        self.assertIsNone(row["finalContext"])

    def test_substituted_body_call_source_or_prefix_remains_unresolved(self):
        for field, replacement in (("transportCallId", "f" * 32),
                ("exposedReplySha256", "f" * 64), ("offeredRequestSha256", "f" * 64)):
            with self.subTest(field=field):
                saved = self.attempt[field]
                self.attempt[field] = replacement
                self.assertEqual(self.join()["joined"], [])
                self.attempt[field] = saved
        self.codec["sourceDigest"] = "0" * 64
        self.assertEqual(self.join()["joined"], [])

    def test_closed_codec_and_header_selection_refuse_substitution(self):
        self.codec["extra"] = "not a codec field"
        self.assertEqual(self.join()["joined"], [])
        del self.codec["extra"]
        for key, replacement in (("method", "GET"), ("phase", "other"), ("status", 503)):
            saved = self.received_headers["received"][key]
            self.received_headers["received"][key] = replacement
            self.assertEqual(self.join()["joined"], [])
            self.received_headers["received"][key] = saved
        self.original_headers["original"]["files"]["path_and_query"]["byteSize"] += 1
        self.received_headers["received"]["files"]["path_and_query"]["byteSize"] += 1
        self.assertEqual(self.join()["joined"], [])

    def test_actual_final_context_must_belong_to_the_same_checked_attempt(self):
        context = {"value": {"version": 1, "attempt": copy.deepcopy(self.attempt),
            "contextKind": "surface_fetch_current_sql", "commitments": {
                "placementStateSha256": "1" * 64, "bindingStateSha256": "2" * 64},
            "completedAtUnixMicros": "101"}, "receiptSha256": "3" * 64}
        self.records["finalContexts"] = [context]
        self.assertEqual(self.join()["joined"][0]["finalContext"], context)
        context["value"]["attempt"]["planId"] = "9" * 32
        self.assertEqual(self.join()["joined"], [])

    def test_unmatched_failed_attempt_is_preserved_in_global_inventory(self):
        extra = copy.deepcopy(self.attempt)
        extra.update(transportCallId="1" * 32, replyStatus=None, exposedReplyBytes="0",
            exposedReplySha256=digest(b""), replyEof=False, outcome="transport_failed")
        self.records["attempts"].append({"value": extra})
        report = self.join()
        self.assertEqual(report["unassignedAttemptCallIds"], ["1" * 32])

    def test_retained_private_body_change_and_symlink_do_not_supply_counts(self):
        reference = self.received["bodies"]["response"]
        Path(reference["file"]).write_bytes(b"changed")
        self.assertEqual(self.join()["joined"], [])
        path = Path(reference["file"])
        path.unlink()
        path.symlink_to(self.original["bodies"]["response"]["file"])
        with self.assertRaises(OSError):
            self.join()

    def test_parser_reuses_exact_journal_process_and_refuses_duplicate_call_ids(self):
        process = {"pid": 12, "executablePath": "/nix/store/selected/bin/aos-hub"}
        event = {"_PID": "12", "_EXE": process["executablePath"], "_SYSTEMD_UNIT": "aos-hub.service",
            "__REALTIME_TIMESTAMP": "100", "MESSAGE": "[INFO] message=storage_work_attempt_observed "
                + json.dumps(self.attempt, separators=(",", ":"))}
        body = json.dumps(event)
        records = NAMESPACE["storage_work_execute_receipts"](body, process)
        self.assertEqual(records["attempts"][0]["value"], self.attempt)
        with self.assertRaises(ValueError):
            NAMESPACE["storage_work_execute_receipts"](body + "\n" + body, process)
        event["_PID"] = "13"
        with self.assertRaises(ValueError):
            NAMESPACE["storage_work_execute_receipts"](json.dumps(event), process)

    def test_stream_contradictions_and_fabricated_reply_mac_refuse(self):
        for patch in ({"replyMacAuthentication": True}, {"unreadResponse": True},
                {"replyEof": False}, {"exposedReplyBytes": "01"}, {"replyStatus": None}):
            with self.subTest(patch=patch):
                value = {**self.attempt, **patch}
                with self.assertRaises(ValueError):
                    NAMESPACE["validate_storage_work_attempt"](value)


if __name__ == "__main__":
    unittest.main()
