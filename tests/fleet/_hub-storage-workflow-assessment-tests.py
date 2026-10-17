"""Controlled real controller paths, without runtime/authentication claims."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).parent


def environment():
    scope = {}
    for name in ("_hub-native-corpus-segments.py", "_hub-storage-capture.py",
                 "_hub-storage-final-sql.py", "_hub-storage-workflow-assessment.py"):
        exec(compile((ROOT / name).read_bytes(), name, "exec"), scope)
    scope["_closed_review_json"] = json.loads
    return scope


def bundle(scope, count=2):
    empty = {"file": "/controlled/empty", "sha256": hashlib.sha256(b"").hexdigest(), "byteSize": "0"}
    cases = [{"requestId": format(index + 1, "032x"), "method": "POST",
        "pathAndQuery": "/_internal/storage/external-copy/v1", "phase": None,
        "status": 200, "responseContentType": "application/json", "responseContentEncoding": None,
        "originalRequest": empty, "receivedRequest": empty, "receivedReply": empty,
        "originalIngress": None, "receivedIngress": None} for index in range(count)]
    inventory = scope["native_corpus_inventory"](("outbound", row) for row in cases)
    owners = [{"originalId": "outbound:" + row["requestId"], "receivedId": row["requestId"],
        "receiptIdSha256": hashlib.sha256(("receipt" + row["requestId"]).encode()).hexdigest(),
        "transportCallIdSha256": hashlib.sha256(("call" + row["requestId"]).encode()).hexdigest()}
        for row in cases]
    return scope["partition_native_codec_corpus"](inventory,
        {"version": 1, "sourceDigest": "a" * 64, "deploymentId": "controlled"}, "cases", cases, owners)


def output(cases):
    return [{"requestId": row["requestId"], "sourceDigest": "a" * 64,
        "requestSha256": row["receivedRequest"]["sha256"], "replySha256": row["receivedReply"]["sha256"],
        "codecSourceSha256": "b" * 64, "exchangeIdSha256": "c" * 64,
        "originalContextSha256": "d" * 64, "operation": "external_copy_control",
        "class": "external_copy_control_metadata", "payload": {
            "requestRawObjectBytes": "0", "replyRawObjectBytes": "0",
            "selectedDataBytes": "0", "semanticOciProjectionBytes": "0"}} for row in cases]


class StorageWorkflowControllerTests(unittest.TestCase):
    def execute(self, change=None, count=2, limit=None):
        scope = environment()
        # Lower per-page count to exercise real global paging with tiny fixtures.
        scope["NATIVE_CODEC_SEGMENT_COUNT_LIMIT"] = 1
        selected = bundle(scope, count)
        persisted, invocations = {}, []
        def retain(name, value):
            body = value if isinstance(value, bytes) else scope["native_corpus_json"](value)
            persisted[name] = body
            return hashlib.sha256(body).hexdigest()
        def decode(selection, manifest, label, artifact_prefix):
            self.assertEqual(artifact_prefix, "storage-codec-observer")
            index = int(label.removeprefix("segment-"))
            invocations.append(index)
            actual = output(selected["segments"][index]["manifest"]["cases"])
            return change(actual, index) if change else actual
        scope["retain_direct_flow"], scope["run_direct_native_codec_observer"] = retain, decode
        if limit is not None:
            scope["NATIVE_SEGMENT_REPORT_BYTE_LIMIT"] = limit
        result = scope["run_storage_workflow_codec_segments"]({
            "observerExecutable": {"sha256": "e" * 64}, "runtimeProvenance": {"sha256": "f" * 64}},
            selected, "b" * 64, "a" * 64)
        return result, persisted, invocations

    def test_every_selected_page_executes_once_but_no_authority_is_inferred(self):
        result, persisted, calls = self.execute()
        self.assertEqual(calls, [0, 1])
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["observations"]), 2)
        self.assertIsNone(result["nativeBulkBytes"])
        self.assertIn("storage-codec-all-terminal-segments.json", persisted)

    def test_missing_substituted_source_body_or_call_refuses_whole_selection(self):
        mutations = [lambda rows: [],
            lambda rows: [{**rows[0], "sourceDigest": "f" * 64}],
            lambda rows: [{**rows[0], "codecSourceSha256": "f" * 64}],
            lambda rows: [{**rows[0], "replySha256": "f" * 64}],
            lambda rows: [{**rows[0], "requestId": "f" * 32}]]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                result, persisted, calls = self.execute(lambda rows, index: mutate(rows) if index == 1 else rows)
                self.assertEqual(calls, [0, 1])
                self.assertFalse(result["complete"])
                self.assertIsNone(result["nativeBulkBytes"])
                outcomes = json.loads(persisted["storage-codec-all-terminal-segments.json"])
                self.assertEqual([row["status"] for row in outcomes], ["success", "refused"])

    def test_actual_controller_checks_full_terminal_envelopes_before_append_or_write(self):
        _, persisted, _ = self.execute()
        outcomes = json.loads(persisted["storage-codec-all-terminal-segments.json"])
        first_envelope = len(environment()["native_corpus_json"](outcomes[0]))
        result, persisted, calls = self.execute(limit=first_envelope + 3)
        self.assertEqual(calls, [0, 1])
        self.assertFalse(result["complete"])
        self.assertIsNone(result["nativeBulkBytes"])
        self.assertNotIn("storage-codec-all-terminal-segments.json", persisted)
        self.assertNotIn("storage-codec-segment-000001-outcome.json", persisted)
        self.assertIn("storage-codec-overflow.json", persisted)

    def test_no_supported_calls_is_explicitly_unresolved_without_review_or_execution(self):
        scope, persisted = environment(), {}
        scope["retain_direct_flow"] = lambda name, value: persisted.setdefault(name, value) or "a" * 64
        result = scope["assess_selected_storage_workflow"]({"completeOriginalInventory": {},
            "selectedCodecSegments": None, "unresolvedNativeRequestIds": ["unsupported"]},
            "a" * 64, {}, {})
        self.assertEqual(result["unresolvedNativeRequestIds"], ["unsupported"])
        self.assertFalse(result["codecComplete"])
        self.assertIsNone(result["nativeBulkBytes"])


class FinalSqlReceiptTests(unittest.TestCase):
    def inputs(self):
        scope = environment()
        exchange = {"version": 2, "route": "/_internal/storage/external-copy/v1",
            "planId": "a" * 32, "operation": "external_copy_control", "transportCallId": "b" * 32,
            "requestSha256": "c" * 64, "replySha256": "d" * 64, "requestBytes": 10, "replyBytes": 20}
        facts = {key: "e" * 64 for key in scope["STORAGE_FINAL_SQL_COMMITMENTS"]["external_copy_current_sql"]}
        event = {"version": 1, "exchange": exchange, "contextKind": "external_copy_current_sql",
            "commitments": facts, "completedAtUnixMicros": "1234567"}
        process = {"pid": 12, "executablePath": "/controlled/native"}
        journal = {"_PID": "12", "_EXE": "/controlled/native", "_SYSTEMD_UNIT": "aos-hub.service",
            "__REALTIME_TIMESTAMP": "1234568", "MESSAGE": "[INFO] message=storage_final_sql_checked " + json.dumps(event)}
        joined = {"nativeRequestId": "original", "operation": exchange["operation"],
            "planIdSha256": hashlib.sha256(exchange["planId"].encode()).hexdigest(),
            "transportCallIdSha256": hashlib.sha256(exchange["transportCallId"].encode()).hexdigest(),
            "requestSha256": exchange["requestSha256"], "replySha256": exchange["replySha256"],
            "offeredRequestBytes": 10, "consumedReplyBytes": 20}
        return scope, process, journal, joined

    def test_external_writer_and_later_actor_are_distinct_exact_permit_joins(self):
        scope, process, journal, transport = self.inputs()
        event = json.loads(journal["MESSAGE"].split("storage_final_sql_checked ", 1)[1])
        event["contextKind"] = "external_oci_stage_writer_checked"
        event["exchange"].update(route="/_internal/storage/external-oci/v1",
            operation="external_oci_control", planId="a" * 64)
        event["commitments"] = {key: "e" * 64 for key in
            scope["STORAGE_FINAL_SQL_COMMITMENTS"][event["contextKind"]]}
        journal["MESSAGE"] = "[INFO] message=storage_final_sql_checked " + json.dumps(event)
        transport.update(operation="external_oci_control",
            planIdSha256=hashlib.sha256(("a" * 64).encode()).hexdigest())
        contexts = scope["storage_final_sql_receipts"](json.dumps(journal), process)
        final = scope["join_storage_final_sql"]({"joined": [transport]}, contexts)
        actor = {"version": 1, "phase": "manifest", "completedAtUnixMicros": "1234569",
            **{key: event["commitments"][key] for key in (
                "stagePermitSha256", "actorOriginalSha256", "writerSha256",
                "uploadOriginalSha256", "profileDigest")}}
        actor_journal = {**journal, "MESSAGE":
            "[INFO] message=external_oci_admission_actor_checked " + json.dumps(actor)}
        rows = scope["external_admission_actor_receipts"](json.dumps(actor_journal), process)
        result = scope["join_external_admission_actor"](final, rows)
        self.assertEqual(len(result["joined"]), 1)
        self.assertIsNone(result["nativeBulkBytes"])
        self.assertIsNone(final["joined"][0]["actorEvidence"])
        for evidence in ([], rows * 2, [{**rows[0], "actorOriginalSha256": "f" * 64}],
                [{**rows[0], "completedAtUnixMicros": "1234566"}]):
            refused = scope["join_external_admission_actor"](final, evidence)
            self.assertFalse(refused["joined"])
            self.assertEqual(refused["unresolvedNativeRequestIds"], ["original"])

    def test_only_exact_real_process_and_call_joins_without_actor_or_provider_inference(self):
        scope, process, journal, joined = self.inputs()
        rows = scope["storage_final_sql_receipts"](json.dumps(journal), process)
        result = scope["join_storage_final_sql"]({"joined": [joined]}, rows)
        self.assertEqual(len(result["joined"]), 1)
        self.assertFalse(result["unresolvedNativeRequestIds"])
        for name in ("independentSqlEvidence", "actorEvidence", "purposeEvidence", "providerPartition"):
            self.assertIsNone(result["joined"][0][name])
        self.assertIsNone(result["nativeBulkBytes"])

    def test_post_auth_without_final_sql_late_or_substituted_reply_remains_unresolved(self):
        scope, process, journal, joined = self.inputs()
        rows = scope["storage_final_sql_receipts"](json.dumps(journal), process)
        for evidence in ([], rows * 2, [{**rows[0], "exchange": {**rows[0]["exchange"], "replySha256": "f" * 64}}]):
            result = scope["join_storage_final_sql"]({"joined": [joined]}, evidence)
            self.assertEqual(result["unresolvedNativeRequestIds"], ["original"])
            self.assertFalse(result["joined"])

    def test_foreign_process_or_unreviewed_commitment_projection_refuses(self):
        scope, process, journal, _ = self.inputs()
        foreign = {**journal, "_PID": "13"}
        with self.assertRaises(ValueError):
            scope["storage_final_sql_receipts"](json.dumps(foreign), process)
        event = json.loads(journal["MESSAGE"].split("storage_final_sql_checked ")[1])
        event["commitments"]["configuredSuccess"] = "f" * 64
        journal["MESSAGE"] = "[INFO] message=storage_final_sql_checked " + json.dumps(event)
        with self.assertRaises(ValueError):
            scope["storage_final_sql_receipts"](json.dumps(journal), process)


if __name__ == "__main__":
    unittest.main()
