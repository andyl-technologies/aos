"""Controlled whole-corpus custody/coverage tests, without authentication claims."""

import ast
import copy
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("segments", Path(__file__).with_name("_hub-native-corpus-segments.py"))
segments = importlib.util.module_from_spec(spec)
spec.loader.exec_module(segments)


def records(count):
    # Closed observational records use the existing explicit ProtoJSON route.
    # Bodies are references only; these tests execute no codec or HTTP handler.
    empty = {"file": "/controlled/empty.body", "sha256": hashlib.sha256(b"").hexdigest(), "byteSize": "0"}
    rows = [{"requestId": format(index + 1, "032x"), "procedure": "/aos.hub.v1.RegistryService/GetRegistry",
        "phase": None, "status": 200, "method": "POST", "responseContentType": "application/json",
        "responseContentEncoding": None, "bodies": {"request": empty, "response": empty}}
        for index in range(count)]
    return rows


def ownership(rows):
    return [{"originalId": "outbound:" + row["requestId"],
        "receivedId": row["requestId"],
        "receiptIdSha256": hashlib.sha256(("receipt:" + row["requestId"]).encode()).hexdigest(),
        "transportCallIdSha256": hashlib.sha256(("call:" + row["requestId"]).encode()).hexdigest()}
        for row in rows]


def assemble(rows, owners=None):
    inventory = segments.native_corpus_inventory(("outbound", row) for row in rows)
    return segments.partition_native_codec_corpus(inventory,
        {"version": 1, "codecRevision": "a" * 40, "sourceDigest": "b" * 64, "issuerVerifier": None},
        "captures", rows, owners if owners is not None else ownership(rows))


def outcomes(bundle):
    return [{"index": row["index"], "status": "success", "manifestSha256": row["manifestSha256"],
        "membershipSha256": row["membershipSha256"], "executableSha256": "c" * 64,
        "provenanceSha256": "d" * 64, "report": {"controlled": row["count"]}}
        for row in bundle["segments"]]


class NativeCorpusSegmentTests(unittest.TestCase):
    def test_actual_4097_closed_records_are_assigned_once_under_existing_limits(self):
        rows = records(4097)
        bundle = assemble(rows)
        self.assertGreater(len(bundle["segments"]), 1)
        self.assertEqual(sum(row["count"] for row in bundle["segments"]), 4097)
        assigned = [member["originalId"] for row in bundle["segments"] for member in row["members"]]
        self.assertEqual(len(set(assigned)), 4097)
        for row in bundle["segments"]:
            self.assertLessEqual(row["count"], 4096)
            self.assertLessEqual(len(segments.native_corpus_json(row["manifest"])), 1024 * 1024)
        result = segments.validate_native_segment_outputs(bundle, outcomes(bundle), "c" * 64, "d" * 64)
        self.assertEqual(result["originalCount"], 4097)
        self.assertIsNone(result["nativeBulkBytes"])

    def test_retained_body_collector_accepts_more_than_one_codec_page(self):
        specification = importlib.util.spec_from_file_location("body_collector",
            Path(__file__).with_name("_hub-direct-boundary.py"))
        collector = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(collector)
        collector.WORKER_CONTROL_REPLY_LIMIT = 8 * 1024 * 1024
        collector.read_direct_guest_file = lambda *_: b""
        collector.retain_direct_flow = lambda *_: "a" * 64
        observations = [{"request_id": row["requestId"], "procedure": row["procedure"],
            "phase": "", "status": 200, "method": "POST", "response_content_type": "application/json",
            "response_content_encoding": "", "request_body_file": "", "request_body_bytes": 0,
            "request_transfer_encoding": "", "response_body_bytes": 0,
            "response_body_file": "/var/lib/hybrid-native-observations/response-bodies/" + row["requestId"]}
            for row in records(4097)]

        measured, retained = collector.capture_direct_native_bodies(None, {"python": "controlled"}, observations)

        self.assertEqual(len(measured), 4097)
        self.assertEqual(len(retained["bodies"]), 4097)
        self.assertEqual(collector.NATIVE_CAPTURE_COUNT_LIMIT, 4096)
        self.assertEqual(retained["maximumCaptures"], 204704)
        with patch.object(collector, "NATIVE_RETAINED_ROLE_COUNT_LIMIT", 4096), self.assertRaises(ValueError):
            collector.capture_direct_native_bodies(None, {"python": "controlled"}, observations)

    def test_count_boundary_splits_before_the_next_row(self):
        with patch.object(segments, "NATIVE_CODEC_SEGMENT_MANIFEST_LIMIT", 4 * 1024 * 1024):
            bundle = assemble(records(4097))
        self.assertEqual([row["count"] for row in bundle["segments"]], [4096, 1])

    def test_exact_manifest_and_reference_boundaries_remain_inclusive(self):
        rows = records(2)
        exact = len(segments.native_corpus_json({"version": 1, "codecRevision": "a" * 40,
            "sourceDigest": "b" * 64, "issuerVerifier": None, "captures": rows[:1]}))
        with patch.object(segments, "NATIVE_CODEC_SEGMENT_MANIFEST_LIMIT", exact):
            self.assertEqual([row["count"] for row in assemble(rows)["segments"]], [1, 1])
        with patch.object(segments, "NATIVE_CODEC_SEGMENT_MANIFEST_LIMIT", exact - 1):
            with self.assertRaises(ValueError):
                assemble(rows)
        for row in rows:
            row["bodies"]["request"]["byteSize"] = "7"
        with patch.object(segments, "NATIVE_CODEC_SEGMENT_REFERENCE_LIMIT", 14):
            self.assertEqual([row["count"] for row in assemble(rows)["segments"]], [1, 1])

    def test_omitted_duplicate_or_substituted_originals_refuse_globally(self):
        rows = records(3)
        inventory = segments.native_corpus_inventory(("outbound", row) for row in rows)
        for changed, owners in ((rows[:-1], ownership(rows[:-1])),
                ([rows[0], rows[0], rows[2]], ownership(rows)),
                (rows, [{**ownership(rows)[0], "originalId": "outbound:foreign"}, *ownership(rows)[1:]])):
            with self.assertRaises(ValueError):
                segments.partition_native_codec_corpus(inventory, {}, "captures", changed, owners)

    def test_cross_segment_received_receipt_or_call_reuse_refuses_before_partition(self):
        rows = records(3)
        for field in ("receivedId", "receiptIdSha256", "transportCallIdSha256"):
            owners = ownership(rows)
            owners[-1][field] = owners[0][field]
            with patch.object(segments, "NATIVE_CODEC_SEGMENT_COUNT_LIMIT", 1), self.assertRaises(ValueError):
                assemble(rows, owners)

    def test_missing_failed_or_source_substituted_outcomes_refuse(self):
        with patch.object(segments, "NATIVE_CODEC_SEGMENT_COUNT_LIMIT", 1):
            bundle = assemble(records(2))
        good = outcomes(bundle)
        for changed in (good[:-1], [good[0], good[0]],
                [good[0], {**good[1], "status": "refused"}],
                [good[0], {**good[1], "executableSha256": "e" * 64}],
                [good[0], {**good[1], "provenanceSha256": "e" * 64}],
                [good[0], {**good[1], "manifestSha256": "e" * 64}]):
            with self.assertRaises(ValueError):
                segments.validate_native_segment_outputs(bundle, changed, "c" * 64, "d" * 64)

    def test_post_freeze_segment_membership_or_source_changes_refuse(self):
        bundle = assemble(records(2))
        for field in ("requestId", "procedure"):
            changed = copy.deepcopy(bundle)
            changed["segments"][0]["manifest"]["captures"][0][field] = "foreign"
            with self.assertRaises(ValueError):
                segments.validate_native_segment_outputs(changed, outcomes(changed), "c" * 64, "d" * 64)
        changed = copy.deepcopy(bundle)
        changed["segments"][0]["manifest"]["sourceDigest"] = "e" * 64
        with self.assertRaises(ValueError):
            segments.validate_native_segment_outputs(changed, outcomes(changed), "c" * 64, "d" * 64)

    def test_proxy_ids_and_timestamps_cannot_disguise_reused_accepted_events(self):
        receipt = {"planIdSha256": "a" * 64, "operation": "head", "requestBytes": 17,
            "replyBytes": 23, "executorSourceBytes": 0, "nativeRequestId": "original-1",
            "requestId": "received-1", "workerProxyCompletedAtUnixMillis": "123"}
        reused = {**receipt, "nativeRequestId": "original-2", "requestId": "received-2",
            "workerProxyCompletedAtUnixMillis": "456"}
        self.assertEqual(segments.native_corpus_receipt_identity(receipt),
            segments.native_corpus_receipt_identity(reused))
        handler = {"handlerReceiptSemanticSha256": "a" * 64,
            "handlerCompletedAtUnixMillis": ["123"]}
        later = {**handler, "handlerCompletedAtUnixMillis": ["456"]}
        self.assertNotEqual(segments.native_corpus_receipt_identity(handler),
            segments.native_corpus_receipt_identity(later))
        with self.assertRaises(ValueError):
            segments.native_corpus_receipt_identity({**handler, "handlerCompletedAtUnixMillis": ["123", "456"]})

    def test_one_body_or_single_manifest_overflow_refuses_without_growing_limits(self):
        rows = records(1)
        rows[0]["bodies"]["request"]["byteSize"] = str(8 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            assemble(rows)
        rows = records(1)
        rows[0]["oversized"] = "x" * (1024 * 1024)
        with self.assertRaises(ValueError):
            assemble(rows)

    def test_inventory_retains_unsupported_and_missing_bodies(self):
        rows = records(2)
        rows[1]["procedure"] = "/unsupported"
        rows[1]["bodies"]["response"] = None
        result = segments.native_corpus_inventory(("outbound", row) for row in rows)
        self.assertEqual(result["originalCount"], 2)
        self.assertEqual(result["originals"][1]["originalSha256"],
            hashlib.sha256(segments.native_corpus_json(rows[1])).hexdigest())

    def test_storage_subset_preserves_every_unresolved_original(self):
        specification = importlib.util.spec_from_file_location("capture_fixtures",
            Path(__file__).with_name("_hub-storage-capture-tests.py"))
        fixtures = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(fixtures)
        capture = fixtures.capture
        for name in ("native_corpus_inventory", "partition_native_codec_corpus", "native_corpus_json", "native_corpus_receipt_identity"):
            setattr(capture, name, getattr(segments, name))
        original = fixtures.body(fixtures.ORIGINAL)
        received = fixtures.body(fixtures.RECEIVED)
        unsupported = fixtures.body("3" * 32)
        unsupported["procedure"] = "/unsupported"
        selected = {"nativeRequestId": fixtures.ORIGINAL, "receivedRequestId": fixtures.RECEIVED,
            "transportCallIdSha256": "a" * 64, "requestSha256": "c" * 64, "replySha256": "d" * 64}
        transport = {"joined": [selected], "unresolvedNativeRequestIds": [unsupported["requestId"]]}

        result = capture.prepare_storage_codec_segment_bundle(transport, [original, unsupported],
            [received], "b" * 64, "controlled-deployment")

        self.assertEqual(result["completeOriginalInventory"]["originalCount"], 2)
        self.assertEqual(result["selectedCodecSegments"]["originalCount"], 1)
        self.assertEqual(result["unresolvedNativeRequestIds"], [unsupported["requestId"]])
        self.assertFalse(result["allOriginalsSelected"])
        self.assertIsNone(result["nativeBulkBytes"])
        transport["unresolvedNativeRequestIds"] = []
        with self.assertRaises(ValueError):
            capture.prepare_storage_codec_segment_bundle(transport, [original, unsupported],
                [received], "b" * 64, "controlled-deployment")

    def run_controlled_terminal_fixture(self, refused, terminal_limit=None):
        specification = importlib.util.spec_from_file_location("segment_controller",
            Path(__file__).with_name("_hub-direct-codec-assessment.py"))
        controller = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(controller)
        for name in ("native_corpus_json", "validate_native_segment_outputs"):
            setattr(controller, name, getattr(segments, name))
        controller.NATIVE_SEGMENT_REPORT_BYTE_LIMIT = segments.NATIVE_SEGMENT_REPORT_BYTE_LIMIT if terminal_limit is None else terminal_limit
        controller.NATIVE_SEGMENT_DIAGNOSTIC_BYTE_LIMIT = segments.NATIVE_SEGMENT_DIAGNOSTIC_BYTE_LIMIT
        controller.NATIVE_CAPTURE_CORPUS_LIMIT = 512 * 1024 * 1024
        controller.WORKER_CONTROL_REPLY_LIMIT = 8 * 1024 * 1024
        # Use the real controller's create-new 0600 retention function. The
        # decoder is an explicit unit stub, not compiled codec/auth evidence.
        flow = ast.parse(Path(__file__).with_name("_hub-direct-flow.py").read_text())
        retain = next(node for node in flow.body if isinstance(node, ast.FunctionDef)
            and node.name == "retain_direct_flow")
        namespace = {"hashlib": hashlib, "json": json, "os": os, "re": re, "Path": Path}
        exec(compile(ast.Module(body=[retain], type_ignores=[]), "actual_retention", "exec"), namespace)
        controller.retain_direct_flow = namespace["retain_direct_flow"]
        with patch.object(segments, "NATIVE_CODEC_SEGMENT_COUNT_LIMIT", 1):
            bundle = assemble(records(2))
        calls = []

        def decode(_selection, manifest, label):
            selected = json.loads(manifest.read_bytes())
            calls.append(label)
            if refused and len(calls) == 1:
                raise RuntimeError("controlled refusal")
            return {"version": 1, "codecRevision": "a" * 40, "selectedSourceDigest": "b" * 64,
                "manifestSha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "selectedBodyBytes": "0", "maximumSelectedBodyBytes": str(512 * 1024 * 1024),
                "maximumBodyBytes": str(8 * 1024 * 1024),
                "captures": [{"requestIdSha256": hashlib.sha256(row["requestId"].encode()).hexdigest()}
                    for row in selected["captures"]]}

        controller.run_direct_native_codec_observer = decode
        selection = {"observerExecutable": {"sha256": "c" * 64}, "runtimeProvenance": {"sha256": "d" * 64}}
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            os.chdir(temporary)
            try:
                if refused or terminal_limit is not None:
                    with self.assertRaises(ValueError):
                        controller.run_direct_native_codec_segments(selection, bundle, "e" * 64,
                            "f" * 64, "a" * 40, "b" * 64, 0)
                else:
                    result = controller.run_direct_native_codec_segments(selection, bundle, "e" * 64,
                        "f" * 64, "a" * 40, "b" * 64, 0)
                    self.assertEqual(len(result["captures"]), 2)
                root = Path("external-direct-flow")
                coverage = json.loads((root / "native-codec-complete-coverage.json").read_bytes())
                self.assertIsNone(coverage["nativeBulkBytes"])
                if terminal_limit is None:
                    terminals = json.loads((root / "native-codec-all-terminal-segments.json").read_bytes())
                    self.assertEqual(calls, ["segment-000000", "segment-000001"])
                    self.assertEqual([row["status"] for row in terminals],
                        ["refused", "success"] if refused else ["success", "success"])
                    if refused:
                        self.assertFalse(coverage["complete"])
                else:
                    self.assertFalse((root / "native-codec-all-terminal-segments.json").exists())
                    self.assertFalse(coverage["complete"])
                    self.assertIsNone(coverage["terminalSegmentsSha256"])
                    self.assertGreater(coverage["attemptedAggregateBytes"], terminal_limit)
                    self.assertEqual(coverage["executedSegmentCount"], len(calls))
                    self.assertEqual(coverage["unexecutedSegmentCount"], 2 - len(calls))
                    self.assertLessEqual((root / "native-codec-complete-coverage.json").stat().st_size,
                        segments.NATIVE_SEGMENT_DIAGNOSTIC_BYTE_LIMIT)
                    for file in root.glob("*-outcome.json"):
                        self.assertLessEqual(file.stat().st_size, terminal_limit)
                    if terminal_limit == 1500:
                        self.assertEqual(calls, ["segment-000000", "segment-000001"])
                        positive = json.loads((root / "native-codec-segment-000000-outcome.json").read_bytes())
                        overflow = json.loads((root / "native-codec-segment-000001-outcome.json").read_bytes())
                        self.assertEqual(overflow["status"], "overflow")
                        # Report bodies alone fit; exact envelope/list overhead
                        # makes the actual retained collection exceed its bound.
                        self.assertLess(2 * len(segments.native_corpus_json(positive["report"])), terminal_limit)
                    else:
                        self.assertEqual(calls, ["segment-000000"])
                for file in root.iterdir():
                    self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            finally:
                os.chdir(previous)

    def test_controlled_terminal_assembly_retains_private_manifests_and_membership(self):
        self.run_controlled_terminal_fixture(False)

    def test_refused_first_segment_still_retains_all_terminals_and_unknown_bulk(self):
        self.run_controlled_terminal_fixture(True)

    def test_actual_controller_bounds_terminal_envelopes_before_aggregate_retention(self):
        self.run_controlled_terminal_fixture(False, terminal_limit=1500)

    def test_actual_controller_stops_single_envelope_overflow_with_unknown_coverage(self):
        self.run_controlled_terminal_fixture(False, terminal_limit=300)

    def test_inventory_and_report_representation_overflows_refuse(self):
        with patch.object(segments, "NATIVE_INVENTORY_COUNT_LIMIT", 1), self.assertRaises(ValueError):
            assemble(records(2))
        with patch.object(segments, "NATIVE_INVENTORY_BYTE_LIMIT", 1), self.assertRaises(ValueError):
            assemble(records(1))
        bundle = assemble(records(1))
        with patch.object(segments, "NATIVE_SEGMENT_REPORT_BYTE_LIMIT", 1), self.assertRaises(ValueError):
            segments.validate_native_segment_outputs(bundle, outcomes(bundle), "c" * 64, "d" * 64)


if __name__ == "__main__":
    unittest.main()
