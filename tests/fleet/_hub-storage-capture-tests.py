"""Controlled capture/schema joins; no VM, MAC, SQL or provider qualification."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(path))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


capture = load("capture", "_hub-storage-capture.py")
review = load("review", "_hub-direct-review.py")
observations = load("observations", "_hub-direct-observations.py")
capture._closed_review_json = review._closed_review_json
retained = {}


def retain(name, value):
    if name in retained:
        raise ValueError("controlled artifact replacement")
    retained[name] = value
    return hashlib.sha256(value).hexdigest()


capture.retain_direct_flow = retain
ROUTE = "/_internal/storage/external-copy/v1"
ORIGINAL = "1" * 32
RECEIVED = "2" * 32
PROCESS = {"pid": 123, "executablePath": "/nix/store/controlled-hub/bin/aos-hub"}


def header(identifier, original="", **changes):
    return {"version": "1", "request_id": identifier, "origin_request_id": original,
        "path_and_query": ROUTE, "method": "POST", "phase": "", "status": "200",
        "ingress": "", "request_signature": "a" * 64, "reply_signature": "b" * 64,
        "query_class": "absent", **changes}


def body(identifier):
    return {"requestId": identifier, "procedure": ROUTE, "method": "POST", "phase": "",
        "status": 200, "responseContentType": "application/json", "responseContentEncoding": "",
        "bodies": {"request": {"file": "/controlled/request", "sha256": "c" * 64, "byteSize": 17},
            "response": {"file": "/controlled/reply", "sha256": "d" * 64, "byteSize": 23}}}


def receipt(**changes):
    return {"version": 1, "route": ROUTE, "planId": "e" * 32,
        "operation": "external_copy_control", "requestSha256": "c" * 64,
        "replySha256": "d" * 64, "requestBytes": 17, "replyBytes": 23, **changes}


def journal(value, **changes):
    return json.dumps({"_PID": "123", "_EXE": PROCESS["executablePath"],
        "_SYSTEMD_UNIT": "aos-hub.service", "__REALTIME_TIMESTAMP": "1770000000123000",
        "MESSAGE": "[INFO] message=external_copy_authenticated " + json.dumps(value)
            + ' span=registry_index registry_id=7', **changes})


class StorageCaptureTests(unittest.TestCase):
    def setUp(self):
        retained.clear()

    def test_only_compact_controls_are_retained_and_summaries_contain_no_values(self):
        raw = header(ORIGINAL, ingress="e30.signature")
        result = capture.capture_protected_headers(json.dumps(raw), "native-outbound")
        summary = json.dumps(result)
        for value in (raw["request_signature"], raw["reply_signature"], raw["ingress"], ROUTE):
            self.assertNotIn(value, summary)
        self.assertEqual(set(retained.values()), {value.encode() for value in (
            raw["request_signature"], raw["reply_signature"], raw["ingress"], ROUTE)})
        self.assertEqual(result[ORIGINAL]["files"]["ingress"]["byteSize"], len(raw["ingress"]))
        retained.clear()
        omitted = capture.capture_protected_headers(json.dumps(header(ORIGINAL,
            path_and_query="", query_class="unsupported")), "native-outbound")
        self.assertIsNone(omitted[ORIGINAL]["files"]["path_and_query"])
        self.assertEqual(omitted[ORIGINAL]["queryClass"], "unsupported")

    def test_numeric_capture_keeps_unsupported_distribution_phases_for_review(self):
        row = {name: "" for name in observations.NATIVE_OBSERVATION_FIELDS}
        row.update(procedure="/v2/repo/blobs/sha256:" + "c" * 64, phase="authorize-final",
            status="200", request_http_bytes="30", request_body_bytes="2",
            response_body_bytes="0", response_http_bytes="40", elapsed_seconds="0.020",
            upstream_status="200", upstream_seconds="0.019", request_id=ORIGINAL,
            request_body_file="/var/lib/hybrid-native-observations/client-body/controlled",
            response_body_file="/var/lib/hybrid-native-observations/response-bodies/" + ORIGINAL)
        for method in ("PUT", "PATCH", "HEAD", "DELETE"):
            row["method"] = method
            result = observations.native_control_observations(json.dumps(row))
            self.assertEqual(result[0]["method"], method)
            self.assertEqual(result[0]["phase"], "authorize-final")

    def test_substituted_or_expanded_headers_refuse_without_capturing_bearers(self):
        for changes in ({"authorization": "Bearer private"}, {"cookie": "private"},
                {"request_signature": "a" * 64 + "," + "b" * 64},
                {"ingress": "Bearer private"}, {"path_and_query": "/v2/token?access_token=private",
                    "query_class": "unsupported"}, {"version": 1}):
            retained.clear()
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                capture.capture_protected_headers(json.dumps(header(ORIGINAL, **changes)), "native-outbound")
            self.assertNotIn(b"Bearer private", retained.values())
        with self.assertRaises(ValueError):
            capture.capture_protected_headers(json.dumps(header(ORIGINAL)) + "\n"
                + json.dumps(header(ORIGINAL)), "native-outbound")

    def test_native_journal_receipt_requires_exact_process_schema_and_route(self):
        rows = capture.copy_authenticated_transport_receipts(journal(receipt()), PROCESS)
        self.assertEqual(rows[0]["requestBytes"], 17)
        self.assertEqual(rows[0]["nativeCompletedAtUnixMicros"], "1770000000123000")
        for changes in ({"_PID": "124"}, {"_EXE": "/another/process"},
                {"_SYSTEMD_UNIT": "another.service"}, {"__REALTIME_TIMESTAMP": "-1"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                capture.copy_authenticated_transport_receipts(journal(receipt(), **changes), PROCESS)
        for changes in ({"requestBytes": True}, {"replyBytes": 65537},
                {"route": "/unsupported"}, {"operation": "external_copy_metadata"},
                {"callerPass": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                capture.copy_authenticated_transport_receipts(journal(receipt(**changes)), PROCESS)
        self.assertEqual(capture.copy_authenticated_transport_receipts(journal(receipt(),
            MESSAGE="[INFO] message=ordinary error mentions external_copy_authenticated fake"), PROCESS), [])

    def test_exact_original_received_headers_bodies_and_consumption_join(self):
        first = capture.capture_protected_headers(json.dumps(header(ORIGINAL)), "native-outbound")
        second = capture.capture_protected_headers(json.dumps(header(RECEIVED, ORIGINAL)), "worker-received")
        receipts = capture.copy_authenticated_transport_receipts(journal(receipt()), PROCESS)
        result = capture.join_copy_captured_transports([body(ORIGINAL)], [body(RECEIVED)], first, second, receipts)
        self.assertEqual(result["unresolvedNativeRequestIds"], [])
        self.assertEqual(result["joined"][0]["consumedReplyBytes"], 23)
        self.assertIsNone(result["nativeBulkBytes"])
        for name in ("currentActorEvidence", "purposeArtifactEvidence", "providerObjectPartition"):
            self.assertIsNone(result["joined"][0][name])
        for mutate in (
                lambda value: value["bodies"]["response"].update(sha256="f" * 64),
                lambda value: value["bodies"].update(response=None),
                lambda value: value.update(phase="authorize-final"),
                lambda value: value.update(status=403)):
            changed = body(RECEIVED)
            mutate(changed)
            result = capture.join_copy_captured_transports([body(ORIGINAL)], [changed], first, second, receipts)
            self.assertEqual(result["unresolvedNativeRequestIds"], [ORIGINAL])
            self.assertEqual(result["joined"], [])
            self.assertIsNone(result["nativeBulkBytes"])
        changed = copy.deepcopy(second)
        changed[RECEIVED]["files"]["reply_signature"]["sha256"] = "f" * 64
        self.assertEqual(capture.join_copy_captured_transports([body(ORIGINAL)], [body(RECEIVED)],
            first, changed, receipts)["joined"], [])
        self.assertEqual(capture.join_copy_captured_transports([body(ORIGINAL)], [body(RECEIVED)],
            first, second, [])["joined"], [])

    def test_codec_selection_comes_only_from_joined_originals_and_keeps_unknowns(self):
        first = capture.capture_protected_headers(json.dumps(header(ORIGINAL)), "native-outbound")
        second = capture.capture_protected_headers(json.dumps(header(RECEIVED, ORIGINAL)), "worker-received")
        receipts = capture.copy_authenticated_transport_receipts(journal(receipt()), PROCESS)
        joined = capture.join_copy_captured_transports([body(ORIGINAL)], [body(RECEIVED)], first, second, receipts)
        selected = capture.prepare_copy_codec_cases(joined, [body(ORIGINAL)], [body(RECEIVED)],
            "f" * 64, "controlled-deployment")
        self.assertEqual(selected["cases"][0]["originalRequest"]["byteSize"], "17")
        self.assertEqual(selected["cases"][0]["requestId"], ORIGINAL)
        self.assertIsNone(selected["cases"][0]["originalIngress"])
        self.assertIsNone(joined["nativeBulkBytes"])
        self.assertIsNone(capture.prepare_copy_codec_cases({"joined": []}, [], [],
            "f" * 64, "controlled-deployment"))
        changed = copy.deepcopy(second)
        changed[RECEIVED]["files"]["path_and_query"]["sha256"] = "f" * 64
        self.assertEqual(capture.join_copy_captured_transports([body(ORIGINAL)], [body(RECEIVED)],
            first, changed, receipts)["joined"], [])

    def test_identical_second_consumed_exchange_cannot_reuse_one_success(self):
        other_original, other_received = "3" * 32, "4" * 32
        first = capture.capture_protected_headers("\n".join(json.dumps(header(identifier))
            for identifier in (ORIGINAL, other_original)), "native-outbound")
        second = capture.capture_protected_headers("\n".join((
            json.dumps(header(RECEIVED, ORIGINAL)),
            json.dumps(header(other_received, other_original)))), "worker-received")

        # Both exchanges consumed identical bodies, but the second call failed
        # its late/expired authenticator and emitted no successful receipt.
        receipts = capture.copy_authenticated_transport_receipts(journal(receipt()), PROCESS)
        result = capture.join_copy_captured_transports(
            [body(ORIGINAL), body(other_original)], [body(RECEIVED), body(other_received)],
            first, second, receipts)

        self.assertEqual(result["joined"], [])
        self.assertEqual(result["unresolvedNativeRequestIds"], [ORIGINAL, other_original])
        self.assertIsNone(result["nativeBulkBytes"])
        self.assertIsNone(capture.prepare_copy_codec_cases(result,
            [body(ORIGINAL), body(other_original)], [body(RECEIVED), body(other_received)],
            "f" * 64, "controlled-deployment"))

    def test_distinct_completion_times_do_not_collapse_into_one_exchange(self):
        first = capture.capture_protected_headers(json.dumps(header(ORIGINAL)), "native-outbound")
        second = capture.capture_protected_headers(json.dumps(header(RECEIVED, ORIGINAL)), "worker-received")
        receipts = capture.copy_authenticated_transport_receipts("\n".join((
            journal(receipt()), journal(receipt(), __REALTIME_TIMESTAMP="1770000000456000"))), PROCESS)

        self.assertEqual([row["nativeCompletedAtUnixMicros"] for row in receipts],
            ["1770000000123000", "1770000000456000"])
        result = capture.join_copy_captured_transports([body(ORIGINAL)], [body(RECEIVED)],
            first, second, receipts)

        self.assertEqual(result["joined"], [])
        self.assertEqual(result["unresolvedNativeRequestIds"], [ORIGINAL])
        self.assertIsNone(result["nativeBulkBytes"])

    def test_two_distinct_originals_retain_exclusive_success_receipts(self):
        other_original, other_received = "3" * 32, "4" * 32
        first = capture.capture_protected_headers("\n".join(json.dumps(header(identifier))
            for identifier in (ORIGINAL, other_original)), "native-outbound")
        second = capture.capture_protected_headers("\n".join((
            json.dumps(header(RECEIVED, ORIGINAL)),
            json.dumps(header(other_received, other_original)))), "worker-received")
        original, received = body(other_original), body(other_received)
        for row in (original, received):
            row["bodies"]["request"]["sha256"] = "5" * 64
        receipts = capture.copy_authenticated_transport_receipts("\n".join((
            journal(receipt()), journal(receipt(planId="6" * 32, requestSha256="5" * 64),
                __REALTIME_TIMESTAMP="1770000000456000"))), PROCESS)

        result = capture.join_copy_captured_transports([body(ORIGINAL), original],
            [body(RECEIVED), received], first, second, receipts)

        self.assertEqual(result["unresolvedNativeRequestIds"], [])
        self.assertEqual([row["nativeRequestId"] for row in result["joined"]], [ORIGINAL, other_original])
        self.assertEqual([row["completionObservationsUnixMicros"] for row in result["joined"]],
            [["1770000000123000"], ["1770000000456000"]])
        self.assertIsNone(result["nativeBulkBytes"])

    def test_private_file_stream_retains_more_than_4096_closed_records(self):
        count = 4097
        with tempfile.NamedTemporaryFile() as source:
            for index in range(count):
                source.write((json.dumps(header(f"{index:032x}")) + "\n").encode())
            source.flush()

            result = capture.capture_protected_headers(Path(source.name), "native-outbound")

        self.assertEqual(len(result), count)
        self.assertEqual(len(retained), count * 3)
        self.assertEqual(set(result), {f"{index:032x}" for index in range(count)})
        self.assertEqual(capture.PROTECTED_HEADER_RECORD_LIMIT, 204_704)

    def test_exact_record_raw_byte_and_row_ceilings_refuse_overflow(self):
        rows = "\n".join(json.dumps(header(f"{index:032x}")) for index in range(2)) + "\n"
        size = len(rows.encode())
        row_size = len(rows.splitlines(keepends=True)[0].encode())

        # Exercise the inclusive boundary with small selected ceilings; the
        # declared workload ceiling remains 204,704, independently checked above.
        with patch.object(capture, "PROTECTED_HEADER_RECORD_LIMIT", 2), \
                patch.object(capture, "PROTECTED_HEADER_LOG_BYTE_LIMIT", size), \
                patch.object(capture, "PROTECTED_HEADER_ROW_BYTE_LIMIT", row_size):
            self.assertEqual(len(capture.capture_protected_headers(rows, "native-outbound")), 2)

        for field, ceiling in (("PROTECTED_HEADER_RECORD_LIMIT", 1),
                ("PROTECTED_HEADER_LOG_BYTE_LIMIT", size - 1),
                ("PROTECTED_HEADER_ROW_BYTE_LIMIT", row_size - 1)):
            retained.clear()
            with self.subTest(field=field), patch.object(capture, field, ceiling), self.assertRaises(ValueError):
                capture.capture_protected_headers(rows, "native-outbound")

    def test_retained_summary_has_separate_byte_and_row_budgets(self):
        raw = json.dumps(header(ORIGINAL))
        result = capture.capture_protected_headers(raw, "native-outbound")
        size = len(json.dumps(result[ORIGINAL], separators=(",", ":")).encode())
        retained.clear()

        with patch.object(capture, "PROTECTED_HEADER_SUMMARY_BYTE_LIMIT", size), \
                patch.object(capture, "PROTECTED_HEADER_SUMMARY_ROW_LIMIT", size):
            self.assertEqual(len(capture.capture_protected_headers(raw, "native-outbound")), 1)

        for field in ("PROTECTED_HEADER_SUMMARY_BYTE_LIMIT", "PROTECTED_HEADER_SUMMARY_ROW_LIMIT"):
            retained.clear()
            with self.subTest(field=field), patch.object(capture, field, size - 1), self.assertRaises(ValueError):
                capture.capture_protected_headers(raw, "native-outbound")

    def test_unterminated_retained_file_is_incomplete_even_with_closed_json(self):
        with tempfile.NamedTemporaryFile() as source:
            source.write(json.dumps(header(ORIGINAL)).encode())
            source.flush()

            with self.assertRaises(ValueError):
                capture.capture_protected_headers(Path(source.name), "native-outbound")

        self.assertEqual(retained, {})


if __name__ == "__main__":
    unittest.main()
