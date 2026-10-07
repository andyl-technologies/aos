"""Controlled capture/schema joins; no VM, MAC, SQL or provider qualification."""

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import os
import re
import tempfile
import textwrap
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(path))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


capture = load("capture", "_hub-storage-capture.py")
review = load("review", "_hub-direct-review.py")
observations = load("observations", "_hub-direct-observations.py")
sql_projection = load("sql_projection", "_hub-native-sql-projection.py")
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
    return {"version": "2", "request_id": identifier, "origin_request_id": original,
        "path_and_query": ROUTE, "method": "POST", "phase": "", "status": "200",
        "ingress": "", "request_signature": "a" * 64, "reply_signature": "b" * 64,
        "query_class": "absent", "transport_call_id": original or identifier,
        "oci_request_signature": "", "oci_reply_signature": "", **changes}


def body(identifier):
    return {"requestId": identifier, "procedure": ROUTE, "method": "POST", "phase": "",
        "status": 200, "responseContentType": "application/json", "responseContentEncoding": "",
        "bodies": {"request": {"file": "/controlled/request", "sha256": "c" * 64, "byteSize": 17},
            "response": {"file": "/controlled/reply", "sha256": "d" * 64, "byteSize": 23}}}


def receipt(**changes):
    return {"version": 2, "transportCallId": ORIGINAL, "route": ROUTE, "planId": "e" * 32,
        "operation": "external_copy_control", "requestSha256": "c" * 64,
        "replySha256": "d" * 64, "requestBytes": 17, "replyBytes": 23, **changes}


def journal(value, event="external_copy_authenticated", **changes):
    return json.dumps({"_PID": "123", "_EXE": PROCESS["executablePath"],
        "_SYSTEMD_UNIT": "aos-hub.service", "__REALTIME_TIMESTAMP": "1770000000123000",
        "MESSAGE": "[INFO] message=" + event + " " + json.dumps(value)
            + ' span=registry_index registry_id=7', **changes})


class StorageCaptureTests(unittest.TestCase):
    def setUp(self):
        retained.clear()

    def test_selected_journal_retains_actual_sql_marker_without_broadening_window(self):
        """Execute generated guest code against a controlled journal/process image."""
        source_child = {"version": 1, "event": "sql_projection", "status": 200,
            "projection": {"version": 1, "checkpoints": [
                {"kind": "admission_checked_transaction", "sessionId": "session_1"}]}}
        sql_line = journal(source_child, event="native_application_sql_projection",
            MESSAGE="[INFO] message=native_application_sql_projection " + json.dumps(source_child))
        phase_line = journal({'terminalOutcome': 'returned_error'}, event='native_application_publication_phases',
            MESSAGE='[INFO] message=native_application_publication_phases ' + json.dumps({'terminalOutcome': 'returned_error'}))
        storage_line = journal(receipt())
        unrelated = journal({"irrelevant": True}, event="ordinary_application_event")
        argv_seen, process_reads = [], []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "123"
            image.mkdir()
            (image / "stat").write_text("123 (controlled) " + " ".join(["S", *(["0"] * 18), "12345"]))
            (image / "exe").write_bytes(b"controlled native executable")
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            selected = {"pid": 123, "startTicks": "12345", "root": str(evidence),
                "executablePath": PROCESS["executablePath"], "journalCursor": "controlled-cursor",
                "executableSha256": hashlib.sha256((image / "exe").read_bytes()).hexdigest()}
            original_path = Path
            original_readlink = os.readlink

            def guest_path(value):
                if str(value) == "/proc":
                    process_reads.append(value)
                    return image.parent
                return original_path(value)

            def guest_readlink(value):
                return selected["executablePath"] if original_path(value) == image / "exe" else original_readlink(value)

            def selected_journal(arguments, **options):
                argv_seen.append(arguments)
                self.assertEqual(options["timeout"], 45)
                self.assertFalse(options["check"])
                self.assertIn("--unit=aos-hub.service", arguments)
                self.assertIn("--after-cursor=controlled-cursor", arguments)
                pattern = next(argument.removeprefix("--grep=") for argument in arguments if argument.startswith("--grep="))
                # The generated argument's literal brackets and alternation use
                # the same subset of ERE syntax here; source escapes are not
                # interpreted a second time by this controlled journal.
                for line in (sql_line, phase_line, storage_line, unrelated):
                    if re.search(pattern, json.loads(line)["MESSAGE"]):
                        options["stdout"].write((line + "\n").encode())
                return types.SimpleNamespace(returncode=0)

            def guest(machine, python, body, document, timeout):
                self.assertEqual(timeout, 60)
                output = io.StringIO()
                with patch("pathlib.Path", guest_path), patch("os.readlink", guest_readlink), \
                        patch("subprocess.run", selected_journal), redirect_stdout(output):
                    exec(textwrap.dedent(body), {"selected": document, "json": json})
                return output.getvalue()

            def retain_window(machine, python, observed, name):
                self.assertEqual(observed["path"], str(evidence / "runtime.jsonl"))
                self.assertEqual(name, "publication-native-authenticated-storage.jsonl")
                return evidence / "runtime.jsonl", {"controlled": True}

            with patch.object(capture, "direct_guest_python", guest, create=True), \
                    patch.object(capture, "retain_direct_log_window", retain_window, create=True):
                retained_path, _ = capture.finish_native_copy_capture(None, {"python": "controlled"}, selected)
            raw = retained_path.read_text()
            self.assertEqual(raw, sql_line + "\n" + phase_line + "\n" + storage_line + "\n")
            self.assertNotIn("ordinary_application_event", raw)
            self.assertEqual(len(argv_seen), 1)
            self.assertEqual(len(process_reads), 2)
            children = capture.observed_native_messages(raw, selected)
            checkpoints = sql_projection.native_sql_checkpoints(children)
            self.assertEqual(checkpoints[0]["checkpoints"], source_child["projection"]["checkpoints"])
            self.assertEqual(checkpoints[0]["rawChildSha256"], hashlib.sha256(json.dumps(source_child).encode()).hexdigest())

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

    def test_managed_cleanup_controls_are_private_and_do_not_imply_authentication(self):
        route = "/_internal/storage/managed-oci-cleanup/v1"
        raw = header(ORIGINAL, version="4", path_and_query=route,
            request_signature="", reply_signature="",
            **{field: "" for field in capture.EXTERNAL_OCI_SIGNATURE_FIELDS},
            managed_oci_cleanup_request_signature="a" * 64,
            managed_oci_cleanup_reply_signature="b" * 64)
        original_headers = capture.capture_protected_headers(json.dumps(raw), "native-outbound")
        received = {**raw, "request_id": RECEIVED, "origin_request_id": ORIGINAL}
        received_headers = capture.capture_protected_headers(json.dumps(received), "worker-received")

        summary = json.dumps(original_headers)
        for field in capture.MANAGED_OCI_CLEANUP_SIGNATURE_FIELDS:
            reference = original_headers[ORIGINAL]["files"][field]
            self.assertEqual(reference["sha256"], hashlib.sha256(raw[field].encode()).hexdigest())
            self.assertEqual(reference["byteSize"], 64)
            self.assertNotIn(raw[field], summary)
        self.assertEqual(original_headers[ORIGINAL]["transportCallId"], ORIGINAL)
        originals = [{**body(ORIGINAL), "procedure": route}]
        actual = [{**body(RECEIVED), "procedure": route}]
        result = capture.join_authenticated_storage_transports(originals, actual,
            original_headers, received_headers, [])

        self.assertEqual(result["joined"], [])
        self.assertEqual(result["unresolvedNativeRequestIds"], [ORIGINAL])
        self.assertIsNone(result["nativeBulkBytes"])

    def test_managed_cleanup_header_schema_and_mac_substitution_refuse(self):
        raw = header(ORIGINAL, version="4", request_signature="", reply_signature="",
            **{field: "" for field in capture.EXTERNAL_OCI_SIGNATURE_FIELDS},
            managed_oci_cleanup_request_signature="a" * 64,
            managed_oci_cleanup_reply_signature="b" * 64)
        for changes in ({"version": "3"}, {"version": "2"},
                {"managed_oci_cleanup_request_signature": "a" * 64 + "," + "b" * 64},
                {"managed_oci_cleanup_reply_signature": "Bearer private"},
                {"authorization": "Bearer private"}):
            retained.clear()
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                capture.capture_protected_headers(json.dumps({**raw, **changes}), "native-outbound")
            self.assertNotIn(b"Bearer private", retained.values())
        del raw["managed_oci_cleanup_reply_signature"]
        with self.assertRaises(ValueError):
            capture.capture_protected_headers(json.dumps(raw), "native-outbound")

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
        rows = capture.authenticated_storage_transport_receipts(journal(receipt()), PROCESS)
        self.assertEqual(rows[0]["requestBytes"], 17)
        self.assertEqual(rows[0]["nativeCompletedAtUnixMicros"], "1770000000123000")
        for changes in ({"_PID": "124"}, {"_EXE": "/another/process"},
                {"_SYSTEMD_UNIT": "another.service"}, {"__REALTIME_TIMESTAMP": "-1"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                capture.authenticated_storage_transport_receipts(journal(receipt(), **changes), PROCESS)
        for changes in ({"requestBytes": True}, {"replyBytes": 65537},
                {"route": "/unsupported"}, {"operation": "external_copy_metadata"},
                {"callerPass": True}, {"transportCallId": "not-a-call"}, {"version": 1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                capture.authenticated_storage_transport_receipts(journal(receipt(**changes)), PROCESS)
        self.assertEqual(capture.authenticated_storage_transport_receipts(journal(receipt(),
            MESSAGE="[INFO] message=ordinary error mentions external_copy_authenticated fake"), PROCESS), [])

    def test_exact_original_received_headers_bodies_and_consumption_join(self):
        first = capture.capture_protected_headers(json.dumps(header(ORIGINAL)), "native-outbound")
        second = capture.capture_protected_headers(json.dumps(header(RECEIVED, ORIGINAL)), "worker-received")
        receipts = capture.authenticated_storage_transport_receipts(journal(receipt()), PROCESS)
        result = capture.join_authenticated_storage_transports([body(ORIGINAL)], [body(RECEIVED)], first, second, receipts)
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
            result = capture.join_authenticated_storage_transports([body(ORIGINAL)], [changed], first, second, receipts)
            self.assertEqual(result["unresolvedNativeRequestIds"], [ORIGINAL])
            self.assertEqual(result["joined"], [])
            self.assertIsNone(result["nativeBulkBytes"])
        changed = copy.deepcopy(second)
        changed[RECEIVED]["files"]["reply_signature"]["sha256"] = "f" * 64
        self.assertEqual(capture.join_authenticated_storage_transports([body(ORIGINAL)], [body(RECEIVED)],
            first, changed, receipts)["joined"], [])
        self.assertEqual(capture.join_authenticated_storage_transports([body(ORIGINAL)], [body(RECEIVED)],
            first, second, [])["joined"], [])

    def test_codec_selection_comes_only_from_joined_originals_and_keeps_unknowns(self):
        first = capture.capture_protected_headers(json.dumps(header(ORIGINAL)), "native-outbound")
        second = capture.capture_protected_headers(json.dumps(header(RECEIVED, ORIGINAL)), "worker-received")
        receipts = capture.authenticated_storage_transport_receipts(journal(receipt()), PROCESS)
        joined = capture.join_authenticated_storage_transports([body(ORIGINAL)], [body(RECEIVED)], first, second, receipts)
        selected = capture.prepare_storage_codec_cases(joined, [body(ORIGINAL)], [body(RECEIVED)],
            "f" * 64, "controlled-deployment")
        self.assertEqual(selected["cases"][0]["originalRequest"]["byteSize"], "17")
        self.assertEqual(selected["cases"][0]["requestId"], ORIGINAL)
        self.assertIsNone(selected["cases"][0]["originalIngress"])
        self.assertIsNone(joined["nativeBulkBytes"])
        self.assertIsNone(capture.prepare_storage_codec_cases({"joined": []}, [], [],
            "f" * 64, "controlled-deployment"))
        changed = copy.deepcopy(second)
        changed[RECEIVED]["files"]["path_and_query"]["sha256"] = "f" * 64
        self.assertEqual(capture.join_authenticated_storage_transports([body(ORIGINAL)], [body(RECEIVED)],
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
        receipts = capture.authenticated_storage_transport_receipts(journal(receipt()), PROCESS)
        result = capture.join_authenticated_storage_transports(
            [body(ORIGINAL), body(other_original)], [body(RECEIVED), body(other_received)],
            first, second, receipts)

        self.assertEqual([row["nativeRequestId"] for row in result["joined"]], [ORIGINAL])
        self.assertEqual(result["unresolvedNativeRequestIds"], [other_original])
        self.assertIsNone(result["nativeBulkBytes"])
        self.assertEqual(len(capture.prepare_storage_codec_cases(result,
            [body(ORIGINAL), body(other_original)], [body(RECEIVED), body(other_received)],
            "f" * 64, "controlled-deployment")["cases"]), 1)

    def test_distinct_completion_times_do_not_collapse_into_one_exchange(self):
        first = capture.capture_protected_headers(json.dumps(header(ORIGINAL)), "native-outbound")
        second = capture.capture_protected_headers(json.dumps(header(RECEIVED, ORIGINAL)), "worker-received")
        receipts = capture.authenticated_storage_transport_receipts("\n".join((
            journal(receipt()), journal(receipt(), __REALTIME_TIMESTAMP="1770000000456000"))), PROCESS)

        self.assertEqual([row["nativeCompletedAtUnixMicros"] for row in receipts],
            ["1770000000123000", "1770000000456000"])
        result = capture.join_authenticated_storage_transports([body(ORIGINAL)], [body(RECEIVED)],
            first, second, receipts)

        self.assertEqual(result["joined"], [])
        self.assertEqual(result["unresolvedNativeRequestIds"], [ORIGINAL])
        self.assertIsNone(result["nativeBulkBytes"])

    def test_identical_successes_are_owned_by_their_distinct_transport_calls(self):
        other_original, other_received = "3" * 32, "4" * 32
        first = capture.capture_protected_headers("\n".join(json.dumps(header(identifier))
            for identifier in (ORIGINAL, other_original)), "native-outbound")
        second = capture.capture_protected_headers("\n".join((
            json.dumps(header(RECEIVED, ORIGINAL)),
            json.dumps(header(other_received, other_original)))), "worker-received")
        receipts = capture.authenticated_storage_transport_receipts("\n".join((
            journal(receipt()), journal(receipt(transportCallId=other_original),
                __REALTIME_TIMESTAMP="1770000000456000"))), PROCESS)

        result = capture.join_authenticated_storage_transports(
            [body(ORIGINAL), body(other_original)], [body(RECEIVED), body(other_received)],
            first, second, receipts)

        self.assertEqual(result["unresolvedNativeRequestIds"], [])
        self.assertEqual([row["nativeRequestId"] for row in result["joined"]], [ORIGINAL, other_original])
        self.assertEqual([row["completionObservationsUnixMicros"] for row in result["joined"]],
            [["1770000000123000"], ["1770000000456000"]])
        self.assertIsNone(result["nativeBulkBytes"])

        # A reused call ID is ambiguous even if the immutable bodies match.
        changed_first, changed_second = copy.deepcopy(first), copy.deepcopy(second)
        changed_first[other_original]["transportCallId"] = ORIGINAL
        changed_second[other_received]["transportCallId"] = ORIGINAL
        result = capture.join_authenticated_storage_transports(
            [body(ORIGINAL), body(other_original)], [body(RECEIVED), body(other_received)],
            changed_first, changed_second, receipts)
        self.assertEqual(result["joined"], [])
        self.assertEqual(result["unresolvedNativeRequestIds"], [ORIGINAL, other_original])

    def test_call_id_missing_substituted_or_receipt_reused_remains_unresolved(self):
        first = capture.capture_protected_headers(json.dumps(header(ORIGINAL)), "native-outbound")
        second = capture.capture_protected_headers(json.dumps(header(RECEIVED, ORIGINAL)), "worker-received")
        receipts = capture.authenticated_storage_transport_receipts(journal(receipt()), PROCESS)
        for value in (None, "f" * 32):
            changed = copy.deepcopy(second)
            changed[RECEIVED]["transportCallId"] = value
            result = capture.join_authenticated_storage_transports([body(ORIGINAL)], [body(RECEIVED)],
                first, changed, receipts)
            self.assertEqual(result["joined"], [])
            self.assertIsNone(result["nativeBulkBytes"])
        result = capture.join_authenticated_storage_transports([body(ORIGINAL)], [body(RECEIVED)],
            first, second, receipts + [{**receipts[0], "replySha256": "f" * 64}])
        self.assertEqual(result["joined"], [])

    def test_oci_projection_requires_its_own_signature_and_post_authentication_event(self):
        route = capture.OCI_CAPTURE_ROUTE
        fields = {"path_and_query": route, "request_signature": "", "reply_signature": "",
            "oci_request_signature": "a" * 64, "oci_reply_signature": "b" * 64}
        first = capture.capture_protected_headers(json.dumps(header(ORIGINAL, **fields)), "native-outbound")
        second = capture.capture_protected_headers(json.dumps(header(RECEIVED, ORIGINAL, **fields)), "worker-received")
        original, received = body(ORIGINAL), body(RECEIVED)
        for row in (original, received):
            row["procedure"] = route
        value = receipt(route=route, planId="e" * 64, operation="OciDocumentProjection")
        receipts = capture.authenticated_storage_transport_receipts(
            journal(value, event="oci_projection_authenticated"), PROCESS)

        result = capture.join_authenticated_storage_transports([original], [received], first, second, receipts)

        self.assertEqual(result["joined"][0]["operation"], "OciDocumentProjection")
        self.assertIsNone(result["nativeBulkBytes"])
        self.assertIsNone(result["joined"][0]["purposeArtifactEvidence"])
        changed = copy.deepcopy(second)
        changed[RECEIVED]["files"]["oci_reply_signature"]["sha256"] = "f" * 64
        self.assertEqual(capture.join_authenticated_storage_transports(
            [original], [received], first, changed, receipts)["joined"], [])
        with self.assertRaises(ValueError):
            capture.authenticated_storage_transport_receipts(journal(value), PROCESS)

        # The shared OCI projection envelope admits a 4 MiB document graph
        # plus 64 KiB framing; observation must not shrink that real contract.
        maximum = 4 * 1024 * 1024 + 64 * 1024
        accepted = capture.authenticated_storage_transport_receipts(journal(
            {**value, "replyBytes": maximum}, event="oci_projection_authenticated"), PROCESS)
        self.assertEqual(accepted[0]["replyBytes"], maximum)
        with self.assertRaises(ValueError):
            capture.authenticated_storage_transport_receipts(journal(
                {**value, "replyBytes": maximum + 1}, event="oci_projection_authenticated"), PROCESS)

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
        receipts = capture.authenticated_storage_transport_receipts("\n".join((
            journal(receipt()), journal(receipt(planId="6" * 32, requestSha256="5" * 64,
                transportCallId=other_original),
                __REALTIME_TIMESTAMP="1770000000456000"))), PROCESS)

        result = capture.join_authenticated_storage_transports([body(ORIGINAL), original],
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
