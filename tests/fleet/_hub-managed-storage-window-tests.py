"""Actual local process custody and controlled decoder-join refusal tests.

The local process is the test interpreter, never a Native/Worker deployment.
Controlled decoder output exercises correlation only, not MAC or authority.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).parent


def environment():
    scope = {}
    for name in ("_hub-direct-storage-boundary.py", "_hub-native-corpus-segments.py",
            "_hub-direct-observations.py", "_hub-direct-boundary.py",
            "_hub-storage-capture.py", "_hub-storage-final-sql.py",
            "_hub-storage-workflow-assessment.py", "_hub-managed-storage-window.py"):
        exec(compile((ROOT / name).read_bytes(), name, "exec"), scope)
    scope["_closed_review_json"] = json.loads
    return scope


class ManagedWindowTests(unittest.TestCase):
    def test_transfer_completion_parser_keeps_unknown_and_refuses_substitution(self):
        scope = environment()
        identifier = "a" * 32
        row = {"procedure": "/v2/fixture/blobs/uploads/" + "b" * 32,
            "phase": "", "status": "204", "request_http_bytes": "120",
            "request_body_bytes": "0", "response_body_bytes": "0", "response_http_bytes": "120",
            "elapsed_seconds": "0.001", "upstream_status": "204", "upstream_seconds": "0.001",
            "request_id": identifier, "request_body_file": "", "response_body_file": "/controlled/empty",
            "method": "GET", "response_content_type": "", "request_transfer_encoding": "",
            "response_content_encoding": "", "completed_unix_seconds": "1700000000.123",
            "request_completion": "OK", "upstream_response_bytes": "0"}
        parse = scope["managed_ingress_completion_receipts"]
        _, clocks, facts = parse(json.dumps(row))
        self.assertEqual(clocks[identifier], "1700000000123")
        self.assertEqual(facts[identifier], {"requestCompletion": "OK", "upstreamResponseBytes": 0})
        unknown = {**row, "request_completion": "", "upstream_response_bytes": "-"}
        self.assertIsNone(parse(json.dumps(unknown))[2][identifier]["upstreamResponseBytes"])
        for bad in ({**row, "upstream_response_bytes": "0, 0"},
                {**row, "request_completion": "OK "}, {**row, "extra": "pass"},
                {key: value for key, value in row.items() if key != "request_completion"}):
            with self.assertRaises(ValueError):
                parse(json.dumps(bad))
        with self.assertRaises(ValueError):
            parse(json.dumps(row) + "\n" + json.dumps(row))

    def test_completed_empty_responses_require_actual_facts_at_each_proxy(self):
        scope = environment()
        scope["read_direct_guest_file"] = lambda *arguments: (_ for _ in ()).throw(ValueError("no stored response"))
        scope["retain_direct_flow"] = lambda name, value: hashlib.sha256(
            value if isinstance(value, bytes) else json.dumps(value).encode()).hexdigest()
        run = "a" * 32
        row = {"request_id": "b" * 32, "procedure": "/v2/fixture/blobs/uploads/" + "c" * 32,
            "phase": "", "status": 204, "upstream_status": 204, "method": "GET",
            "response_content_type": "", "response_content_encoding": "",
            "request_transfer_encoding": "", "request_body_bytes": 0,
            "response_body_bytes": 0, "request_body_file": "",
            "response_body_file": "/var/lib/hybrid-managed-native/" + run + "/inbound/response-bodies/" + "b" * 32}
        facts = {"requestCompletion": "OK", "upstreamResponseBytes": 0}
        capture = scope["capture_direct_native_bodies"]
        arguments = (None, {"python": "controlled"}, [row],
            "/var/lib/hybrid-managed-native/" + run + "/inbound", "managed-" + run + "-window-native")
        _, receipt = capture(*arguments, empty_response_observations={row["request_id"]: facts})
        retained = receipt["bodies"][0]
        self.assertEqual(retained["bodies"]["response"]["sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(retained["bodies"]["response"]["byteSize"], 0)
        self.assertEqual(retained["emptyResponseObservation"]["kind"], "measured_completed_empty_transport")
        for changed in (None, {**facts, "requestCompletion": ""},
                {**facts, "upstreamResponseBytes": 1}, {**facts, "upstreamResponseBytes": None}):
            _, receipt = capture(*arguments, empty_response_observations={row["request_id"]: changed})
            self.assertIsNone(receipt["bodies"][0]["bodies"]["response"])
            self.assertEqual(len(receipt["incompleteCaptures"]), 1)
        for field, value in (("upstream_status", 500), ("response_body_bytes", 1)):
            bad = {**row, field: value}
            self.assertFalse(scope["managed_completed_empty_response"](bad, facts))

    def test_independent_ingress_pairs_preserve_missing_substituted_and_duplicate_calls(self):
        scope = environment()
        target = "/v2/fixture/blobs/uploads/" + "a" * 32 + "?digest=sha256%3A" + "b" * 64
        scope["direct_selected_bytes"] = lambda reference, limit: target.encode()
        body = {"file": "/controlled/body", "sha256": "c" * 64, "byteSize": 0}
        original = {"requestId": "1" * 32, "procedure": target.split("?", 1)[0],
            "method": "PATCH", "phase": "authorize-final", "status": 200,
            "responseContentType": "application/json", "responseContentEncoding": "",
            "bodies": {"request": body, "response": body}}
        received = {**copy.deepcopy(original), "requestId": "2" * 32}
        header = {"requestId": original["requestId"], "originalRequestId": None,
            "method": "PATCH", "phase": "authorize-final", "status": 200, "queryClass": "retained",
            "files": {"path_and_query": {"file": "/controlled/target", "sha256": "d" * 64,
                "byteSize": len(target)}, "ingress": {"file": "/controlled/ingress",
                "sha256": "e" * 64, "byteSize": 128}}}
        received_header = {**copy.deepcopy(header), "requestId": received["requestId"],
            "originalRequestId": original["requestId"]}
        arguments = [[original], [received], {original["requestId"]: [received["requestId"]]},
            {original["requestId"]: header}, {received["requestId"]: received_header}, "f" * 64, "fixture"]
        result = scope["prepare_managed_ingress_codec_segments"](*arguments)
        self.assertEqual(result["completeOriginalInventory"]["originalCount"], 2)
        self.assertEqual(result["selectedCodecSegments"]["segments"][0]["manifest"]["cases"][0]["pathAndQuery"], target)
        self.assertEqual(result["unresolvedOriginalRequestIds"], [])
        self.assertIsNone(result["nativeBulkBytes"])

        for defect in ("duplicate", "body", "compact", "missing", "target"):
            changed = copy.deepcopy(arguments)
            if defect == "duplicate":
                changed[2][original["requestId"]].append(received["requestId"])
            elif defect == "body":
                changed[1][0]["bodies"]["request"]["sha256"] = "9" * 64
            elif defect == "compact":
                changed[4][received["requestId"]]["files"]["ingress"]["sha256"] = "9" * 64
            elif defect == "missing":
                changed[4].clear()
            else:
                scope["direct_selected_bytes"] = lambda reference, limit: b"/unsupported"
            with self.subTest(defect=defect):
                refused = scope["prepare_managed_ingress_codec_segments"](*changed)
                self.assertIsNone(refused["selectedCodecSegments"])
                self.assertEqual(refused["unresolvedOriginalRequestIds"], [original["requestId"]])
                self.assertEqual(refused["unselectedReceivedRequestIds"], [received["requestId"]])
                self.assertIsNone(refused["nativeBulkBytes"])

    def test_plain_file_event_retains_unknown_clock_and_changed_custody_refuses(self):
        scope = environment()
        process = {"pid": 1, "ownerUid": os.getuid(), "startTicks": "1",
            "executableSha256": "a" * 64, "commandLineSha256": "b" * 64,
            "commandLineBytes": "20", "environmentSha256": "c" * 64,
            "logFile": "/controlled/native-accepted.log"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "actual.log"
            body = b"[INFO] message=unrelated event\n"
            path.write_bytes(body)
            path.chmod(0o600)
            window = {"file": str(path), "sha256": hashlib.sha256(body).hexdigest(),
                "capturedBytes": len(body), "before": {"path": process["logFile"],
                    "device": "1", "inode": "2", "byteSize": 0},
                "after": {"path": process["logFile"], "device": "1", "inode": "2", "byteSize": len(body)}}
            provenance = {"beforeProcess": process, "afterProcess": process, "window": window}
            rows = list(scope["observed_native_messages"](path, process, provenance))
            self.assertEqual(rows, [(body.decode().rstrip("\n"), None)])
            for changed in ({**provenance, "afterProcess": {**process, "startTicks": "2"}},
                    {**provenance, "window": {**window, "sha256": "0" * 64}}):
                with self.assertRaises(ValueError):
                    list(scope["observed_native_messages"](path, process, changed))
            path.write_bytes(body[:-1])
            with self.assertRaises(ValueError):
                list(scope["observed_native_messages"](path, process, provenance))

    def test_actual_local_process_is_pinned_and_modified_invocation_or_environment_refuses(self):
        scope = environment()
        root = Path("/proc") / str(os.getpid())
        command = (root / "cmdline").read_bytes()
        selected = {"version": 1, "pid": os.getpid(), "ownerUid": os.getuid(),
            "startTicks": (root / "stat").read_text().rpartition(") ")[2].split()[19],
            "arguments": [value.decode() for value in command.rstrip(b"\0").split(b"\0")],
            "executableSha256": hashlib.sha256((root / "exe").read_bytes()).hexdigest(),
            "environmentSha256": hashlib.sha256((root / "environ").read_bytes()).hexdigest(),
            "commandLineSha256": hashlib.sha256(command).hexdigest(),
            "commandLineBytes": str(len(command)), "logFile": "/controlled/private.log",
            "invocationObservationMode": "original_argv"}
        def local_guest(machine, python, source, selection, timeout=30):
            prelude = "import json\nselected = json.loads(" + repr(json.dumps(selection)) + ")\n"
            # Guest helper bodies normally receive indentation normalization
            # from direct_guest_python. Normalize the concatenated body here.
            import textwrap
            marker = "\n        import hashlib, os, time\n"
            common, body = source.split(marker, 1)
            script = prelude + common + "\n" + textwrap.dedent(marker + body)
            result = subprocess.run([python, "-c", script], capture_output=True, timeout=timeout)
            if result.returncode:
                raise ValueError("controlled local process observation refused")
            return result.stdout.decode()
        scope["direct_guest_python"] = local_guest
        tools = {"python": str(Path("/proc/self/exe").resolve())}
        result = scope["observe_managed_process"](None, tools, selected)
        self.assertEqual(result["pid"], selected["pid"])
        self.assertEqual(result["commandLineSha256"], selected["commandLineSha256"])
        for field in ("startTicks", "executableSha256", "environmentSha256", "commandLineSha256"):
            altered = {**selected, field: "0" if field == "startTicks" else "0" * 64}
            with self.subTest(field=field), self.assertRaises(ValueError):
                scope["observe_managed_process"](None, tools, altered)

    def test_pair_source_and_window_substitution_refuse_before_collection(self):
        scope = environment()
        prepared = {"captureSelection": {"run": "a" * 32, "sourceDigest": "b" * 64,
            "nativeAddress": "192.168.50.1"}}
        boundary = {"run": "a" * 32}
        self.assertEqual(scope["managed_window_selector"](prepared, boundary, "gc")["run"], "a" * 32)
        for changed in ({"run": "c" * 32}, {"run": "a" * 32, "pass": True}):
            if "pass" in changed:
                bad = copy.deepcopy(prepared)
                bad["captureSelection"]["pass"] = True
                arguments = (bad, boundary, "gc")
            else:
                arguments = (prepared, changed, "gc")
            with self.assertRaises(ValueError):
                scope["managed_window_selector"](*arguments)

    def codec_fixture(self, directory):
        scope = environment()
        def reference(name, value):
            body = json.dumps(value, separators=(",", ":")).encode()
            path = Path(directory) / name
            path.write_bytes(body)
            path.chmod(0o600)
            return {"file": str(path), "sha256": hashlib.sha256(body).hexdigest(), "byteSize": len(body)}
        request = reference("request", {"plan_id": "a" * 32})
        reply = reference("reply", {"plan_id": "a" * 32, "source_bytes": 0})
        capture = {"requestId": "c" * 32, "procedure": "/_internal/storage/v1/execute",
            "method": "POST", "phase": "", "status": 200,
            "responseContentType": "application/json", "responseContentEncoding": "",
            "storageWorkSelection": {"originalPlan": request}, "bodies": {"request": request, "response": reply}}
        provenance = {"version": 1, "runtimeCodecRevision": "e" * 40,
            "nativeExecutableSha256": "f" * 64, "workerSourceDigest": "b" * 64,
            "sourceArchiveSha256": "1" * 64, "codecSourceSha256": "2" * 64}
        selection = {"runtimeProvenance": {"path": "/controlled/provenance", "sha256": "3" * 64},
            "observerExecutable": {"path": "/controlled/codec", "sha256": "4" * 64}}
        completion = {"requestId": capture["requestId"], "operation": "head",
            "requestSha256": request["sha256"], "replySha256": reply["sha256"],
            "requestBytes": request["byteSize"], "replyBytes": reply["byteSize"],
            "planIdSha256": hashlib.sha256(("a" * 32).encode()).hexdigest()}
        boundary = {"captures": [capture], "authenticatedCompletions": [completion],
            "captureProvenance": {"sourceDigest": "b" * 64, "nativeExecutableSha256": "f" * 64,
                "deploymentId": "controlled"}}
        def selected_bytes(ref, maximum):
            if ref["path"] == "/controlled/provenance":
                return json.dumps(provenance).encode()
            body = Path(ref["path"]).read_bytes()
            if len(body) > maximum or hashlib.sha256(body).hexdigest() != ref["sha256"]:
                raise ValueError("controlled actual file commitment differs")
            return body
        output = {"requestId": capture["requestId"], "sourceDigest": "b" * 64,
            "codecSourceSha256": "2" * 64, "class": "storage_work_gc_metadata", "operation": "head",
            "requestSha256": request["sha256"], "replySha256": reply["sha256"],
            "exchangeIdSha256": completion["planIdSha256"], "originalContextSha256": request["sha256"],
            "payload": {"requestRawObjectBytes": "0", "replyRawObjectBytes": "0",
                "selectedDataBytes": "0", "semanticOciProjectionBytes": "0"}}
        scope["direct_selected_bytes"] = selected_bytes
        scope["retain_direct_flow"] = lambda name, value: hashlib.sha256(scope["native_corpus_json"](value)
            if not isinstance(value, bytes) else value).hexdigest()
        scope["run_direct_native_codec_observer"] = lambda *args, **kwargs: [output]
        scope["WORKER_CONTROL_REPLY_LIMIT"] = 8 * 1024 * 1024
        return scope, capture, boundary, selection, provenance, output

    def test_controlled_codec_requires_exact_selected_tuple_completion_and_consumed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            scope, capture, boundary, selection, provenance, output = self.codec_fixture(directory)
            classify = scope["classify_managed_storage_capture"]
            result = classify(capture, boundary, "gc", selection, provenance)
            self.assertEqual(result["plan"]["plan_id"], "a" * 32)
            self.assertEqual(result["validationReceipt"]["exitCode"], 0)
            self.assertIsNone(result["nativeBulkBytes"])
            for change in (lambda: boundary["authenticatedCompletions"].append(
                    boundary["authenticatedCompletions"][0]),
                    lambda: output.update(sourceDigest="9" * 64),
                    lambda: Path(capture["bodies"]["response"]["file"]).write_bytes(b"{}")):
                scope, capture, boundary, selection, provenance, output = self.codec_fixture(directory)
                change()
                with self.assertRaises(ValueError):
                    scope["classify_managed_storage_capture"](capture, boundary, "gc", selection, provenance)


if __name__ == "__main__":
    unittest.main()
