"""Hermetic synthetic hosted joins; no provider or runtime qualification."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location("hosted_assessment", ROOT / "hosted_assessment.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
SUPPORT = runpy.run_path(str(ROOT / "test_support.py"))
OBSERVER = SUPPORT["fixtures"](ROOT)


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sequence = 0
        self.old_capture_sha = adapter.CAPTURE_IMPLEMENTATION_SHA
        adapter.CAPTURE_IMPLEMENTATION_SHA = "9" * 64
        self.addCleanup(setattr, adapter, "CAPTURE_IMPLEMENTATION_SHA", self.old_capture_sha)
        self.actual_report = json.loads((OBSERVER / "cli-proof/positive-stdout.json").read_bytes())
        self.codec = self.actual_report["captures"][1]
        self.call = "b" * 32
        request = (OBSERVER / "cli-proof/storage-request.bin").read_bytes()
        reply = (OBSERVER / "cli-proof/storage-response.bin").read_bytes()
        self.receipts = {}
        for direction, raw in (("received_request", request), ("exposed_response", reply)):
            self.receipts[direction] = {
                "role": "storage_wrapper", "method": "POST", "pathSha256": adapter.sha(b"/_internal/storage/v1/execute"),
                "transportCallId": self.call, "queryClass": "absent", "state": "eof", "eof": True,
                "capturePersistence": "written", "responseConsumptionClaim": False,
                "observedBytes": str(len(raw)), "retainedBytes": str(len(raw)), "status": 200,
                "provenance": "independent_wrapper_received_bytes" if direction == "received_request" else "wrapper_exposed_reply_bytes",
                "imageKind": "complete_received_image" if direction == "received_request" else "complete_wrapper_reply_image",
                "privateImages": [{"name": "body", "bytes": str(len(raw)), "sha256": adapter.sha(raw), "reference": self.private(raw)}],
            }
        self.attempt = {
            "version": 1, "invocationId": "c" * 32, "transportCallId": self.call,
            "attempt": 1, "planId": "a" * 32, "operation": "head", "endpointScheme": "https",
            "offeredRequestSha256": adapter.sha(request), "offeredRequestBytes": str(len(request)),
            "replyStatus": 200, "exposedReplySha256": adapter.sha(reply), "exposedReplyBytes": str(len(reply)),
            "replyEof": True, "unreadResponse": False, "outcome": "typed_result_checked",
            "elapsedMicros": "1", "observedAtUnixMicros": "100", "replyMacAuthentication": None,
        }
        self.context = {"version": 1, "attempt": dict(self.attempt), "contextKind": "surface_fetch_current_sql",
                        "commitments": {"placementStateSha256": "4" * 64, "bindingStateSha256": "5" * 64},
                        "completedAtUnixMicros": "101"}

    def private(self, raw):
        path = self.root / str(self.sequence)
        self.sequence += 1
        path.write_bytes(raw)
        path.chmod(0o600)
        return {"file": str(path), "sha256": adapter.sha(raw), "byteSize": str(len(raw))}

    def json_ref(self, value):
        return self.private(json.dumps(value, separators=(",", ":")).encode())

    def ref(self, path):
        raw = path.read_bytes()
        return {"file": str(path), "sha256": adapter.sha(raw), "byteSize": str(len(raw))}

    def selection(self):
        return {"version": 1, "runtime": dict(adapter.RUNTIME),
                "runtimeProvenance": self.ref(OBSERVER / "runtime-provenance.json"),
                "bodyManifest": self.ref(OBSERVER / "cli-proof/positive-manifest.json"),
                "observerExecutable": self.ref(Path(adapter.PACKAGE["observerExecutable"]["file"])),
                "authSidecar": None, "capturePolicy": None, "captureExport": None, "sdkApplicationLog": None,
                "clientApplicationLog": None, "indexSnapshots": None, "workloadWindows": [], "wireMetrics": None}

    def test_actual_codec_cli_with_missing_evidence_retains_incomplete(self):
        selected = self.selection()
        selected["workloadWindows"] = [self.json_ref({"successfulPublishers": 2, "retained": True})]
        path = self.json_ref(selected)["file"]
        process = subprocess.run([sys.executable, str(ROOT / "hosted_assessment.py"), path],
                                 capture_output=True, timeout=60, check=False)
        self.assertEqual(process.returncode, 2, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["hostedAcceptance"], "incomplete")
        self.assertIsNone(result["applicationBodyAssessment"]["nativeBulkBytes"])
        self.assertIsNone(result["applicationBodyAssessment"]["nativeCapturedObjectPayloadBytes"])
        self.assertIsNone(result["applicationProviderLedger"]["httpProviderRows"])
        self.assertEqual(len(result["loadedWindowReferences"]), 1)

    def test_selected_receiver_image_matches_native_without_deployment_proof(self):
        joined = adapter.receiver_pair(self.call, self.receipts, self.attempt, self.context, self.codec)
        self.assertEqual(joined["requestImage"], "matched_selected_receiver_byte_image")
        self.assertEqual(joined["nativeReplyConsumedBytes"], self.attempt["exposedReplyBytes"])
        self.assertTrue(joined["fullReplyConsumed"])
        self.assertEqual(joined["finalSqlContext"], self.context["commitments"])
        self.assertIn("independent_current_original_policy_and_provider_mapping_required", joined["missing"])
        self.assertIn("independent_current_receiver_deployment_and_window_proof_required", joined["missing"])

    def test_wrapper_full_reply_does_not_prove_native_consumption(self):
        attempt = dict(self.attempt, exposedReplyBytes="0", exposedReplySha256=adapter.sha(b""),
                       replyEof=False, unreadResponse=True, outcome="http_rejected")
        joined = adapter.receiver_pair(self.call, self.receipts, attempt, None, self.codec)
        self.assertFalse(joined["fullReplyConsumed"])
        self.assertEqual(joined["nativeReplyConsumedBytes"], "0")
        self.assertIn("reply_not_fully_checked", joined["missing"])
        self.assertIsNone(joined["finalSqlContext"])

    def test_correlation_source_bytes_and_partial_receiver_refuse(self):
        for change in (
                lambda pair: pair["received_request"].update(transportCallId="e" * 32),
                lambda pair: pair["received_request"].update(state="cancelled", eof=False),
                lambda pair: pair["exposed_response"].update(observedBytes="0")):
            pair = copy.deepcopy(self.receipts)
            change(pair)
            result = adapter.receiver_pair(self.call, pair, self.attempt, self.context, self.codec)
            self.assertIsNone(result["requestImage"])
            self.assertIn("receiver_native_codec_join_mismatch", result["missing"])
        changed = copy.deepcopy(self.codec)
        changed["storageWork"]["planIdSha256"] = "f" * 64
        self.assertIsNone(adapter.receiver_pair(self.call, self.receipts, self.attempt, self.context, changed)["requestImage"])

    def client(self, ordinal=1, outcome="accepted"):
        return {"version": 1, "purpose": "upload_part", "observerSourceSha256": "1" * 64,
                "processId": 456, "attemptOrdinal": ordinal, "startedAtMillis": 1, "completedAtMillis": 2,
                "sessionSha256": "1" * 64, "originalSha256": "2" * 64, "clientOperationSha256": "3" * 64,
                "placementSha256": "4" * 64, "partSha256": "5" * 64,
                "providerOriginSha256": "6" * 64, "providerPathSha256": "7" * 64,
                "offered": {"bytes": 8, "sha256": adapter.sha(b"fixture!"), "eof": True, "failed": False, "overflow": False},
                "reply": {"bytes": 0, "sha256": adapter.sha(b""), "eof": True, "failed": False, "overflow": False},
                "status": 200, "etagSha256": "8" * 64, "outcome": outcome}

    def test_client_retry_counts_unique_offered_bytes_not_wire_or_settlement(self):
        first = self.client()
        pending = dict(first, completedAtMillis=None, offered=None, reply=None, status=None,
                       etagSha256=None, outcome="pending")
        result = adapter.client_summary([pending, first, self.client(2)])
        self.assertEqual(result["allAttemptOfferedBytes"], "16")
        self.assertEqual(result["uniqueAcknowledgedOfferedBytes"], "8")
        self.assertEqual(result["uniqueAcceptedPartCommitments"], 1)
        self.assertIsNone(result["wireBytes"])
        self.assertIsNone(result["providerConsumedBytes"])
        self.assertEqual(result["settlement"], "not_observed")
        with self.assertRaises(ValueError):
            adapter.client_summary([first, first])
        changed = self.client(2)
        changed["offered"]["sha256"] = "a" * 64
        with self.assertRaises(ValueError):
            adapter.client_summary([first, changed])

    def test_unknown_partial_and_missing_original_never_become_acknowledged_bytes(self):
        for mutate in (lambda row: row.update(outcome="unknown"),
                       lambda row: row["offered"].update(eof=False),
                       lambda row: row["reply"].update(failed=True),
                       lambda row: row.update(partSha256=None),
                       lambda row: row.update(status=201)):
            row = self.client()
            mutate(row)
            result = adapter.client_summary([row])
            self.assertEqual(result["uniqueAcknowledgedOfferedBytes"], "0")
            self.assertEqual(len(result["unresolvedAttempts"]), 1)

    def test_sdk_return_without_original_does_not_become_http_or_settlement(self):
        start = {"version": 1, "purpose": "direct_upload_sdk", "observerSourceSha256": "2" * 64,
                 "sourceDigest": adapter.RUNTIME["workerSourceDigest"], "isolateSha256": "a" * 64,
                 "attemptOrdinal": 1, "atMillis": 1, "operation": "head", "keySha256": "b" * 64,
                 "original": None, "outcome": "dispatch_attempt"}
        result = adapter.sdk_summary([start, dict(start, atMillis=2, outcome="sdk_returned")], start["sourceDigest"])
        self.assertEqual(result["unresolvedDispatches"], 1)
        self.assertIsNone(result["httpRequests"])
        self.assertIsNone(result["bodyBytes"])
        with self.assertRaises(ValueError):
            adapter.sdk_summary([start, dict(start, outcome="sdk_returned", keySha256="c" * 64)], start["sourceDigest"])

    def test_uninstalled_application_producer_cannot_adopt_log_commitment(self):
        selected = self.selection()
        selected["clientApplicationLog"] = {"log": self.private(b""),
            "processWindow": self.json_ref({"synthetic": True}), "producerSourceSha256": "1" * 64}
        with self.assertRaisesRegex(ValueError, "producer is unavailable"):
            adapter.assess(selected)

    def test_source_log_reader_requires_closed_events_and_source_pin(self):
        row = self.client()
        reference = self.private(b"[INFO] direct_upload_part_application_observation " + json.dumps(row).encode() + b"\n")
        observed = adapter.application_records(reference, "direct_upload_part_application_observation ", adapter.CLIENT_FIELDS)
        self.assertEqual(observed, [row])
        row["fakeHttpBytes"] = 8
        reference = self.private(b"direct_upload_part_application_observation " + json.dumps(row).encode())
        with self.assertRaises(ValueError):
            adapter.application_records(reference, "direct_upload_part_application_observation ", adapter.CLIENT_FIELDS)
        reference["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            adapter.read(reference)

    def test_actual_native_attempt_parser_and_clock_process_bracket(self):
        wrapper_tests = runpy.run_path(str(ROOT / "native_auth_tests.py"))
        fixture = wrapper_tests["ContextTests"]()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        selected = fixture.selected
        raw = b"".join(json.dumps({"_PID": str(fixture.process["pid"]),
            "_EXE": fixture.process["executablePath"], "_SYSTEMD_UNIT": "aos-hub.service",
            "__REALTIME_TIMESTAMP": "100", "MESSAGE": "[INFO] message=" + kind + " "
            + json.dumps(row, separators=(",", ":"))}).encode() + b"\n" for kind, row in (
                ("storage_work_attempt_observed", self.attempt),
                ("storage_work_final_sql_checked", self.context)))
        selected["nativeLog"]["reference"] = self.private(raw)
        records = adapter.execute_records(selected)
        self.assertEqual(records["attempts"][0]["value"], self.attempt)
        self.assertEqual(records["finalContexts"][0]["value"], self.context)
        selected["nativeLog"]["epoch"]["lastUnixMicros"] = "100"
        with self.assertRaises(ValueError):
            adapter.execute_records(selected)

    def test_actual_export_policy_and_connected_native_codec_join(self):
        fixture = runpy.run_path(str(ROOT / "native_auth_tests.py"))["ContextTests"]()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        selected = self.selection()
        selected["bodyManifest"] = self.json_ref(fixture.manifest)
        log = adapter.read(fixture.selected["nativeLog"]["reference"], 256 * adapter.MAX_JSON)
        log += b"".join(json.dumps({"_PID": str(fixture.process["pid"]),
            "_EXE": fixture.process["executablePath"], "_SYSTEMD_UNIT": "aos-hub.service",
            "__REALTIME_TIMESTAMP": "100", "MESSAGE": "[INFO] message=" + kind + " "
            + json.dumps(row, separators=(",", ":"))}).encode() + b"\n" for kind, row in (
                ("storage_work_attempt_observed", self.attempt), ("storage_work_final_sql_checked", self.context)))
        fixture.selected["nativeLog"]["reference"] = self.private(log)
        selected["authSidecar"] = self.json_ref(fixture.selected)
        policy = {"version": 1, "corpusId": "1" * 32, "windowId": "2" * 32,
            "sourceCommit": adapter.SOURCE_COMMIT, "sourceTree": adapter.SOURCE_TREE,
            "runtimeSourceDigest": adapter.RUNTIME["workerSourceDigest"],
            "nativeExecutableSha256": adapter.RUNTIME["nativeExecutableSha256"],
            "workerSourceDigest": adapter.RUNTIME["workerSourceDigest"],
            "captureImplementationSha256": adapter.CAPTURE_IMPLEMENTATION_SHA,
            "startsAt": 0, "expiresAt": 3600, "capturePrefix": "private-capture/" + "1" * 32 + "/",
            "storageOrigin": "https://storage.example", "originProxyOrigin": "https://origin.example",
            "originRoutes": [], "maximumBodyBytes": adapter.MAX_BODY, "maximumCorpusBytes": adapter.MAX_CORPUS}
        selected["capturePolicy"] = self.json_ref(policy)
        window = self.json_ref({"captureCompleteness": "unknown", "qualificationClaim": False,
            **{name: policy[name] for name in ("corpusId", "windowId", "sourceCommit", "sourceTree")}})
        receipts = []
        raw_receipts = []
        for direction, value in self.receipts.items():
            receipt = {**copy.deepcopy(value), "version": 1, "captureId": "3" * 32,
                **{name: policy[name] for name in ("corpusId", "windowId", "sourceCommit", "sourceTree",
                    "runtimeSourceDigest", "nativeExecutableSha256", "workerSourceDigest", "captureImplementationSha256")},
                "purpose": "storage-work", "requestId": "2" * 32, "direction": direction,
                "instrumentationTraffic": True, "qualificationClaim": False, "frameState": "bounded",
                "startedAtMillis": "1", "finishedAtMillis": "2"}
            images = []
            for image in receipt["privateImages"]:
                key = policy["capturePrefix"] + receipt["captureId"] + "/" + direction + "-body.bin"
                images.append({"key": key, "reference": image.pop("reference")})
                image["key"] = key
            raw_receipts.append(receipt)
            receipts.append({"receipt": self.json_ref(receipt), "images": images})
        export = {"version": 1, "runtime": dict(adapter.RUNTIME), "windows": [window], "receipts": receipts}
        selected["captureExport"] = self.json_ref(export)
        result = adapter.assess(selected)
        joins = result["applicationBodyAssessment"]["receiverJoins"]
        self.assertEqual(joins[0]["requestImage"], "matched_selected_receiver_byte_image")
        self.assertIn("independent_current_receiver_deployment_and_window_proof_required", joins[0]["missing"])
        self.assertEqual(joins[0]["typedPayload"]["operation"], "head")
        self.assertTrue(joins[0]["fullReplyConsumed"])
        self.assertEqual(result["hostedAcceptance"], "incomplete")
        self.assertIsNone(result["applicationBodyAssessment"]["nativeCapturedObjectPayloadBytes"])
        substituted = dict(raw_receipts[0], windowId="4" * 32)
        export["receipts"][0]["receipt"] = self.json_ref(substituted)
        selected["captureExport"] = self.json_ref(export)
        with self.assertRaises(ValueError):
            adapter.assess(selected)

    def parity_selection(self):
        source = "d" * 40
        projection = runpy.run_path(str(adapter.SOURCE / "tests/fleet/_hub-index-parity.py"))
        queries = []

        def query(statement):
            if statement.startswith("SELECT generation, content_digest"):
                rows = [[1, "e" * 64]]
            elif statement.startswith("SELECT state, error"):
                rows = [["fresh", None, source, "fixture", None, None, None, None, None]]
            elif statement.startswith("SELECT semver, tag_oid"):
                rows = [["1.0.0", "a" * 40, source, "fixture", 1, True]]
            elif statement.startswith("SELECT channel, floor"):
                rows = [["stable", "1.0.0"]]
            elif statement.startswith("SELECT channel.name, partition.bucket"):
                rows = [["stable", index, "1.0.0"] for index in range(256)]
            elif statement.startswith("SELECT release.semver, snapshot.source_commit"):
                rows = [["1.0.0", source, "a" * 40, "b" * 64, "complete", 1, 1, None]]
            else:
                rows = [["synthetic-source-row"]]
            queries.append({"statementSha256": adapter.sha(statement.encode()), "rows": rows})
            return rows

        projection["registry_index_observations"](query, "fixture")
        modes = {}
        for number, mode in enumerate(("hybrid", "native_only", "worker_only")):
            modes[mode] = self.json_ref({"version": 1, "mode": mode,
                "databaseIdentitySha256": str(number + 1) * 64,
                "readerProcessReference": self.json_ref({"fixture": True, "mode": mode}), "queries": queries})
        return {"registrySlug": "fixture", "signedSourceCommit": source, "modes": modes}

    def test_unchanged_sql_projection_parity_and_distinct_mode_custody(self):
        selected = self.parity_selection()
        result = adapter.index_parity(selected)
        self.assertEqual(result["state"], "retained_contents_match")
        self.assertIn("required", result["readerAuthority"])
        row = adapter.parsed(selected["modes"]["worker_only"])
        row["databaseIdentitySha256"] = "1" * 64
        selected["modes"]["worker_only"] = self.json_ref(row)
        with self.assertRaises(ValueError):
            adapter.index_parity(selected)
        selected = self.parity_selection()
        selected["signedSourceCommit"] = "f" * 40
        with self.assertRaises(ValueError):
            adapter.index_parity(selected)


class DirectControlAssessmentTests(unittest.TestCase):
    """Use actual selected codec output; sender/image fixtures grant no authority."""

    private = AssessmentTests.private
    json_ref = AssessmentTests.json_ref
    ref = AssessmentTests.ref

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sequence = 0
        self.call = "b" * 32
        self.route = "/_internal/storage/v1/capabilities"
        self.constructor = "d" * 64
        # These tests isolate event/image joins from installed-source custody.
        # The real constructor formula and package reader remain separate checks.
        self.constructor_function = adapter.direct_constructor_sha256
        patch = mock.patch.object(adapter, "direct_constructor_sha256", return_value=self.constructor)
        patch.start()
        self.addCleanup(patch.stop)
        self.original = {
            "version": 2, "deploymentId": "observation-deployment",
            "executorPublicOrigin": "https://executor.example", "requestNonce": "1" * 64,
            "issuedAt": "100", "expiresAt": "130", "managed": True, "externalSelectors": [],
        }
        profile = {
            "deploymentId": self.original["deploymentId"], "bucketNamespace": "namespace",
            "accountId": "account", "bucketName": "bucket", "credentialId": "credential",
            "credentialGeneration": "1", "secretVersionRef": "worker-profile:1",
            "credentialFingerprint": "2" * 64, "checksumAlgorithm": "md5",
            "clockQualification": "3" * 64, "clockUncertaintySeconds": "1",
        }
        runtime = {
            "version": 1, "qualificationDigest": "4" * 64, "maximumObjectBytes": "1048576",
            "maximumVerificationSeconds": "10", "settlementReserveSeconds": "8",
            "maximumParallelObjects": "4", "maximumParallelProviderRequests": "8",
            "cacheDestinationPolicy": "retained_original_baseline",
        }
        reply = {"request": self.original, "capabilities": {
            "version": 2, "capability": "aos.direct.multipart.v1", "profile": profile,
            "privateStagePolicy": {"policyId": "fixture-policy", "policyDigest": "5" * 64,
                                   "namespace": "namespace"},
            "runtimeQualification": runtime, "externalProfiles": [],
        }}
        self.request = json.dumps(self.original, separators=(",", ":")).encode()
        self.reply = json.dumps(reply, separators=(",", ":")).encode()
        request_ref, reply_ref = self.private(self.request), self.private(self.reply)
        manifest = {"version": 1, "codecRevision": adapter.RUNTIME["runtimeCodecRevision"],
            "sourceDigest": adapter.RUNTIME["workerSourceDigest"], "issuerVerifier": None,
            "captures": [{"requestId": self.call, "procedure": self.route, "method": "POST",
                "phase": None, "status": 200, "responseContentType": "application/json",
                "responseContentEncoding": None, "bodies": {"request": request_ref, "response": reply_ref},
                "controlSelection": {"sourceDigest": adapter.RUNTIME["workerSourceDigest"],
                    "deploymentId": self.original["deploymentId"], "originalRequest": request_ref}}]}
        selected = {"runtime": adapter.RUNTIME, "observerExecutable": adapter.PACKAGE["observerExecutable"]}
        _, report, error = adapter.observe(selected, self.json_ref(manifest))
        self.assertIsNone(error)
        self.codec = report["captures"][0]
        self.receipts = {}
        for direction, raw in (("received_request", self.request), ("exposed_response", self.reply)):
            self.receipts[direction] = {
                "role": "storage_wrapper", "method": "POST", "pathSha256": adapter.sha(self.route.encode()),
                "transportCallId": self.call, "queryClass": "absent", "state": "eof", "eof": True,
                "capturePersistence": "written", "responseConsumptionClaim": False,
                "observedBytes": str(len(raw)), "retainedBytes": str(len(raw)), "status": 200,
                "provenance": "independent_wrapper_received_bytes" if direction == "received_request" else "wrapper_exposed_reply_bytes",
                "imageKind": "complete_received_image" if direction == "received_request" else "complete_wrapper_reply_image",
                "privateImages": [{"name": "body", "bytes": str(len(raw)), "sha256": adapter.sha(raw),
                                   "reference": self.private(raw)}],
            }
        self.offered = {
            "version": 1, "state": "offered", "route": self.route, "transportCallId": self.call,
            "constructorSourceSha256": self.constructor,
            "nonceSha256": adapter.sha(self.original["requestNonce"].encode()),
            "offeredRequestSha256": adapter.sha(self.request), "offeredRequestBytes": str(len(self.request)),
            "endpointScheme": "https", "replyStatus": None, "exposedReplySha256": adapter.sha(b""),
            "exposedReplyBytes": "0", "replyEof": False, "outcome": "offered",
            "observedAtUnixMicros": "100", "replyMacAuthentication": None, "finalSqlAuthority": None,
        }
        self.terminal = dict(self.offered, state="terminal", replyStatus=200,
            exposedReplySha256=adapter.sha(self.reply), exposedReplyBytes=str(len(self.reply)),
            replyEof=True, outcome="reply_eof_unverified", observedAtUnixMicros="101")

    def join(self, offered=None, terminal=None, receipts=None, codec=None):
        return adapter.direct_control_receiver_pair(self.call,
            self.receipts if receipts is None else receipts,
            [self.offered] if offered is None else offered,
            [self.terminal] if terminal is None else terminal,
            self.codec if codec is None else codec)

    def test_finite_constructor_inputs_and_length_frames_are_source_bound(self):
        names = []
        def source_fixture(path, maximum):
            name = str(path.relative_to(adapter.SOURCE))
            names.append(name)
            self.assertEqual(maximum, adapter.MAX_JSON)
            return name.encode()

        with mock.patch.dict(adapter.PACKAGE_READER, {"installed_bytes": source_fixture}):
            actual = self.constructor_function()
        self.assertEqual(len(names), 6)
        self.assertEqual(len(set(names)), 6)
        expected = bytearray(b"aos.native.direct-control-constructor.v1\0")
        for name in names:
            raw = name.encode()
            expected.extend(len(raw).to_bytes(8, "big") + raw)
            expected.extend(len(raw).to_bytes(8, "big") + raw)
        self.assertEqual(actual, adapter.sha(expected))
        with mock.patch.dict(adapter.PACKAGE_READER, {"installed_bytes": lambda *_: b"changed"}):
            self.assertNotEqual(self.constructor_function(), actual)

    def test_actual_codec_and_complete_images_preserve_unknown_auth_sql_and_whole_egress(self):
        result = self.join()
        self.assertEqual(result["requestImage"], "matched_selected_control_receiver_byte_image")
        self.assertEqual(result["nativeReplyConsumedBytes"], str(len(self.reply)))
        self.assertTrue(result["fullReplyConsumed"])
        self.assertEqual(result["typedPayload"], self.codec["control"])
        for name in ("replyMacAuthentication", "finalSqlContext", "workerHandlerCompletion"):
            self.assertIsNone(result[name])
        self.assertIn("independent_worker_authenticated_completion_receipt_required", result["missing"])
        self.assertNotIn("nativeBulkBytes", result)

    def test_missing_duplicate_and_partial_images_never_claim_delivery(self):
        for offered, terminal in (([], [self.terminal]), ([self.offered], []),
                ([self.offered, self.offered], [self.terminal]), ([self.offered], [self.terminal, self.terminal])):
            self.assertIsNone(self.join(offered, terminal)["requestImage"])
        self.assertIsNone(self.join(receipts={"received_request": self.receipts["received_request"]})["requestImage"])
        pair = copy.deepcopy(self.receipts)
        pair["exposed_response"]["eof"] = False
        self.assertIsNone(self.join(receipts=pair)["requestImage"])

    def test_identity_source_nonce_route_and_actual_body_substitutions_refuse(self):
        for name, changed in (("transportCallId", "c" * 32), ("route", "/different"),
                ("constructorSourceSha256", "e" * 64), ("nonceSha256", "f" * 64),
                ("offeredRequestSha256", "a" * 64), ("observedAtUnixMicros", None)):
            with self.subTest(field=name):
                self.assertIsNone(self.join(offered=[dict(self.offered, **{name: changed})])["requestImage"])
        pair = copy.deepcopy(self.receipts)
        pair["received_request"]["privateImages"][0]["reference"] = self.private(b"changed")
        self.assertIsNone(self.join(receipts=pair)["requestImage"])
        codec = copy.deepcopy(self.codec)
        codec["control"]["selectedSourceDigest"] = "f" * 64
        self.assertIsNone(self.join(codec=codec)["requestImage"])

    def test_cancelled_consumed_prefix_is_distinct_from_receiver_eof(self):
        last = dict(self.terminal, exposedReplyBytes="3", exposedReplySha256=adapter.sha(self.reply[:3]),
                    replyEof=False, outcome="cancelled")
        result = self.join(terminal=[last])
        self.assertEqual(result["nativeReplyConsumedBytes"], "3")
        self.assertFalse(result["fullReplyConsumed"])
        self.assertIn("control_reply_not_fully_consumed", result["missing"])
        self.assertIsNone(result["replyMacAuthentication"])
        self.assertIsNone(self.join(terminal=[dict(last, exposedReplySha256="f" * 64)])["requestImage"])

    def test_real_process_reader_closed_events_and_clock_brackets(self):
        fixture = runpy.run_path(str(ROOT / "native_auth_tests.py"))["ContextTests"]()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        selected = fixture.selected
        raw = b"".join(json.dumps({"_PID": str(fixture.process["pid"]),
            "_EXE": fixture.process["executablePath"], "_SYSTEMD_UNIT": "aos-hub.service",
            "__REALTIME_TIMESTAMP": "100", "MESSAGE": "[INFO] message=direct_control_sender_observed "
            + json.dumps(row, separators=(",", ":"))}).encode() + b"\n"
            for row in (self.offered, self.terminal))
        selected["nativeLog"]["reference"] = self.private(raw)
        records = adapter.execute_records(selected)
        self.assertEqual(records["directOffered"][0]["value"], self.offered)
        self.assertEqual(records["directTerminal"][0]["value"], self.terminal)
        self.assertEqual(records["attempts"], [])
        selected["nativeLog"]["epoch"]["lastUnixMicros"] = "100"
        with self.assertRaises(ValueError):
            adapter.execute_records(selected)
        selected["nativeLog"]["epoch"]["lastUnixMicros"] = "101"
        selected["nativeLog"]["reference"] = self.private(raw + raw)
        with self.assertRaisesRegex(ValueError, "Duplicate record"):
            adapter.execute_records(selected)

    def test_unknown_extra_fields_counter_overflow_and_invented_authentication_refuse(self):
        for row in (dict(self.offered, extra=True), dict(self.offered, offeredRequestBytes="65537"),
                    dict(self.terminal, replyMacAuthentication=True), dict(self.terminal, finalSqlAuthority=True),
                    dict(self.terminal, outcome="stream_error", replyEof=True)):
            with self.assertRaises(ValueError):
                adapter.validate_direct_control_event(row, self.constructor)
        messages = lambda *_: [("[INFO] message=direct_control_sender_observed " + " " * 8193, "100")]
        with self.assertRaises(ValueError):
            adapter.direct_control_records("", {}, None, messages)

    def test_unmatched_offer_is_retained_without_delivery_or_zero_claim(self):
        selected = AssessmentTests.selection(self)
        original_records = {"attempts": [], "finalContexts": [],
                            "directOffered": [{"value": self.offered}], "directTerminal": []}
        selected["authSidecar"] = self.json_ref({"fixture": "source-only"})
        with mock.patch.object(adapter, "execute_records", return_value=original_records), \
                mock.patch.dict(adapter.READERS, {"assess": lambda *_: {"state": "unknown"}}):
            result = adapter.assess(selected)
        body = result["applicationBodyAssessment"]
        self.assertEqual(body["directControlUnmatchedOffers"][0]["transportCallId"], self.call)
        self.assertEqual(body["directControlUnmatchedOffers"][0]["delivery"], "unknown")
        self.assertIsNone(body["nativeBulkBytes"])
        self.assertEqual(result["hostedAcceptance"], "incomplete")


if __name__ == "__main__":
    unittest.main(verbosity=2)
