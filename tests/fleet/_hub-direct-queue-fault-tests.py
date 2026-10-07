"""Exercise fault identity/refusal joins and actual owned-process observations."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


def load(name):
    path = Path(__file__).with_name(name)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


faults = load("_hub-direct-queue-faults.py")
native = load("_hub-direct-queue-fault-native.py")
resources = load("_hub-direct-invocation-resources.py")


def original():
    admission = {"sessionId": "session_1", "logicalFingerprint": "a" * 64,
                 "placements": [{"placementId": "1"}],
                 "intent": {"dependencyPhase": "content",
                            "target": {"kind": "publication_object", "publicationId": "b" * 32}}}
    complete = {"session": {"sessionId": "session_1", "logicalFingerprint": "a" * 64},
                "operationId": "c" * 64, "expectedResourceVersion": "1", "manifests": []}
    return admission, complete


def snapshot_body(admission, complete):
    return json.dumps({"sessionId": admission["sessionId"], "state": "admitted",
        "admission": admission, "complete": complete, "completeOperationId": complete["operationId"],
        "publicationId": "b" * 32, "publicationState": "preparing", "completionReceipts": 0}).encode()


class OriginalRefusalTests(unittest.TestCase):
    def test_admission_query_does_not_require_a_complete_intent(self):
        query = native.admission_only_query("fixture-deployment", "session_1")
        self.assertTrue(query.startswith("BEGIN TRANSACTION READ ONLY;"))
        self.assertNotIn("JOIN direct_upload_completion_intents", query)
        self.assertIn("'completionIntents',(SELECT count(*)", query)
        self.assertIn("'deploymentId',s.deployment_id", query)
        with self.assertRaises(ValueError):
            native.admission_only_query("fixture", "x';DELETE")

    def prepared(self):
        admission, complete = original()
        admission.update(principalId="actor", actorSlot={"kind": "service_account"})
        admission["intent"].update(expectedSha256="7" * 64, byteSize="8388608")
        placement = {"placementId": "1"}
        complete["manifests"] = [{"placement": placement, "manifestDigest": "8" * 64, "parts": []}]
        status = {"session": complete["session"], "intent": admission["intent"],
                  "resourceVersion": "1", "state": "creating", "placements": [placement]}
        whoami = {"deploymentId": "fixture", "principalId": "actor", "principalKind": "service_account"}
        row = {"sessionId": "session_1", "deploymentId": "fixture", "principalId": "actor",
               "state": "admitted", "admission": admission, "intent": admission["intent"],
               "logicalFingerprint": "a" * 64, "sourceSha256": "7" * 64, "declaredSize": "8388608",
               "publicationId": "b" * 32, "publicationState": "preparing",
               "completionIntents": 0, "completionReceipts": 0}
        batch = {"operationId": "9" * 64, "items": [complete]}
        return row, status, whoami, batch

    def test_precomplete_sql_joins_actual_namespace_and_refuses_existing_intent(self):
        row, status, whoami, batch = self.prepared()
        context = faults.prepared_queue_context(json.dumps(row).encode(), status,
            json.dumps(batch).encode(), whoami, "1", "d" * 64, "e" * 64, "enqueue_ack_lost")
        self.assertNotIn("deploymentId", context["admission"])
        self.assertIsNone(context["closedJob"])
        for field, value in [("completionIntents", 1), ("completionIntents", False),
                             ("principalId", "foreign"), ("sourceSha256", "0" * 64)]:
            changed = {**row, field: value}
            with self.assertRaises(ValueError):
                faults.prepared_queue_context(json.dumps(changed).encode(), status,
                    json.dumps(batch).encode(), whoami, "1", "d" * 64, "e" * 64, "enqueue_ack_lost")
        with self.assertRaises(ValueError):
            faults.prepared_queue_context(json.dumps(row).encode(), status,
                json.dumps(batch).encode(), {**whoami, "deploymentId": "other"},
                "1", "d" * 64, "e" * 64, "enqueue_ack_lost")

    def test_precomplete_callback_retains_original_before_install_and_starts_bounded_collection(self):
        row, status, whoami, batch = self.prepared()
        actions = []
        def retain(name, value):
            actions.append(name)
            return {"file": "/private/" + name, "sha256": faults.canonical_digest(value), "byteSize": "1"}
        def install(selection):
            actions.append("install")
            return {"compiledSourceDigest": selection["sourceDigest"], "selection": selection,
                    "scriptPath": "/private/queue-fault-entry.mjs",
                    "modules": {name: {} for name in ["installed-shim.mjs", "index.wasm",
                                                      "queue-fault-worker.mjs", "queue-fault-entry.mjs"]}}
        def collector(wrapper, cutoff):
            actions.append("collect")
            self.assertEqual(cutoff, 123456789)
            return {"scope": "fixed_owned_collector"}
        def configure(context):
            actions.append("fault")
            self.assertEqual(context["before"]["completionReceipts"], 0)
            return {"scope": "selected_fault_original"}
        public, evidence = self.admission_evidence(row)
        def project(context):
            actions.append("core-project")
            self.assertEqual(context["admission"], row["admission"])
            return evidence
        result = faults.run_precomplete_queue_fault({"fault": "enqueue_ack_lost", "status": status,
            "publicBeginBody": public, "completeBody": json.dumps(batch).encode(),
            "placementId": "1", "sourceDigest": "d" * 64,
            "runDigest": "e" * 64, "cutoffUnixMs": 123456789},
            read_admission=lambda session: json.dumps(row).encode(), read_whoami=lambda: whoami,
            capture_admission_projection=project,
            install_wrapper=install, start_collector=collector, configure_fault=configure, retain_private=retain)
        self.assertLess(actions.index("core-project"), actions.index("install"))
        self.assertLess(actions.index("queue-admission-core.json"), actions.index("install"))
        self.assertLess(actions.index("queue-original.json"), actions.index("install"))
        self.assertLess(actions.index("collect"), actions.index("fault"))
        self.assertIn("admissionObservation", result)

    def admission_evidence(self, row):
        """Supply synthetic codec output for orchestration refusal tests only."""
        def reference(name, raw):
            return {"file": "/private/" + name, "sha256": hashlib.sha256(raw).hexdigest(),
                    "byteSize": str(len(raw))}
        public = json.dumps({"operationId": "3" * 64,
                             "items": [row["admission"]["intent"]]}, separators=(",", ":")).encode()
        request, reply = b"synthetic-logical-request", b"synthetic-logical-reply"
        sql = json.dumps({"sessionId": row["sessionId"], "publicationId": row["publicationId"],
                         "state": "admitted", "admission": row["admission"]}).encode()
        capture = {"requestId": "synthetic-request", "procedure": "/aos.hub.v1.DirectUploadService/BeginBatch",
                   "method": "POST", "phase": "admission", "status": 200,
                   "responseContentType": "application/json", "responseContentEncoding": None,
                   "bodies": {"request": reference("request", request), "response": reference("reply", reply)}}
        manifest = native.admission_codec_manifest(capture, reference("public", public),
            reference("sql", sql), "1" * 40, "d" * 64)
        raw_manifest = json.dumps(manifest).encode()
        manifest_sha = hashlib.sha256(raw_manifest).hexdigest()
        projection = {"version": 1, "kind": "direct_logical_admission",
            "originalRequestSha256": hashlib.sha256(request).hexdigest(),
            "sqlEvidenceSha256": hashlib.sha256(sql).hexdigest(), "matchedOriginalCount": "1",
            "requestControlBytes": str(len(request)), "replyControlBytes": str(len(reply)),
            "objectPayloadBytes": None,
            "sqlReaderAuthority": "not_checked_join_measured_read_only_source_process_and_window",
            "missing": ["independent_sql_reader_custody_and_temporal_current_fences"]}
        observed = {"requestIdSha256": hashlib.sha256(b"synthetic-request").hexdigest(),
            "procedure": capture["procedure"], "method": "POST", "phase": "admission",
            "originalPublicRequestSha256": hashlib.sha256(public).hexdigest(),
            "immutableProjection": projection,
            "request": {key: value for key, value in capture["bodies"]["request"].items() if key != "file"},
            "response": {key: value for key, value in capture["bodies"]["response"].items() if key != "file"}}
        stdout = json.dumps({"version": 1, "codecRevision": "1" * 40, "selectedSourceDigest": "d" * 64,
                             "manifestSha256": manifest_sha, "captures": [observed]}).encode()
        control = {"step": "admission", "requestDigest": "2" * 64,
            "signedBodyDigest": hashlib.sha256(request).hexdigest(),
            "publicBodyDigest": hashlib.sha256(public).hexdigest(),
            "replyBodyDigest": hashlib.sha256(reply).hexdigest(),
            "sessions": [{"sessionDigest": hashlib.sha256(row["sessionId"].encode()).hexdigest(),
                          "originalDigest": hashlib.sha256(row["logicalFingerprint"].encode()).hexdigest()}]}
        events = [{"kind": kind, "sourceDigest": "d" * 64, "outcome": "positive",
                   "bytes": str(len(body)), "control": dict(control)}
                  for kind, body in [("control_request", request), ("control_reply", reply)]]
        references = {name: reference(name, b"synthetic-custody") for name in (
            "codecExecution", "sqlReader", "nativeCapture", "workerCapture")}
        references.update(codecOutput=reference("output", stdout), manifest=reference("manifest", raw_manifest))
        return public, {"manifest": manifest, "manifestSha256": manifest_sha, "codecStdout": stdout,
                        "sqlAdmissionsBody": sql, "authenticatedEvents": events, "references": references}

    def test_precomplete_refuses_missing_core_or_foreign_authenticated_original_before_install(self):
        row, status, whoami, batch = self.prepared()
        public, evidence = self.admission_evidence(row)
        installed = []
        def invoke(selected):
            return faults.run_precomplete_queue_fault({"fault": "enqueue_ack_lost", "status": status,
                "publicBeginBody": public, "completeBody": json.dumps(batch).encode(),
                "placementId": "1", "sourceDigest": "d" * 64, "runDigest": "e" * 64,
                "cutoffUnixMs": 123456789}, read_admission=lambda session: json.dumps(row).encode(),
                read_whoami=lambda: whoami, capture_admission_projection=lambda context: selected,
                install_wrapper=lambda value: installed.append(value), start_collector=lambda *args: None,
                configure_fault=lambda context: None, retain_private=lambda *args: None)
        with self.assertRaises(ValueError):
            invoke({"ready": True})
        changed = copy.deepcopy(evidence)
        changed["authenticatedEvents"][1]["control"]["sessions"][0]["originalDigest"] = "0" * 64
        with self.assertRaises(ValueError):
            invoke(changed)
        changed = copy.deepcopy(evidence)
        changed["authenticatedEvents"] = changed["authenticatedEvents"][:1]
        with self.assertRaises(ValueError):
            invoke(changed)
        changed = copy.deepcopy(evidence)
        decoded = json.loads(changed["codecStdout"])
        decoded["captures"][0]["immutableProjection"]["matchedOriginalCount"] = "0"
        changed["codecStdout"] = json.dumps(decoded).encode()
        with self.assertRaises(ValueError):
            invoke(changed)
        self.assertEqual(installed, [])

    def test_saved_complete_preserves_bytes_and_cannot_replay_after_unknown(self):
        _, _, _, batch = self.prepared()
        body = json.dumps(batch, separators=(", ", ": ")).encode()
        reference = {"sha256": hashlib.sha256(body).hexdigest(), "byteSize": str(len(body))}
        class UnknownTransport(native.QueueFaultNativeTransport):
            def _call_encoded(self, route, encoded):
                self.dispatched_body = encoded.encode()
                raise RuntimeError("unknown controlled transport")
        transport = UnknownTransport(None, {}, "/var/lib/hybrid-client/queue-faults/case.token", None, None)
        with self.assertRaises(RuntimeError):
            transport.complete_saved(body, reference, batch["items"][0], batch["operationId"])
        self.assertEqual(transport.dispatched_body, body)
        with self.assertRaises(ValueError):
            transport.complete_saved(body, reference, batch["items"][0], batch["operationId"])

    def test_called_window_does_not_repeat_a_failed_production_driver(self):
        cases = [{"fault": fault, "runDigest": f"{index:064x}",
                  "selectionFile": "/private/case-%d.json" % index,
                  "outputDirectory": "/private/output-%d" % index}
                 for index, fault in enumerate(sorted(faults.FAULTS), 1)]
        calls = []
        def run(selection, output, *, before_complete):
            calls.append(selection)
            before_complete({}, output)
            raise RuntimeError("unknown actual mutation boundary")
        with self.assertRaises(RuntimeError):
            faults.run_called_queue_fault_window(cases, run, lambda case: lambda prepared, root: {},
                                                  lambda case, result: {})
        self.assertEqual(len(calls), 1)

    def test_canonical_original_rejects_unsafe_numbers_and_matches_closed_utf8(self):
        self.assertEqual(faults.canonical_digest({"z": "é", "a": "1"}),
                         hashlib.sha256('{"a":"1","z":"é"}'.encode()).hexdigest())
        for value in [float("nan"), 1.0, 9007199254740992, {"a": object()}]:
            with self.assertRaises(ValueError):
                faults.canonical_digest(value)

    def test_real_phase_and_exact_complete_select_the_queue(self):
        admission, complete = original()
        for phase, binding in [("content", "HUB_DIRECT_VERIFY_BULK"),
                               ("leaf_metadata", "HUB_DIRECT_VERIFY_METADATA"),
                               ("visibility", "HUB_DIRECT_VERIFY_METADATA")]:
            admission["intent"]["dependencyPhase"] = phase
            selected = faults.queue_selection(admission, complete, "1", "d" * 64, "e" * 64, "none")
            self.assertEqual(selected["binding"], binding)
        complete["session"]["logicalFingerprint"] = "f" * 64
        with self.assertRaises(ValueError):
            faults.queue_selection(admission, complete, "1", "d" * 64, "e" * 64, "none")

    def test_sql_query_is_readonly_exact_and_rejects_injection(self):
        query = native.pending_original_query("fixture-deployment", "session_1", "c" * 64)
        self.assertTrue(query.startswith("BEGIN TRANSACTION READ ONLY;"))
        self.assertTrue(query.endswith("COMMIT;"))
        self.assertIn("direct_upload_completion_intents", query)
        self.assertIn("direct_upload_completion_receipts", query)
        self.assertIn("c.operation_id='" + "c" * 64 + "'", query)
        for values in [("x';DELETE", "session_1", "c" * 64),
                       ("fixture", "session_1' OR 1=1", "c" * 64),
                       ("fixture", "session_1", "c" * 65)]:
            with self.assertRaises(ValueError):
                native.pending_original_query(*values)

    def test_private_sql_original_drift_duplicate_or_missing_row_refuses(self):
        admission, complete = original()
        body = snapshot_body(admission, complete)
        selected = native.pending_snapshot(body, admission, complete)
        self.assertEqual(selected["completionReceipts"], 0)
        faults.assert_pending_did_not_publish(selected, selected, [], {"d" * 64})
        for mutate in [lambda row: row["complete"].update(operationId="e" * 64),
                       lambda row: row.update(publicationId="e" * 32),
                       lambda row: row.update(completionReceipts=False)]:
            row = json.loads(body)
            mutate(row)
            with self.assertRaises(ValueError):
                native.pending_snapshot(json.dumps(row).encode(), admission, complete)
        for changed in [b"", body + b"\n" + body,
                        body.replace(b'"state": "admitted"', b'"state": "admitted", "state": "committed"')]:
            with self.assertRaises(ValueError):
                native.pending_snapshot(changed, admission, complete)

    def test_pending_barrier_refuses_publication_provider_mutation_and_unknown_caller(self):
        admission, complete = original()
        before = native.pending_snapshot(snapshot_body(admission, complete), admission, complete)
        for field, value in [("state", "committed"), ("completionReceipts", 1),
                             ("publicationState", "writing_pointers")]:
            after = {**before, field: value}
            with self.assertRaises(AssertionError):
                faults.assert_pending_did_not_publish(before, after, [], {"d" * 64})
        for receipt in [{"caller": "worker", "pathSha256": "d" * 64, "method": "POST"},
                        {"caller": "unknown", "pathSha256": "d" * 64, "method": "GET"}]:
            with self.assertRaises((AssertionError, ValueError)):
                faults.assert_pending_did_not_publish(before, before, [receipt], {"d" * 64})
        result = faults.assert_pending_did_not_publish(before, before,
            [{"caller": "worker", "pathSha256": "d" * 64, "method": "GET"}], {"d" * 64})
        self.assertIsNone(result["nativeBulkBytes"])
        self.assertIsNone(result["qualification"])

    def test_current_token_retirement_echoes_actual_plan_revision(self):
        class ControlledApi:
            def call(self, service, method, request):
                self.listed = (service, method, request)
                return {"tokens": [{"tokenId": "actual-token", "scope": "actual-scope",
                                    "resourceVersion": "active"}]}

            def reviewed(self, *args):
                self.applied = args
                return {}
        api = ControlledApi()
        result = native.retire_actual_token(api, "actual-token", "actual-scope", "fault-retire")
        self.assertEqual(api.applied[:3], ("IdentityService", "PlanRetireAccessToken", "RetireAccessToken"))
        self.assertEqual(api.applied[3], {"tokenId": "actual-token", "expectedResourceVersion": "active"})
        self.assertEqual(result["tokenDigest"], hashlib.sha256(b"actual-token").hexdigest())
        with self.assertRaises(ValueError):
            native.retire_actual_token(api, "foreign-token", "actual-scope", "fault-retire")

    def test_exact_complete_denial_rejects_success_unrelated_error_and_unknown_transport(self):
        _, complete = original()
        for status, reply in [("401", {"code": "unauthenticated"}),
                              ("403", {"code": "permission_denied"}),
                              ("200", {"operationId": "d" * 64,
                                       "errors": [{"itemId": "session_1", "code": "denied"}]})]:
            native.assert_complete_denied({"status": status, "exitCode": 0}, reply, complete, "d" * 64)
        for status, reply in [("500", {"code": "unavailable"}), (None, {}),
                              ("200", {"operationId": "d" * 64, "sessions": [{}]})]:
            with self.assertRaises(AssertionError):
                native.assert_complete_denied({"status": status, "exitCode": 0}, reply, complete, "d" * 64)
        with self.assertRaises(ValueError):
            native.assert_complete_denied({"status": "401", "exitCode": 1},
                {"code": "unauthenticated"}, complete, "d" * 64)

    def test_actual_transport_retains_unknown_prefix_and_forbids_unselected_routes(self):
        tools = {"curl": "/nix/store/controlled-curl/bin/curl",
                 "python": "/nix/store/controlled-python/bin/python3"}
        calls = []
        def guest(client, python, source, selected, **options):
            calls.append(selected)
            compile(textwrap.dedent(source), "queue-fault-private-guest", "exec")
            self.assertIn("'--config','-'", source)
            if "request" not in selected:
                self.assertIn("https://aos.andyl.org/oauth2/token", source)
                self.assertIn("grant_type=urn%3Aaos%3Aparams%3Aoauth%3Agrant-type%3Aprovisioning-token", source)
                self.assertEqual(selected["tokenFile"], "/var/lib/hybrid-client/queue-faults/selected.token")
                return json.dumps({"path": "private-oauth-response", "bytes": 100, "exitCode": 0,
                    "status": "200", "jwtFile": selected["jwtFile"], "jwtSha256": "f" * 64,
                    "jwtBytes": 100, "oauthExpiresInSeconds": 3600})
            self.assertEqual(selected["route"], "DirectUploadService/CompleteBatch")
            self.assertEqual(selected["tokenFile"], "/var/lib/hybrid-client/queue-faults/selected.jwt")
            self.assertEqual(selected["jwtSha256"], "f" * 64)
            self.assertNotIn("secret", selected)
            return json.dumps({"path": "private-response", "sha256": hashlib.sha256(b'{}').hexdigest(),
                               "bytes": 2, "exitCode": 1, "status": None})
        transport = native.QueueFaultNativeTransport(None, tools,
            "/var/lib/hybrid-client/queue-faults/selected.token", guest, lambda *_: b'{}')
        _, complete = original()
        with self.assertRaises(ValueError):
            transport.complete(complete, "d" * 64)
        self.assertEqual(calls, [])
        transport.provision()
        with self.assertRaises(ValueError):
            transport.provision()
        with self.assertRaises(RuntimeError):
            transport.complete(complete, "d" * 64)
        self.assertEqual(transport.observations[1]["outcome"], "unknown")
        self.assertEqual(json.loads(calls[1]["request"])["items"], [complete])
        with self.assertRaises(ValueError):
            transport.call("DirectUploadService/BeginBatch", {})
        self.assertEqual(len(calls), 2)

    def test_source_built_expiry_token_uses_real_reviewed_issue_api_contract(self):
        class ControlledApi:
            def reviewed(self, *args):
                self.arguments = args
                return {"tokenId": "issued", "secret": "one-time-private"}
        api = ControlledApi()
        with self.assertRaises(ValueError):
            native.issue_fault_token(api, "service_account/invalid", "scope", ["publish"], 5, "issue")
        result = native.issue_fault_token(api, "service_account:fixture/actor", "scope", ["publish"], 5, "issue")
        self.assertEqual(api.arguments[:3], ("IdentityService", "PlanIssueAccessToken", "IssueAccessToken"))
        self.assertEqual(api.arguments[3]["ttlSecs"], "5")
        self.assertEqual(result["tokenId"], "issued")
        with self.assertRaises(ValueError):
            native.issue_fault_token(api, "service_account:fixture/actor", "scope", ["publish"], 0, "issue")

    def test_expiry_requires_current_active_unretired_selected_token_metadata(self):
        class ControlledTransport:
            def whoami(self):
                return {"status": "403", "observedAtUnixSeconds": 123}, {"code": "permission_denied"}
        class ControlledApi:
            def __init__(self):
                self.token = {"tokenId": "actual-token", "scope": "scope", "resourceVersion": "active",
                              "createdAt": "118", "expiresAt": "123", "retiredAt": "0"}

            def call(self, *_):
                return {"tokens": [self.token]}
        api = ControlledApi()
        retained = native.retain_actual_token(api, "actual-token", "scope")
        result = native.wait_actual_token_expiry(ControlledTransport(), {"accessExpiresAt": "3723"},
                                                retained, api, "scope")
        self.assertEqual(result["tokenExpiryUnixSeconds"], 123)
        self.assertEqual(result["jwtExpiryUnixSeconds"], 3723)
        for field, value in [("resourceVersion", "retired"), ("retiredAt", "124"), ("expiresAt", "124")]:
            old = api.token[field]
            api.token[field] = value
            with self.assertRaises(ValueError):
                native.wait_actual_token_expiry(ControlledTransport(), {"accessExpiresAt": "3723"},
                                                retained, api, "scope")
            api.token[field] = old

    def test_expiry_refuses_jwt_expiry_unrelated_denial_and_preexpiry_window(self):
        retained = {"tokenId": "actual-token", "scope": "scope", "resourceVersion": "active",
                    "createdAt": "118", "expiresAt": "123", "retiredAt": "0"}
        class ControlledApi:
            def call(self, *_):
                return {"tokens": [retained]}
        class ControlledTransport:
            def __init__(self, status, code, observed):
                self.receipt = {"status": status, "observedAtUnixSeconds": observed}
                self.reply = {"code": code}

            def whoami(self):
                return self.receipt, self.reply
        for status, code, observed in [("401", "unauthenticated", 123),
                                       ("403", "permission_denied", 122),
                                       ("403", "permission_denied", 3723),
                                       ("403", "permission_denied", None)]:
            with self.assertRaises(ValueError):
                native.wait_actual_token_expiry(ControlledTransport(status, code, observed),
                    {"accessExpiresAt": "3723"}, retained, ControlledApi(), "scope")
        with self.assertRaises(ValueError):
            native.wait_actual_token_expiry(ControlledTransport("403", "permission_denied", 123),
                {"accessExpiresAt": "123"}, retained, ControlledApi(), "scope")

    def test_fault_token_actor_must_match_real_original(self):
        admission = {"deploymentId": "actual-deployment", "principalId": "actual-principal",
                     "actorSlot": {"kind": "service_account"}}
        whoami = {"deploymentId": "actual-deployment", "principalId": "actual-principal",
                  "principalKind": "service_account"}
        native.assert_original_actor(whoami, admission)
        with self.assertRaises(ValueError):
            native.assert_original_actor({**whoami, "principalId": "other"}, admission)

    def test_lost_enqueue_requires_actual_sdk_return_and_never_server_acceptance(self):
        rows = [{"kind": kind, "jobDigest": "a" * 64, "invocationDigest": "b" * 64,
                 "atMillis": index, "outcome": outcome, "sdkReturned": returned}
                for index, (kind, outcome, returned) in enumerate([
                    ("enqueue_dispatch", "pending", None),
                    ("enqueue_sdk_return", "positive", True),
                    ("enqueue_ack_dropped", "unknown", True)])]
        report = faults.assert_ack_loss_observed(rows, "a" * 64, "enqueue_ack_lost")
        self.assertIsNone(report["queueServerAcceptance"])
        self.assertIsNone(report["qualification"])
        for changed in [rows[:-1], rows[1:], [*rows, rows[-1]]]:
            with self.assertRaises(AssertionError):
                faults.assert_ack_loss_observed(changed, "a" * 64, "enqueue_ack_lost")

    def test_retained_replay_needs_real_flag_and_unchanged_closed_job(self):
        admission, complete = original()
        selected = faults.production_original(admission, complete, "1")
        obj = {"session": {"sessionDigest": selected["sessionDigest"],
                           "originalDigest": selected["originalDigest"]},
               "placementDigest": selected["placementDigest"],
               "completeOperationDigest": selected["completeOperationDigest"]}
        events = [{"kind": "queue_finish", "object": obj, "attemptDigest": "a" * 64,
                   "atMillis": 10, "outcome": "positive", "replayed": False},
                  {"kind": "queue_finish", "object": obj, "attemptDigest": "b" * 64,
                   "atMillis": 20, "outcome": "positive", "replayed": True}]
        jobs = [{"kind": "invocation_jobs", "selectedMessages": 1, "jobDigest": "d" * 64}] * 2
        result = faults.assert_retained_read_replay(events, selected, "d" * 64, jobs)
        self.assertIsNone(result["providerRedispatch"])
        with self.assertRaises(AssertionError):
            faults.assert_retained_read_replay(events, selected, "e" * 64, jobs)
        events[1]["replayed"] = None
        with self.assertRaises(AssertionError):
            faults.assert_retained_read_replay(events, selected, "d" * 64, jobs)


def samples():
    return {"terminal": "completed", "ticksPerSecond": 100,
            "samples": [{"atUnixStartedMillis": t, "atUnixMillis": t + 1,
                "monotonicStartedNs": t * 1000000, "monotonicFinishedNs": (t + 1) * 1000000,
                "userTicks": i * 2, "systemTicks": i, "lifetimeResidentHighWaterBytes": 8000000}
                for i, t in enumerate([1000, 1100, 1200, 1300])]}


class ResourceBoundaryTests(unittest.TestCase):
    def test_invocation_join_refuses_overlap_or_missing_handler_finish(self):
        admission, complete = original()
        selected = faults.production_original(admission, complete, "1")
        wrappers = [{"kind": kind, "invocationDigest": "d" * 64, "atMillis": at,
                     "selectedMessages": 1, "batchMessages": 1, "jobDigest": "e" * 64}
                    for kind, at in [("invocation_start", 1050), ("invocation_jobs", 1060),
                                     ("invocation_finish", 1250)]]
        obj = {"session": {"sessionDigest": selected["sessionDigest"],
                           "originalDigest": selected["originalDigest"]},
               "placementDigest": selected["placementDigest"],
               "completeOperationDigest": selected["completeOperationDigest"]}
        events = [{"kind": kind, "atMillis": at, "object": obj, "aggregateActive": 1,
                   "attemptDigest": "f" * 64}
                  for kind, at in [("queue_start", 1070), ("queue_finish", 1200)]]
        result = faults.single_invocation_resources(samples(), wrappers, events, selected)
        self.assertFalse(result["processEnvelope"]["unresolved"])
        with self.assertRaises(ValueError):
            faults.single_invocation_resources(samples(), wrappers[:-1], events, selected)
        overlap = {**wrappers[0], "invocationDigest": "a" * 64, "atMillis": 1100}
        with self.assertRaises(ValueError):
            faults.single_invocation_resources(samples(), wrappers + [overlap], events, selected)

    def test_enclosing_process_bound_preserves_unknown_platform_facts(self):
        result = resources.invocation_process_envelope(samples(), 1050, 1250)
        self.assertEqual(result["wholeInvocationWallMillis"], 200)
        self.assertEqual(result["processCpuUpperMillis"], 110)
        self.assertEqual(result["processLifetimeResidentHighWaterBytes"], 8000000)
        self.assertIsNone(result["isolateMemoryBytes"])
        self.assertIsNone(result["platformCpuMillis"])
        self.assertFalse(result["unresolved"])

    def test_missing_boundaries_clock_step_and_partial_process_cannot_become_zero(self):
        for change in [lambda row: row.update(terminal="process_observation_failed"),
                       lambda row: row["samples"][3].update(atUnixMillis=1401, atUnixStartedMillis=1400),
                       lambda row: row["samples"][3].update(userTicks=0)]:
            row = samples()
            change(row)
            result = resources.invocation_process_envelope(row, 1050, 1250)
            self.assertTrue(result["unresolved"])
            self.assertIsNone(result["processCpuUpperMillis"])
        self.assertTrue(resources.invocation_process_envelope(samples(), 900, 1250)["unresolved"])
        self.assertTrue(resources.invocation_process_envelope(samples(), 1050, 1400)["unresolved"])

    def test_foreground_comparison_uses_original_remaining_budget(self):
        foreground = {"invocationId": "a" * 64, "issuedAt": "100", "expiresAt": "130"}
        result = resources.foreground_comparison(foreground, 120, 2, 8001)
        self.assertEqual(result["remainingVerificationBudgetMillis"], 8000)
        self.assertTrue(result["aboveObservedForegroundBudget"])
        for now in [99, 130]:
            with self.assertRaises(ValueError):
                resources.foreground_comparison(foreground, now, 2, 8001)

    def test_actual_owned_child_cpu_and_memory_samples_and_lifetime_refusal(self):
        self.assertTrue(sys.executable.startswith("/nix/store/"))
        child = subprocess.Popen([sys.executable, "-c",
            "import time\nbody=bytearray(8*1024*1024)\nprint('ready',flush=True)\n"
            "deadline=time.monotonic()+2\nvalue=0\n"
            "while time.monotonic()<deadline:\n value=(value+1)%100000\nbody[0]=value%256\n"],
            stdout=subprocess.PIPE)
        try:
            self.assertEqual(child.stdout.readline(), b"ready\n")
            identity = resources.process_identity(child.pid, sys.executable)
            observation = resources.collect_process_window(identity, 0.35, 50)
            self.assertEqual(observation["terminal"], "completed")
            rows = observation["samples"]
            self.assertGreater(rows[-1]["userTicks"], rows[0]["userTicks"])
            self.assertGreater(rows[-1]["lifetimeResidentHighWaterBytes"], 8 * 1024 * 1024)
            result = resources.invocation_process_envelope(observation,
                rows[1]["atUnixMillis"], rows[-2]["atUnixStartedMillis"])
            self.assertFalse(result["unresolved"])
            with self.assertRaises(ValueError):
                resources.process_sample({**identity, "startTicks": identity["startTicks"] + 1})
        finally:
            # Only this test's exact owned child is joined; no external process
            # is signalled or reused, including historical workerd lifetimes.
            child.wait(timeout=5)
            child.stdout.close()

    def test_cli_process_exit_retains_partial_report_with_failure_status(self):
        child = subprocess.Popen([sys.executable, "-c",
            "import time\nprint('ready',flush=True)\ntime.sleep(0.5)\n"], stdout=subprocess.PIPE)
        try:
            self.assertEqual(child.stdout.readline(), b"ready\n")
            identity = resources.process_identity(child.pid, sys.executable)
            with tempfile.TemporaryDirectory(prefix="aos-resource-cli-") as directory:
                output = Path(directory) / "partial.json"
                result = subprocess.run([sys.executable, "-B", resources.__file__,
                    "--pid", str(child.pid), "--executable", sys.executable,
                    "--start-ticks", str(identity["startTicks"]), "--duration-seconds", "1",
                    "--interval-millis", "50", "--output", str(output)],
                    capture_output=True, timeout=3, check=False)
                self.assertEqual(result.returncode, 1, result.stderr)
                report = json.loads(output.read_bytes())
                self.assertEqual(report["terminal"], "process_observation_failed")
                self.assertGreater(len(report["samples"]), 0)
                self.assertIsNone(report["platformCpuMillis"])
        finally:
            child.wait(timeout=3)
            child.stdout.close()


if __name__ == "__main__":
    unittest.main()
