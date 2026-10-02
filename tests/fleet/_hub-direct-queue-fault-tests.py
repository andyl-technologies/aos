"""Exercise fault identity/refusal joins and actual owned-process observations."""

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
