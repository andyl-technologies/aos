"""Check real receipt schema joins with controlled independent byte captures.

These are parser and orchestration gates, not actual authenticated Worker events
or VM observations. Missing proof remains unresolved even with HTTP success.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


boundary = load("storage_boundary", "_hub-direct-storage-boundary.py")
review = load("review_inputs", "_hub-direct-review.py")
observations = load("native_observations", "_hub-direct-observations.py")
boundary._closed_review_json = review._closed_review_json
boundary.NATIVE_OBSERVATION_FIELDS = observations.NATIVE_OBSERVATION_FIELDS
boundary.native_control_observations = observations.native_control_observations
assessment = load("codec_assessment", "_hub-direct-codec-assessment.py")
assessment.WORKER_CONTROL_REPLY_LIMIT = observations.WORKER_CONTROL_REPLY_LIMIT


SOURCE = "a" * 64
ROUTE = "/_internal/storage/v1/binding-adoption"


def receipt(**changes):
    return {"version": 1, "route": ROUTE, "compiledSource": SOURCE,
        "requestBodySha256": "b" * 64, "replyBodySha256": "c" * 64,
        "requestBytes": "17", "replyBytes": "23", "completedAtUnixMillis": "1770000000110",
        **changes}


def captured(identifier, route=ROUTE):
    return {"requestId": identifier, "procedure": route, "phase": "", "method": "POST",
        "status": 200, "responseContentType": "application/json", "responseContentEncoding": "",
        "bodies": {"request": {"file": "/controlled/original", "sha256": "b" * 64, "byteSize": 17},
            "response": {"file": "/controlled/reply", "sha256": "c" * 64, "byteSize": 23}}}


def encoded(value):
    return "runtime-prefix storage_control_complete " + json.dumps(value)


class SuccessfulHandlerReceiptJoins(unittest.TestCase):
    def test_closed_schema_and_semantic_replay_preserve_completion_observations(self):
        text = encoded(receipt()) + "\n" + encoded(receipt(completedAtUnixMillis="1770000000111"))
        parsed = boundary.direct_control_completion_receipts(text + "\n" + text)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(next(iter(parsed.values()))["completionObservations"],
            {"1770000000110", "1770000000111"})

        for changes in ({"version": True}, {"route": "/_internal/storage/invented"},
                {"compiledSource": "A" * 64}, {"requestBodySha256": None},
                {"requestBytes": "017"}, {"replyBytes": 23}, {"replyBytes": "65537"},
                {"completedAtUnixMillis": "0"}, {"completedAtUnixMillis": "-1"},
                {"invented": "field"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                boundary.direct_control_completion_receipts(encoded(receipt(**changes)))
        with self.assertRaises(ValueError):
            boundary.direct_control_completion_receipts(encoded(receipt()).replace(
                '"version": 1', '"version": 1, "version": 1'))

    def test_source_exact_bytes_and_actual_receiving_interval_are_required(self):
        parsed = boundary.direct_control_completion_receipts(encoded(receipt()))
        body = captured("d" * 32)
        positive = boundary.direct_control_completion_join(parsed, body, SOURCE,
            "1770000000123", "0.020")
        self.assertEqual(positive["handlerCompletedAtUnixMillis"], ["1770000000110"])
        self.assertEqual(positive["requestBytes"], 17)
        self.assertNotIn("authority", positive)
        self.assertIsNone(boundary.direct_control_completion_join({}, body, SOURCE,
            "1770000000123", "0.020"))
        self.assertIsNone(boundary.direct_control_completion_join(parsed, body, "e" * 64,
            "1770000000123", "0.020"))
        self.assertIsNone(boundary.direct_control_completion_join(parsed, body, SOURCE,
            "1770000001123", "0.020"))
        for direction, field, value in (("request", "sha256", "f" * 64),
                ("response", "sha256", "f" * 64), ("response", "byteSize", 24)):
            changed = copy.deepcopy(body)
            changed["bodies"][direction][field] = value
            self.assertIsNone(boundary.direct_control_completion_join(parsed, changed, SOURCE,
                "1770000000123", "0.020"))
        for route in ("/_internal/storage/v1/bindings", "/_internal/storage/mirror-final-guard"):
            other = boundary.direct_control_completion_receipts(encoded(receipt(route=route)))
            self.assertIsNone(boundary.direct_control_completion_join(other,
                captured("d" * 32, route), SOURCE, "1770000000123", "0.020"))
        for finished, elapsed in (("0", "0.020"), ("1770000000123", "-1.000"),
                ("1770000000123", "0.02")):
            with self.assertRaises(ValueError):
                boundary.direct_control_completion_join(parsed, body, SOURCE, finished, elapsed)

    def test_independent_native_original_and_worker_received_join_or_remain_unresolved(self):
        original_id, received_id = "1" * 32, "2" * 32
        original_body, received_body = captured(original_id), captured(received_id)
        def proxy_row(identifier, root):
            result = {name: "" for name in observations.NATIVE_OBSERVATION_FIELDS}
            result.update(request_id=identifier, procedure=ROUTE, method="POST", status="200",
                request_http_bytes="30", request_body_bytes="17", response_body_bytes="23",
                response_http_bytes="40", elapsed_seconds="0.020", upstream_seconds="0.019",
                upstream_status="200", response_content_type="application/json",
                request_body_file=root + "/client-body/selected",
                response_body_file=root + "/response-bodies/" + identifier,
                completed_unix_seconds="1770000000.123")
            return result
        original_row = proxy_row(original_id, "/var/lib/hybrid-native-outbound")
        received_row = {**proxy_row(received_id, "/var/lib/hybrid-worker-boundary"),
            "origin_request_id": original_id, "caller": "192.0.2.10"}
        def capture(machine, tools, parsed, root, label):
            value = original_body if label == "native-original" else received_body
            return parsed, {"bodies": [copy.deepcopy(value)]}
        with patch.object(boundary, "capture_direct_native_bodies", capture, create=True), \
                patch.object(boundary, "retain_direct_flow", lambda *args: None, create=True):
            def run(runtime):
                return boundary.capture_direct_storage_boundary(None, None,
                    {"deploymentId": "controlled-deployment"}, json.dumps(original_row),
                    json.dumps(received_row), runtime, SOURCE, "192.0.2.10")
            result = run(encoded(receipt()))
            self.assertEqual(result["unresolvedNativeRequestIds"], [])
            self.assertEqual(result["captures"][0]["controlSelection"]["originalRequest"],
                original_body["bodies"]["request"])
            self.assertEqual(result["authenticatedCompletions"][0]["nativeRequestId"], original_id)
            self.assertIsNone(result["nativeBulkBytes"])
            self.assertEqual(run("")["unresolvedNativeRequestIds"], [original_id])
            received_body["bodies"]["response"]["sha256"] = "f" * 64
            self.assertEqual(run(encoded(receipt()))["unresolvedNativeRequestIds"], [original_id])


class TypedControlAssessmentJoins(unittest.TestCase):
    def test_exact_original_and_deployment_selection_survive_projection(self):
        selected = {"sourceDigest": SOURCE, "deploymentId": "controlled-deployment",
            "originalRequest": captured("1" * 32)["bodies"]["request"]}
        projected = assessment.direct_control_codec_selection(selected, SOURCE)
        self.assertEqual(projected["originalRequest"]["byteSize"], "17")
        self.assertEqual(selected["originalRequest"]["byteSize"], 17)
        for mutate in (
                lambda value: value.update(sourceDigest="f" * 64),
                lambda value: value.update(deploymentId="bad\nheader"),
                lambda value: value.update(invented="field"),
                lambda value: value["originalRequest"].update(byteSize=True),
                lambda value: value["originalRequest"].update(byteSize="17"),
                lambda value: value["originalRequest"].update(file="relative"),
                lambda value: value["originalRequest"].update(sha256="f")):
            changed = copy.deepcopy(selected)
            mutate(changed)
            with self.assertRaises(ValueError):
                assessment.direct_control_codec_selection(changed, SOURCE)

    def test_no_typed_control_zero_without_actual_successful_handler_and_original_join(self):
        body = captured("1" * 32)
        selected = {"sourceDigest": SOURCE, "deploymentId": "controlled-deployment",
            "originalRequest": body["bodies"]["request"]}
        capture = {**body, "controlSelection": assessment.direct_control_codec_selection(selected, SOURCE)}
        typed = {"operation": "binding_adoption", "selectedSourceDigest": SOURCE,
            "originalRequestSha256": "b" * 64, "originalRequestSemanticSha256": "d" * 64,
            "deploymentIdSha256": hashlib.sha256(b"controlled-deployment").hexdigest(),
            "challengeNonceSha256": "e" * 64, "originalContextSha256": "f" * 64,
            "returnedProtectedMaterialBytes": "0", "correlationValidatorSourceSha256": "d" * 64}
        item = {"class": "storage_control_metadata", "control": typed,
            "authentication": "not_checked_join_independent_authenticated_worker_receipt",
            "request": {"sha256": "b" * 64, "byteSize": "17", "typedSemanticSha256": "d" * 64},
            "response": {"sha256": "c" * 64, "byteSize": "23"}}
        positive = boundary.direct_control_completion_join(
            boundary.direct_control_completion_receipts(encoded(receipt())), body, SOURCE,
            "1770000000123", "0.020")
        result = assessment.direct_control_codec_join(item, capture, positive, SOURCE)
        self.assertEqual(result["requestBytes"], 17)
        self.assertEqual(result["authenticatedHandlerReceiptSemanticSha256"],
            positive["handlerReceiptSemanticSha256"])
        with self.assertRaises(ValueError):
            assessment.direct_control_codec_join(item, capture, None, SOURCE)
        for mutate in (
                lambda value: value["control"].update(returnedProtectedMaterialBytes="1"),
                lambda value: value["control"].update(selectedSourceDigest="f" * 64),
                lambda value: value["control"].update(originalRequestSha256="f" * 64),
                lambda value: value["control"].update(deploymentIdSha256="f" * 64),
                lambda value: value["control"].update(invented="field"),
                lambda value: value.update(authentication="invented_authenticated")):
            changed = copy.deepcopy(item)
            mutate(changed)
            with self.assertRaises(ValueError):
                assessment.direct_control_codec_join(changed, capture, positive, SOURCE)
        for mutate in (
                lambda value: value.update(compiledSource="f" * 64),
                lambda value: value.update(requestSha256="f" * 64),
                lambda value: value.update(replyBytes=24),
                lambda value: value.update(handlerCompletedAtUnixMillis=[])):
            changed = copy.deepcopy(positive)
            mutate(changed)
            with self.assertRaises(ValueError):
                assessment.direct_control_codec_join(item, capture, changed, SOURCE)


if __name__ == "__main__":
    unittest.main()
