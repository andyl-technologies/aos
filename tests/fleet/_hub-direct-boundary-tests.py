"""Check evidence refusals with synthetic inputs, never runtime qualification."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


runtime = load("runtime_observer", "_hub-direct-runtime-observations.py")
models = load("runtime_observer_test_models", "_hub-direct-runtime-observations-tests.py")
boundary = load("boundary_observer", "_hub-direct-boundary.py")
for name in ("_direct_runtime_closed_json", "_direct_runtime_integer", "_direct_runtime_original"):
    setattr(boundary, name, getattr(runtime, name))
boundary.DIRECT_CONTROL_BODY_LIMIT = 256 * 1024
boundary.DIRECT_NATIVE_PHASES = {"admission", "authorize", "commit", "abort-report"}
boundary.retain_direct_flow = lambda *_: None


class BoundaryEvidenceRefusals(unittest.TestCase):
    def test_exact_verified_replay_is_one_classification_but_changed_original_refuses(self):
        queue = models.event("queue_start")
        offer, finish = models.event("control_request"), models.event("control_reply")
        control = {"requestDigest": "a" * 64, "publicBodyDigest": "b" * 64,
            "signedBodyDigest": "c" * 64, "replyBodyDigest": None, "step": "freeze",
            "sessions": [queue["object"]["session"]]}
        for value in (offer, finish):
            value.update(scope="native_control", object=None, control=copy.deepcopy(control))
        offer["bytes"] = "71"
        finish.update(bytes="83", outcome="positive")
        finish["control"]["replyBodyDigest"] = "d" * 64
        capture = {"requestId": "e" * 32, "phase": "authorize", "status": 200,
            "responseContentEncoding": "", "bodies": {
                "request": {"sha256": "c" * 64, "byteSize": 71},
                "response": {"sha256": "d" * 64, "byteSize": 83}}}
        events = [queue, offer, finish, copy.deepcopy(offer), copy.deepcopy(finish)]
        result = boundary.join_direct_native_control_bodies({"bodies": [capture]}, events)
        self.assertEqual(len(result["joined"]), 1)
        self.assertEqual(result["unresolvedDirectRequestIds"], [])
        self.assertIsNone(result["nativeBulkBytes"])

        changed = copy.deepcopy(finish)
        changed["control"]["sessions"][0]["originalDigest"] = "f" * 64
        ambiguous = boundary.join_direct_native_control_bodies({"bodies": [capture]}, events + [changed])
        self.assertEqual(ambiguous["joined"], [])
        self.assertEqual(ambiguous["unresolvedDirectRequestIds"], [capture["requestId"]])

    def test_multipart_listing_is_control_and_an_unknown_caller_cannot_supply_zero(self):
        raw = {"method": "GET", "operation": "multipart_session", "caller": "10.0.0.2",
            "path": "/synthetic/payload", "status": "200", "request_http_bytes": "71",
            "request_body_bytes": "-", "transfer_encoding": "", "response_http_bytes": "140",
            "response_body_bytes": "53", "etag": "", "content_md5": "", "elapsed_seconds": "0.1"}
        callers = {"client": "10.0.0.1", "worker": "10.0.0.2", "native": "10.0.0.3",
            "provider": "127.0.0.1"}
        receipts = boundary.provider_boundary_observations(json.dumps(raw), callers)
        original = {"sessionDigest": "1" * 64, "originalDigest": "2" * 64,
            "placementDigest": "3" * 64, "publicationId": "4" * 32,
            "dependencyPhase": "visibility", "stagePathSha256": receipts["receipts"][0]["pathSha256"],
            "finalPathSha256": "5" * 64}
        classified = boundary.classify_direct_provider_object_receipts(receipts, {"originals": [original]})
        self.assertEqual(classified["classified"][0]["objectTransferBytes"], 0)
        self.assertEqual(classified["classified"][0]["boundedProviderProtocolMetadataBytes"], 53)
        self.assertIsNone(classified["nativeBulkBytes"])

        raw["caller"] = "10.0.0.9"
        unknown = boundary.provider_boundary_observations(json.dumps(raw), callers)
        refused = boundary.classify_direct_provider_object_receipts(unknown, {"originals": [original]})
        self.assertEqual(refused["classified"], [])
        self.assertEqual(refused["unresolvedReceiptIndexes"], [0])

    def test_chunked_unknown_request_and_query_leak_remain_refusals(self):
        raw = {"method": "PUT", "operation": "multipart_session", "caller": "10.0.0.1",
            "path": "/synthetic/payload", "status": "200", "request_http_bytes": "71",
            "request_body_bytes": "-", "transfer_encoding": "chunked", "response_http_bytes": "140",
            "response_body_bytes": "53", "etag": "", "content_md5": "", "elapsed_seconds": "0.1"}
        callers = {"client": "10.0.0.1", "worker": "10.0.0.2", "native": "10.0.0.3",
            "provider": "127.0.0.1"}
        receipts = boundary.provider_boundary_observations(json.dumps(raw), callers)
        self.assertIsNone(receipts["receipts"][0]["request_body_bytes"])
        raw["path"] += "?synthetic_capability=must_not_be_logged"
        with self.assertRaises(ValueError):
            boundary.provider_boundary_observations(json.dumps(raw), callers)


if __name__ == "__main__":
    unittest.main()
