"""Check evidence refusals with synthetic inputs, never runtime qualification."""

import copy
import hashlib
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
    def throughput_inputs(self):
        corpus = {"large_objects": [{"path": f"web/direct-content/object-{number}.bin",
            "byte_size": size, "sha256": str(number + 1) * 64}
            for number, size in enumerate((20, 30, 40))], "metadata_objects": 2}
        sources = [(item["path"], item["byte_size"], item["sha256"], "content")
            for item in corpus["large_objects"]]
        sources += [(f"web/packages/direct-qualification-{number:05d}.json", size, "9" * 64, "visibility")
            for number, size in enumerate((5, 6))]
        sources.append(("HEAD", 4, "a" * 64, "visibility"))
        originals, rows = [], []
        for number, (path, size, digest, phase) in enumerate(sources):
            stage = f"/synthetic/stage/{number}"
            originals.append({"objectPathSha256": hashlib.sha256(path.encode()).hexdigest(),
                "byteSize": str(size), "expectedSha256": digest, "dependencyPhase": phase,
                "sessionDigest": f"{number + 1:064x}", "originalDigest": f"{number + 7:064x}",
                "placementDigest": "b" * 64, "publicationId": ("c" if number != 2 else "d") * 32,
                "stagePathSha256": hashlib.sha256(stage.encode()).hexdigest(), "finalPathSha256": f"{number + 13:064x}"})
            for caller, method in (("10.0.0.1", "PUT"), ("10.0.0.2", "GET")):
                rows.append({"method": method, "operation": "object", "caller": caller,
                    "path": stage, "status": "200", "request_http_bytes": "200",
                    "request_body_bytes": str(size if method == "PUT" else 0), "transfer_encoding": "",
                    "response_http_bytes": "200", "response_body_bytes": str(size if method == "GET" else 0),
                    "etag": "", "content_md5": "", "elapsed_seconds": "60.000"})
        rows.append(copy.deepcopy(rows[0]))
        callers = {"client": "10.0.0.1", "worker": "10.0.0.2", "native": "10.0.0.3", "provider": "127.0.0.1"}
        receipts = boundary.provider_boundary_observations("\n".join(json.dumps(row) for row in rows), callers)
        mapping = {"originals": originals}
        classified = boundary.classify_direct_provider_object_receipts(receipts, mapping)
        interval = {"clock": "controller_monotonic", "startedNanoseconds": "1000000000",
            "finishedNanoseconds": "3000000000", "elapsedNanoseconds": "2000000000"}
        return receipts, classified, mapping, corpus, interval

    def test_rates_use_one_actual_interval_and_include_retries_separately_by_class(self):
        inputs = self.throughput_inputs()
        result = boundary.summarize_direct_provider_throughput(*inputs)
        self.assertEqual(result["sourceObjects"], {"bulk": 3, "metadata": 2})
        self.assertEqual(result["classes"]["bulk"]["positiveClientUploadBytes"], 110)
        self.assertEqual(result["classes"]["bulk"]["positiveWorkerReadBytes"], 90)
        self.assertEqual(result["classes"]["bulk"]["clientUploadBytesPerSecond"], 55)
        self.assertEqual(result["classes"]["bulk"]["workerReadBytesPerSecond"], 45)
        self.assertEqual(result["classes"]["metadata"]["clientUploadBytesPerSecond"], 5.5)
        self.assertEqual(result["classes"]["signed_surface_other"]["workerReadBytesPerSecond"], 2)
        self.assertEqual(inputs[0]["receipts"][0]["elapsedSeconds"], "60.000")
        self.assertIn("not unique goodput", result["scope"])

    def test_missing_time_originals_or_provider_coverage_cannot_supply_a_rate(self):
        for defect in ("missing_time", "zero_time", "nonfinite_time", "missing_original",
                "missing_receipt", "duplicate_receipt", "partial_upload", "changed_bytes", "changed_source"):
            with self.subTest(defect=defect):
                inputs = list(copy.deepcopy(self.throughput_inputs()))
                receipts, classified, mapping, corpus, interval = inputs
                if defect == "missing_time":
                    interval.pop("elapsedNanoseconds")
                elif defect == "zero_time":
                    interval.update(finishedNanoseconds=interval["startedNanoseconds"], elapsedNanoseconds="0")
                elif defect == "nonfinite_time":
                    interval["elapsedNanoseconds"] = "NaN"
                elif defect == "missing_original":
                    mapping["originals"].pop(3)
                elif defect == "missing_receipt":
                    classified["classified"].pop()
                elif defect == "duplicate_receipt":
                    classified["classified"][-1] = copy.deepcopy(classified["classified"][0])
                elif defect == "partial_upload":
                    classified["classified"][6]["status"] = 403
                    receipts["receipts"][6]["status"] = 403
                elif defect == "changed_bytes":
                    classified["classified"][0]["objectTransferBytes"] += 1
                elif defect == "changed_source":
                    corpus["large_objects"][0]["sha256"] = "f" * 64
                with self.assertRaises(ValueError):
                    boundary.summarize_direct_provider_throughput(*inputs)

    def test_provider_elapsed_preserves_observed_zero_resolution_but_refuses_nonfinite(self):
        callers = {"client": "10.0.0.1", "worker": "10.0.0.2", "native": "10.0.0.3", "provider": "127.0.0.1"}
        raw = {"method": "GET", "operation": "object", "caller": "10.0.0.2", "path": "/synthetic/payload",
            "status": "200", "request_http_bytes": "71", "request_body_bytes": "0", "transfer_encoding": "",
            "response_http_bytes": "140", "response_body_bytes": "53", "etag": "", "content_md5": "", "elapsed_seconds": "0.000"}
        result = boundary.provider_boundary_observations(json.dumps(raw), callers)
        self.assertEqual(result["receipts"][0]["elapsedSeconds"], "0.000")
        for value in (None, "NaN", "Infinity", "-0.1", "1e3", "", "9" * 25):
            with self.subTest(value=value), self.assertRaises(ValueError):
                boundary.provider_boundary_observations(json.dumps({**raw, "elapsed_seconds": value}), callers)

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
