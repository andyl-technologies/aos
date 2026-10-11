"""Controlled strict Mirror source, current SQL and authenticated-call joins."""

import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import unittest


def load(name, leaf):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(leaf))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


module = load("mirror_accounting", "_hub-external-mirror-accounting.py")
capture = load("mirror_capture", "_hub-storage-capture.py")
workflow = load("mirror_workflow", "_hub-external-workflow-accounting.py")
capture._closed_review_json = load("mirror_review", "_hub-direct-review.py")._closed_review_json


def fixture():
    source = {"registry_id": 1, "registry_resource_version": 2, "mirror_resource_version": 3,
        "upstream_base": "https://aos.fleet.test:4778/fleet-mirror/" + "a" * 32,
        "protected_profile_digest": "b" * 64, "placement_id": 4, "placement_resource_version": 5,
        "write_spec_version": 6, "binding_id": 7, "binding_resource_version": 8,
        "placement_prefix": ".aos-mirror-qualification/" + "a" * 32 + "/final/full"}
    rows = {"registry": {"id": 1, "resource_version": 2}, "mirror": {"resource_version": 3},
        "placement": {"id": 4, "resource_version": 5, "write_spec_version": 6},
        "binding": {"id": 7, "resource_version": 8}}
    case = {"selection": {"upstream": source["upstream_base"], "placementPrefix": source["placement_prefix"]},
        "configuration": {"registryId": "1"},
        "effects": {"sql": {"value": rows, "receipt": {"controlledPrivateSql": True}}}}
    return source, {"full": case}


class MirrorAccountingTests(unittest.TestCase):
    def test_mirror_header_capture_retains_only_named_compact_controls(self):
        row = {field: "" for field in capture.PROTECTED_HEADER_V5_FIELDS}
        row.update(version="5", request_id="a" * 32, method="POST", status="200",
            path_and_query="/__hub/external-mirror-functional-guard", query_class="absent",
            transport_call_id="b" * 32, mirror_guard_request_signature="c" * 64,
            mirror_guard_reply_signature="d" * 64)
        retained = {}
        capture.retain_direct_flow = lambda name, body: (
            retained.setdefault(name, body), hashlib.sha256(body).hexdigest())[1]

        result = capture.capture_protected_headers(json.dumps(row), "worker-received")

        files = result["a" * 32]["files"]
        self.assertEqual(files["mirror_guard_request_signature"]["byteSize"], 64)
        self.assertEqual(files["mirror_guard_reply_signature"]["sha256"],
            hashlib.sha256(("d" * 64).encode()).hexdigest())
        self.assertEqual(set(retained.values()), {row["path_and_query"].encode(),
            ("c" * 64).encode(), ("d" * 64).encode()})

    def test_mirror_header_capture_refuses_unknown_missing_and_malformed_controls(self):
        capture.retain_direct_flow = lambda name, body: hashlib.sha256(body).hexdigest()
        row = {field: "" for field in capture.PROTECTED_HEADER_V5_FIELDS}
        row.update(version="5", request_id="a" * 32, method="POST", status="200",
            path_and_query="/__hub/external-mirror-functional-guard", query_class="absent")
        missing = dict(row)
        del missing["mirror_guard_reply_signature"]
        for changed in (missing, {**row, "authorization": "forbidden"},
                {**row, "mirror_guard_request_signature": "not-a-compact-mac"},
                {**row, "mirror_guard_reply_signature": "d" * 65},
                {**row, "version": "4"}):
            with self.assertRaises(ValueError):
                capture.capture_protected_headers(json.dumps(changed), "worker-received")

    def test_exact_single_batch_and_semantic_sources_preserve_original_partition(self):
        source, _ = fixture()
        for operation, request in (
                ("mirror_guard", {"original": source}),
                ("mirror_guard_batch", {"items": [{"original": source}]}),
                ("mirror_transfer", {"operation": {"kind": "mirror_transfer", "original": source}}),
                ("mirror_transfer_batch_v1", {"operation": {"kind": "mirror_transfer_batch", "items": [{"original": source}]}}),
                ("inspect_mirror_pack_v1", {"operation": {"kind": "inspect_mirror_pack", "inspection": source}}),
                ("inspect_mirror_live_metadata_v1", {"operation": {"kind": "inspect_mirror_live_metadata", "target": source}}),
                ("inspect_mirror_live_metadata_batch_v1", {"operation": {"kind": "inspect_mirror_live_metadata_batch", "targets": [source]}}),
                ("inspect_mirror_membership_v1", {"operation": {"kind": "inspect_mirror_membership", "query": {"inspection": source}}}),
                ("inspect_mirror_tree_inventory_v1", {"operation": {"kind": "inspect_mirror_tree_inventory", "query": {
                    "source": {"kind": "pack", "inspection": source}}}})):
            self.assertEqual(module.mirror_request_sources(request, operation), [source])
        with self.assertRaises(ValueError):
            module.mirror_request_sources({"operation": {"kind": "put"}}, "mirror_transfer")

    def test_current_registry_binding_and_profile_drift_refuse(self):
        source, cases = fixture()
        self.assertEqual(module.join_mirror_source_current(source, cases, "b" * 64)["registryId"], "1")
        for field, value in (("registry_id", 10), ("registry_resource_version", 10),
                ("mirror_resource_version", 10), ("binding_id", 10),
                ("placement_resource_version", 10), ("placement_prefix", "another/destination"),
                ("protected_profile_digest", "c" * 64), ("upstream_base", "https://other.example.test")):
            with self.assertRaises(ValueError):
                module.join_mirror_source_current({**source, field: value}, cases, "b" * 64)
        query = module.mirror_current_query(cases["full"])
        self.assertIn("READ ONLY", query)
        self.assertIn("r.id=1 AND p.id=4", query)
        self.assertNotIn("INSERT", query)

    def test_authenticated_receipts_only_admit_four_actual_routes_and_exact_labels(self):
        for route, operation in capture.MIRROR_CAPTURE_ROUTES.items():
            value = {"version": 2, "route": route, "planId": "a" * 64,
                "operation": operation, "requestSha256": "b" * 64, "replySha256": "c" * 64,
                "requestBytes": 17, "replyBytes": 23, "transportCallId": "d" * 32}
            self.assertEqual(capture.validate_storage_authenticated_value(value,
                capture.MIRROR_CAPTURE_ROUTES), value)
            for changed in ({**value, "route": route + "?other=1"},
                    {**value, "route": "/_internal/storage/mirror-candidate-guard"},
                    {**value, "operation": "external_copy_control"},
                    {**value, "replyBytes": 256 * 1024 + 1},
                    {**value, "authenticated": True}):
                with self.assertRaises(ValueError):
                    capture.validate_storage_authenticated_value(changed, capture.MIRROR_CAPTURE_ROUTES)

    def test_checked_nonce_and_operation_must_match_independent_body_decoder(self):
        decoded = {"requestId": "original", "operation": "mirror_guard", "exchangeIdSha256": "e" * 64,
            "requestSha256": "b" * 64, "replySha256": "c" * 64,
            "payload": {field: 0 for field in workflow.PAYLOAD_FIELDS}}
        original = {"requestId": "original", "bodies": {
            "request": {"sha256": "b" * 64, "byteSize": 17},
            "response": {"sha256": "c" * 64, "byteSize": 23}}}
        call = {"operation": "mirror_guard_control", "planIdSha256": "e" * 64,
            "requestSha256": "b" * 64, "replySha256": "c" * 64,
            "offeredRequestBytes": 17, "consumedReplyBytes": 23, "transportCallIdSha256": "f" * 64}
        result = workflow.external_body_partition(decoded, original, {
            "kind": "authenticated_control", "value": call}, None)
        self.assertEqual(result["checkedOutcome"], "existing_control_mac_and_correlation_accepted")
        for changed in ({**call, "planIdSha256": "d" * 64},
                {**call, "operation": "external_copy_control"}, {**call, "replySha256": "d" * 64}):
            with self.assertRaises(ValueError):
                workflow.external_body_partition(decoded, original, {"kind": "authenticated_control", "value": changed}, None)


if __name__ == "__main__":
    unittest.main()
