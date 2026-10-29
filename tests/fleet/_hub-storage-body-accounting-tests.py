"""Controlled body/counter join tests, never capture or runtime qualification."""

import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("accounting", HERE / "_hub-storage-body-accounting.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def digest(body):
    return hashlib.sha256(body).hexdigest()


class BodyJoinTests(unittest.TestCase):
    def fixture(self, root, raw=False):
        def body(name, value):
            path = root / name
            path.write_bytes(value)
            path.chmod(0o600)
            return {"file": str(path), "sha256": digest(value), "byteSize": str(len(value))}
        request = body("request", b"" if raw else b"{}")
        reply = body("reply", b"fixture-body" if raw else b"{\"retained\":null}")
        operation = "oci_blob_download" if raw else "external_copy_metadata"
        route = "/v2/repository/blobs/sha256:" + "a"*64 if raw else MODULE.OPERATIONS[operation]
        capture = {"requestId": "fixture", "procedure": route, "method": "GET" if raw else "POST",
                   "phase": None, "status": 200, "responseContentEncoding": "",
                   "bodies": {"request": request, "response": reply}}
        source = "a"*64
        context = {"requestId": "fixture", "operation": operation, "sourceDigest": source,
                   "requestSha256": request["sha256"], "replySha256": reply["sha256"],
                   "originalContextSha256": "b"*64, "purposeArtifactSha256": "c"*64,
                   "actorSnapshotSha256": "d"*64, "exchangeIdSha256": digest(b"original-exchange")}
        codec = {key: value for key, value in context.items()
                 if key not in {"purposeArtifactSha256", "actorSnapshotSha256"}}
        codec.update({"codecSourceSha256": "e"*64,
                 "class": "oci_distribution_blob_body" if raw else "external_copy_profile_metadata",
                 "payload": {"requestRawObjectBytes": "0", "replyRawObjectBytes": reply["byteSize"] if raw else "0",
                             "selectedDataBytes": "0", "semanticOciProjectionBytes": "0"}})
        exchange = {"requestId": "fixture", "plan_id": "original-exchange", "operation": operation,
                    "outcome": "success", "exchange_attempts": "1", "discarded_status_responses": "0",
                    "offered_plan_bytes": request["byteSize"], "observed_body_bytes": reply["byteSize"]}
        provider = {"unresolvedReceiptIndexes": [], "unknownCallers": [], "nativeProviderCalls": 0,
                    "classified": [], "observedReceiptCount": 0, "rawReportSha256": digest(b"")}
        return [[capture], [copy.deepcopy(capture)], [codec], [context], [exchange], provider, source, "e"*64]

    def test_exact_metadata_join_and_raw_blob_payload_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for raw in (False, True):
                selected = self.fixture(root, raw)
                result = MODULE.assess_storage_workflow_bodies(*selected)
                self.assertEqual(result["nativeBulkBytes"], len(b"fixture-body") if raw else 0)
                self.assertEqual(result["nativeTransportBodyBytes"], sum(int(row["byteSize"]) for row in selected[0][0]["bodies"].values()))
                self.assertEqual(result["unresolvedRequestIds"], [])

    def test_missing_unread_invalid_or_substituted_evidence_stays_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = self.fixture(Path(directory))
            for defect in ("context", "provider", "truncated", "signature", "source", "original", "counter", "exchange", "kind", "extra_payload", "codec_provenance"):
                selected = copy.deepcopy(baseline)
                if defect == "context": selected[3] = []
                elif defect == "provider": selected[5] = None
                elif defect == "truncated": selected[0][0]["bodies"]["response"]["byteSize"] = "1"
                elif defect == "signature": selected[4][0]["outcome"] = "invalid_result"
                elif defect == "source": selected[2][0]["sourceDigest"] = "f"*64
                elif defect == "original": selected[1][0]["bodies"]["request"]["sha256"] = "f"*64
                elif defect == "counter": selected[4][0]["observed_body_bytes"] = "0"
                elif defect == "exchange": selected[4][0]["plan_id"] = "replacement-exchange"
                elif defect == "kind": selected[2][0]["operation"] = "unsupported"
                elif defect == "extra_payload": selected[2][0]["payload"]["unknown"] = "0"
                elif defect == "codec_provenance": selected[7] = "f"*64
                with self.subTest(defect=defect):
                    self.assertIsNone(MODULE.assess_storage_workflow_bodies(*selected)["nativeBulkBytes"])

    def test_metadata_label_or_payload_count_cannot_hide_original_blob_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = self.fixture(Path(directory), True)
            selected[2][0]["class"] = "oci_distribution_control_metadata"
            self.assertIsNone(MODULE.assess_storage_workflow_bodies(*selected)["nativeBulkBytes"])

    def test_malformed_collections_remain_unknown_without_an_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            for defect in (None, [None], [{}]):
                selected = self.fixture(Path(directory))
                selected[0] = defect
                self.assertIsNone(MODULE.assess_storage_workflow_bodies(*selected)["nativeBulkBytes"])
            selected = self.fixture(Path(directory), True)
            selected[2][0]["payload"]["replyRawObjectBytes"] = "0"
            self.assertIsNone(MODULE.assess_storage_workflow_bodies(*selected)["nativeBulkBytes"])

    def test_duplicate_nonprivate_or_changed_files_cannot_supply_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = self.fixture(Path(directory))
            selected[4].append(copy.deepcopy(selected[4][0]))
            self.assertIsNone(MODULE.assess_storage_workflow_bodies(*selected)["nativeBulkBytes"])
            selected = self.fixture(Path(directory))
            Path(selected[0][0]["bodies"]["request"]["file"]).chmod(0o644)
            self.assertIsNone(MODULE.assess_storage_workflow_bodies(*selected)["nativeBulkBytes"])


if __name__ == "__main__":
    unittest.main()
