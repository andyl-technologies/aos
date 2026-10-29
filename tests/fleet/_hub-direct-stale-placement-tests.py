"""Controlled metadata API and original-custody gates; no fleet acceptance."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location("stale", Path(__file__).with_name("_hub-direct-stale-placement.py"))
stale = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stale)


class StalePlacementTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="aos-stale-placement-controlled-")
        self.file = Path(self.directory.name) / "original.json"
        self.expiry = int(time.time()) + 30
        self.original = {"version": 1, "plan_id": "controlled-plan", "expires_at": self.expiry,
            "placement_id": 3, "placement_resource_version": 4, "placement_prefix": "controlled/",
            "operation": {"kind": "inspect_metadata", "path": "info/refs"}}
        self.body = json.dumps(self.original).encode()
        self.file.write_bytes(self.body)
        self.file.chmod(0o600)
        self.held = {"version": 1, "state": "held", "requestSha256": hashlib.sha256(self.body).hexdigest(),
            "signatureSha256": "a" * 64, "planIdSha256": hashlib.sha256(b"controlled-plan").hexdigest(),
            "bodyBytes": str(len(self.body)), "expiresAtUnixSeconds": str(self.expiry),
            "observedAtUnixMillis": str(int(time.time() * 1000))}
        self.before = {"name": "selected", "bindingName": "controlled", "prefix": "controlled/",
            "resourceVersion": "4", "spec": {"readOrder": "0", "desiredState": "active",
                "desiredReadEnabled": True}, "status": {"effectiveReadEnabled": True}}
        self.calls = []
        owner = self

        class Controls:
            def __init__(self):
                self.current = copy.deepcopy(owner.before)

            def call(self, service, method, request):
                owner.calls.append((service, method, request))
                return {"placement": copy.deepcopy(self.current)}

            def reviewed(self, service, plan, apply, request, label):
                owner.calls.append((service, plan, apply, request, label))
                self.current["resourceVersion"] = "5"
                self.current["spec"]["readOrder"] = "1"
                return {"placement": copy.deepcopy(self.current)}

        self.controls = Controls()

    def tearDown(self):
        self.directory.cleanup()

    def advance(self):
        return stale.advance_held_stale_placement(self.controls, self.held, self.file,
            {"registrySlug": "controlled/registry"}, "selected", "stale-selected")

    def test_exact_read_order_plan_preserves_read_authority_and_unknown_provider_counts(self):
        result = self.advance()
        self.assertEqual(result["placementAfter"]["resourceVersion"], "5")
        service, plan, apply, request, label = self.calls[1]
        self.assertEqual((service, plan, apply), ("TopologyService", "PlanUpdatePlacement", "UpdatePlacement"))
        self.assertEqual(request["updateMask"], ["read_order"])
        self.assertEqual(request["expectedResourceVersion"], "4")
        self.assertNotIn("desiredReadEnabled", request)
        self.assertIsNone(result["providerRequests"])
        self.assertIsNone(result["nativeBulkBytes"])

    def test_missing_changed_symlink_or_public_original_refuses_before_api(self):
        for kind in ("hash", "public", "symlink"):
            with self.subTest(kind=kind):
                if kind == "hash":
                    self.file.write_bytes(self.body + b" ")
                elif kind == "public":
                    self.file.chmod(0o644)
                else:
                    self.file.unlink()
                    self.file.symlink_to(Path(self.directory.name) / "missing")
                with self.assertRaises((ValueError, OSError)):
                    self.advance()
                self.assertEqual(self.calls, [])
                self.file.unlink()
                self.file.write_bytes(self.body)
                self.file.chmod(0o600)

    def test_genuine_current_revision_disagreement_refuses_mutation(self):
        self.controls.current["resourceVersion"] = "6"
        with self.assertRaises(ValueError):
            self.advance()
        self.assertEqual(len(self.calls), 1)

    def test_source_bound_native_cli_failure_checks_authoritative_projection(self):
        request = self.held["requestSha256"]
        result = {"exitCode": 1, "timedOut": False, "requestSha256": request,
            "stderr": b"index failed: storage placement or binding changed during Worker execution"}
        projection = {name: [] for name in stale.STALE_INDEX_TABLES}
        for name in ("packages", "releases", "channels"):
            projection[name] = [["controlled"]]
        projection["index"] = [["fresh", None, "a" * 64, "controlled", None, "b" * 64, None, None, None]]
        failed = copy.deepcopy(projection)
        failed["index"][0][:2] = ["failed", result["stderr"].decode()]
        observed = stale.assert_stale_index_refusal(projection, failed, result, request)
        self.assertIsNone(observed["providerRequests"])
        for changed in ({**result, "exitCode": 0}, {**result, "timedOut": True},
                {**result, "stderr": b"ordinary timeout"}, {**result, "requestSha256": "b" * 64}):
            with self.assertRaises(ValueError):
                stale.assert_stale_index_refusal(projection, failed, changed, request)
        with self.assertRaises(ValueError):
            stale.assert_stale_index_refusal(projection, {}, result, request)
        for table in stale.STALE_INDEX_TABLES - {"index"}:
            altered = copy.deepcopy(failed)
            altered[table].append(["changed"])
            with self.assertRaises(ValueError, msg=table):
                stale.assert_stale_index_refusal(projection, altered, result, request)


if __name__ == "__main__":
    unittest.main()
