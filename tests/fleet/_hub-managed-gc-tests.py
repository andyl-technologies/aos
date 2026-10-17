"""Controlled Managed GC evidence refusals and real immutable SQL query shapes.

No test invokes a provider, publishes a manifest or qualifies a GC deletion.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import unittest


spec = importlib.util.spec_from_file_location("managed_gc", Path(__file__).with_name("_hub-managed-gc.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def controlled_join():
    """Return deliberately synthetic evidence for structural refusal tests."""
    action = {
        "id": "controlled-action", "state": "confirmed_absent", "inventory_entry_present": 1,
        "deletion_outcome": "deleted", "delete_credential_purpose": None,
        "delete_credential_generation": None, "expected_strong_etag": '"etag"',
        "expected_size": 71, "expected_hash": "sha256:" + "a" * 64,
        "expected_provider_version": "actual-R2-upload-string-not-S3-versionId",
        "placement_id": 12, "placement_resource_version": 3, "binding_id": 8,
        "binding_resource_version": 2, "placement_prefix": "controlled/gc",
        "object_key": "oci/blobs/sha256/" + "a" * 64, "conditional_etag": '"etag"',
        "response_idempotency_key": "controlled-response", "provider_request_id": None,
        "evidence_confirmed_at": 104,
    }
    canonical = {"actionId": action["id"], "responseIdempotencyKey": action["response_idempotency_key"],
                 "outcome": "deleted", "conditionalEtag": action["conditional_etag"],
                 "providerRequestId": None, "confirmedAt": 104}
    action["evidence_digest"] = "sha256:" + hashlib.sha256(
        json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()
    expected = {"claim_id": action["id"], "expected_etag": action["expected_strong_etag"],
                "expected_size": 71, "expected_hash": action["expected_hash"],
                "expected_provider_version": action["expected_provider_version"]}
    plan = {"plan_id": "b" * 32, "deployment_id": "controlled-deployment",
            "binding_kind": "deployment_r2", "binding_snapshot_revision": None,
            "credential_references": [], "placement_prefix": action["placement_prefix"],
            "operation": {"kind": "delete_if_matches", "path": action["object_key"], **expected}}
    result = {"plan_id": plan["plan_id"], "source_bytes": 0,
              "outcome": {"kind": "object_deleted", "etag": '"etag"'}}
    for field in ("placement_id", "placement_resource_version", "binding_id", "binding_resource_version"):
        plan[field] = result[field] = action[field]
    key = action["placement_prefix"] + "/" + action["object_key"]
    identity = {"version": action["expected_provider_version"], "etag": '"etag"', "size": 71}
    guard = {"guardName": plan["deployment_id"] + ":" + hashlib.sha256(key.encode()).hexdigest(),
             "deleteReceipts": {action["id"]: {"claim": expected, "outcome": {
                 "kind": "deleted", "etag": '"etag"'}}},
             "pendingDelete": None, "pendingMutation": None}
    before = {"backingIdentity": "c" * 64, "objects": {key: identity}, "guards": {}}
    after = {"backingIdentity": before["backingIdentity"], "objects": {key: None}, "guards": {key: guard}}
    window = {"backingIdentity": before["backingIdentity"], "coverage": "scoped_requests_complete", "brackets": [{
        "requestId": "d" * 32, "scope": "managed_gc_guard", "key": key,
        "subjectId": action["id"], "invoked": 2}], "calls": [
        {"callId": "head-one", "sequence": 1, "method": "head", "key": key, "result": identity},
        {"callId": "delete-one", "sequence": 2, "method": "delete", "key": key,
         "result": {"kind": "resolved"}},
    ]}
    for call in window["calls"]:
        call.update(requestId="d" * 32, scope="managed_gc_guard", subjectId=action["id"])
    return action, plan, result, window, before, after


class ManagedGcHelperTests(unittest.TestCase):
    def test_sql_projections_compile_against_actual_immutable_schema(self):
        source = Path(__file__).resolve().parents[2]
        connection = sqlite3.connect(":memory:")
        try:
            connection.executescript((source / "crates/aos-hub-core/src/db/schema.sql").read_text())
            connection.executescript((source / "crates/aos-hub-core/src/db/002-r2-gc-incarnation.sql").read_text())
            for query in (helper.managed_capability_sql(1), helper.action_evidence_sql("real-run-id")):
                self.assertEqual(connection.execute(query).fetchall(), [])
                self.assertIn("LIMIT", query)
                self.assertNotIn("UPDATE", query)
        finally:
            connection.close()
        for value in (True, 0, -1, "1 OR 1=1"):
            with self.assertRaises(ValueError):
                helper.managed_capability_sql(value)
        for value in ("", "' OR 1=1", "x" * 65, 1):
            with self.assertRaises(ValueError):
                helper.action_evidence_sql(value)

    def test_managed_probe_is_not_external_credential_or_oci_acceptance(self):
        fields = ("registry_id", "placement_id", "captured_mutation_epoch", "placement_resource_version",
                  "placement_write_spec_version", "placement_observation_version", "binding_id",
                  "binding_resource_version", "binding_write_revision")
        pins = {field: index + 1 for index, field in enumerate(fields)}
        inventory = {**pins, "state": "complete", "object_count": 2, "page_count": 1,
                     "hash_count": 2, "nonversioned_count": 0, "inventory_digest": "sha256:" + "a" * 64}
        capability = {**pins, "kind": "deployment_r2", "state": "valid",
                      "delete_credential_purpose": None, "delete_credential_generation": None,
                      "current_write_revision": pins["binding_write_revision"],
                      "capability_fingerprint": "controlled-fingerprint", "resource_version": 1}
        helper.require_managed_inventory(inventory, capability, pins)
        for field, value in (("kind", "s3"), ("state", "invalid"),
                             ("delete_credential_purpose", "delete"), ("delete_credential_generation", 1),
                             ("binding_resource_version", 88), ("current_write_revision", 88)):
            with self.assertRaises(ValueError):
                helper.require_managed_inventory(inventory, {**capability, field: value}, pins)
        for field, value in (("nonversioned_count", 1), ("hash_count", 1), ("placement_id", 88)):
            with self.assertRaises(ValueError):
                helper.require_managed_inventory({**inventory, field: value}, capability, pins)

    def test_structural_join_requires_actual_incarnation_and_guard_identity(self):
        baseline = controlled_join()
        joined = helper.join_managed_deletion(*baseline)
        self.assertEqual(joined["sdkDeleteCallId"], "delete-one")
        for index, field, value in (
            (0, "expected_provider_version", None), (0, "evidence_digest", "sha256:" + "0" * 64),
            (1, "binding_kind", "s3"), (1, "placement_resource_version", 99),
            (2, "source_bytes", 1), (3, "coverage", "unknown"),
            (5, "backingIdentity", "another-store"),
        ):
            changed = copy.deepcopy(baseline)
            changed[index][field] = value
            with self.assertRaises(ValueError):
                helper.join_managed_deletion(*changed)
        key = joined["key"]
        for field, value in (("pendingDelete", {"unknown": "effect"}),
                             ("pendingMutation", {"unknown": "effect"}), ("guardName", "another-key")):
            changed = copy.deepcopy(baseline)
            changed[5]["guards"][key][field] = value
            with self.assertRaises(ValueError):
                helper.join_managed_deletion(*changed)

    def test_sdk_resolution_or_absence_alone_cannot_qualify_positive(self):
        baseline = controlled_join()
        for mutate in (
            lambda values: values[3]["calls"].clear(),
            lambda values: values[3]["calls"].append(copy.deepcopy(values[3]["calls"][-1])),
            lambda values: values[3]["calls"].reverse(),
            lambda values: values[3]["calls"][-1].update(result={"kind": "unknown"}),
            lambda values: values[5]["guards"][next(iter(values[5]["guards"]))]["deleteReceipts"].clear(),
        ):
            changed = copy.deepcopy(baseline)
            mutate(changed)
            # Call array order is not evidence ordering: the observed sequence
            # remains authoritative when a collector emits rows out of order.
            if changed[3]["calls"] == list(reversed(baseline[3]["calls"])):
                helper.join_managed_deletion(*changed)
            else:
                with self.assertRaises((ValueError, KeyError)):
                    helper.join_managed_deletion(*changed)
        changed = copy.deepcopy(baseline)
        changed[3]["calls"][0]["sequence"] = 3
        with self.assertRaises(ValueError):
            helper.join_managed_deletion(*changed)

    def test_replay_requires_complete_observed_window_and_unchanged_persisted_receipt(self):
        _, _, _, window, _, after = controlled_join()
        keys = list(after["objects"])
        replay = {**window, "calls": [], "brackets": [{**window["brackets"][0], "invoked": 0}]}
        helper.require_no_redispatch(replay, after, copy.deepcopy(after), keys)
        with self.assertRaises(ValueError):
            helper.require_no_redispatch(window, after, copy.deepcopy(after), keys)
        with self.assertRaises(ValueError):
            helper.require_no_redispatch({**replay, "brackets": []}, after, after, keys)
        with self.assertRaises(ValueError):
            helper.require_no_redispatch({**replay, "brackets": [{
                **replay["brackets"][0], "subjectId":"another-claim"}]}, after, after, keys)
        with self.assertRaises(ValueError):
            helper.require_no_redispatch({**replay, "coverage": "unknown"}, after, after, keys)
        changed = copy.deepcopy(after)
        changed["guards"][keys[0]]["deleteReceipts"].clear()
        with self.assertRaises(ValueError):
            helper.require_no_redispatch(replay, after, changed, keys)


if __name__ == "__main__":
    unittest.main()
