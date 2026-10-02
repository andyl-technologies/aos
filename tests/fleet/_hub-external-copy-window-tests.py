"""Controlled tests of selected catalogue and normal API caller assertions.

These cases establish caller source behavior only, not SQL/provider/runtime
qualification. Missing independent payload/provider joins remain unknown.
"""

import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("external_copy", Path(__file__).with_name("_hub-external-copy-window.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CatalogueTests(unittest.TestCase):
    def setUp(self):
        self.registry = {"registry": {"slug": "system/copy", "stableId": "registry-copy"}}
        self.commit = "c" * 64
        self.sql = {"registry": {"id": 1, "slug": "system/copy", "stable_id": "registry-copy"},
            "indexed": {"registry_id": 1, "state": "fresh", "last_indexed_commit": self.commit},
            "objects": [{"id": 2, "path": "objects/source", "digest": "sha256:" + "a" * 64,
                         "size": 17, "resource_version": 3}]}
        self.queries = []

    def read_sql(self, query, label):
        self.queries.append((query, label))
        return {"value": copy.deepcopy(self.sql), "receipt": {"controlledRawReference": label}}

    def observe(self):
        return module.observe_external_copy_catalog(self.read_sql, self.registry, self.commit, "selected")

    def test_transaction_and_exact_index_selection_are_explicit(self):
        result = self.observe()
        query, label = self.queries[0]
        self.assertTrue(query.startswith("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;"))
        for literal in ("LIMIT 513", "registry-copy", "system/copy", self.commit):
            self.assertIn(literal, query)
        self.assertTrue(query.endswith("COMMIT;"))
        self.assertEqual(result["objects"], [{"path": "objects/source", "sha256": "a" * 64, "byteSize": 17}])
        self.assertEqual(result["receipt"]["controlledRawReference"], label)

    def test_existing_sha256_encodings_are_normalized_without_minting_hashes(self):
        for digest in ("a" * 64, "sha256:" + "A" * 64,
                       "sha256-" + base64.b64encode(bytes.fromhex("a" * 64)).decode()):
            self.sql["objects"][0]["digest"] = digest
            self.assertEqual(self.observe()["objects"][0]["sha256"], "a" * 64)

    def test_actual_overflow_and_untrusted_hash_size_refuse_without_truncation(self):
        original = copy.deepcopy(self.sql)
        self.sql["objects"] = [{**original["objects"][0], "path": f"objects/{i:04d}"} for i in range(513)]
        with self.assertRaises(ValueError):
            self.observe()
        for key, value in (("digest", None), ("size", None), ("size", -1), ("resource_version", 0)):
            self.sql = copy.deepcopy(original)
            self.sql["objects"][0][key] = value
            with self.assertRaises((ValueError, TypeError)):
                self.observe()

    def test_wrong_registry_stale_index_and_missing_receipt_refuse(self):
        original = copy.deepcopy(self.sql)
        for record, field, value in (("registry", "stable_id", "another"),
                ("indexed", "state", "stale"), ("indexed", "last_indexed_commit", "b" * 64)):
            self.sql = copy.deepcopy(original)
            self.sql[record][field] = value
            with self.assertRaises(ValueError):
                self.observe()
        with self.assertRaises(ValueError):
            module.observe_external_copy_catalog(lambda *args: {"value": original, "receipt": None},
                self.registry, self.commit, "missing")

    def test_presence_requires_real_missing_then_exact_hash_size_identity(self):
        objects = self.observe()["objects"]
        before = [{"presences": [{"placementName": "source", "objectRef": "objects/source",
            "state": "present", "contentDigest": "sha256:" + "a" * 64, "size": "17"},
            {"placementName": "target", "objectRef": "objects/source", "state": "missing"}]}]
        module.require_external_copy_presence(before, objects, "source", "target", copied=False)
        with self.assertRaises(ValueError):
            module.require_external_copy_presence(before, objects, "source", "target", copied=True)
        after = copy.deepcopy(before)
        after[0]["presences"][1].update(state="present", contentDigest="a" * 64, size="17")
        module.require_external_copy_presence(after, objects, "source", "target", copied=True)
        after[0]["presences"][1]["contentDigest"] = "b" * 64
        with self.assertRaises(ValueError):
            module.require_external_copy_presence(after, objects, "source", "target", copied=True)

    def test_completion_requires_full_real_catalogue_and_original_copy_counters(self):
        facts = {"phase": "complete", "catalogObjects": 1, "missingObjects": 0, "corruptObjects": 0,
            "copy": {"source": "source", "destination": "target", "copiedObjects": 1, "copiedBytes": 17}}
        detail = {"operation": {"kind": "repair_placement", "state": "succeeded"}, "detailJson": json.dumps(facts)}
        module.require_external_copy_operation(detail, "repair", "source", "target", 1)
        facts["missingObjects"] = 1
        detail["detailJson"] = json.dumps(facts)
        with self.assertRaises(ValueError):
            module.require_external_copy_operation(detail, "repair", "source", "target", 1)


if __name__ == "__main__":
    unittest.main()
