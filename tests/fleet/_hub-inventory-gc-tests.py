"""Controlled helper refusal checks; no inventory or provider effect qualification."""

import copy
import hashlib
import importlib.util
from pathlib import Path
import sqlite3
import unittest


spec = importlib.util.spec_from_file_location("inventory_gc", Path(__file__).with_name("_hub-inventory-gc.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class InventoryGcPrerequisiteTests(unittest.TestCase):
    def test_delete_selection_is_copied_not_derived_from_upload(self):
        publication = {"controlFixture": "not-real-SQL-evidence"}
        issuer = {"controlFixture": "not-an-installed-issuer"}
        association = {"binding_id": "12", "binding_resource_version": "4"}
        write = {"association": association, "admitted_prefix": "managed/selected"}
        cohort = {**write, "credential": {"purpose": "delete"},
                  "allowed_effects": ["conditional_delete"]}
        bootstrap = {"publication": publication, "issuer_installation": issuer, "write_cohort": write}
        export = {"version": 1, "publication": publication, "issuer_installation": issuer,
                  "delete_cohort": cohort}
        bindings = {"HUB_EXTERNAL_OBJECT_CONSUMER": {"publications": [publication], "cohorts": [write]}}
        body = b"controlled contract commitment only"
        selected = helper.external_gc_bindings(bootstrap, export, hashlib.sha256(body).hexdigest(), body, bindings)
        self.assertEqual(selected["HUB_EXTERNAL_OBJECT_CONSUMER"]["cohorts"][-1], cohort)
        self.assertEqual(bindings["HUB_EXTERNAL_OBJECT_CONSUMER"]["cohorts"], [write])
        for field, value in [("purpose", "write"), ("purpose", "read")]:
            changed = copy.deepcopy(export)
            changed["delete_cohort"]["credential"][field] = value
            with self.assertRaises(ValueError):
                helper.external_gc_bindings(bootstrap, changed, hashlib.sha256(body).hexdigest(), body, bindings)
        changed = copy.deepcopy(export)
        changed["publication"] = {"otherHead": 2}
        with self.assertRaises(ValueError):
            helper.external_gc_bindings(bootstrap, changed, hashlib.sha256(body).hexdigest(), body, bindings)
        with self.assertRaises(ValueError):
            helper.external_gc_bindings(bootstrap, export, "a" * 64, body, bindings)

    def test_null_version_invalid_probe_or_stale_inventory_cannot_satisfy_positive(self):
        pins = {name: index + 1 for index, name in enumerate((
            "registry_id", "placement_id", "captured_mutation_epoch", "placement_resource_version",
            "placement_write_spec_version", "placement_observation_version", "binding_id",
            "binding_resource_version", "binding_write_revision", "delete_credential_generation"))}
        inventory = {**pins, "state": "complete", "object_count": 2, "page_count": 1,
                     "hash_count": 2, "nonversioned_count": 0, "inventory_digest": "sha256:" + "b" * 64}
        capability = {**pins, "state": "valid", "delete_credential_purpose": "delete"}
        helper.require_current_inventory(inventory, capability, pins)
        for name, value in [("nonversioned_count", 1), ("hash_count", 1),
                            ("captured_mutation_epoch", 99), ("binding_resource_version", 99)]:
            with self.assertRaises(ValueError):
                helper.require_current_inventory({**inventory, name: value}, capability, pins)
        for name, value in [("state", "invalid"), ("delete_credential_purpose", "write"),
                            ("delete_credential_generation", 99)]:
            with self.assertRaises(ValueError):
                helper.require_current_inventory(inventory, {**capability, name: value}, pins)

    def test_sql_projection_is_readonly_bounded_and_does_not_interpolate_paths(self):
        query = helper.current_inventory_sql(1, 2)
        self.assertIn("LIMIT 1", query)
        self.assertIn("entry.provider_version IS NULL", query)
        self.assertNotIn("UPDATE", query)
        for registry, placement in [(True, 2), (1, "2 OR 1=1"), (0, 2), (1, -1)]:
            with self.assertRaises(ValueError):
                helper.current_inventory_sql(registry, placement)

    def test_inventory_projection_matches_the_retained_source_sql_columns(self):
        # This checks query shape against actual immutable DDL in a disposable
        # local database. It does not invoke a provider or populate inventory.
        source = Path(__file__).resolve().parents[2]
        connection = sqlite3.connect(":memory:")
        try:
            connection.executescript((source / "crates/aos-hub-core/src/db/schema.sql").read_text())
            connection.executescript((source / "crates/aos-hub-core/src/db/002-r2-gc-incarnation.sql").read_text())
            self.assertEqual(connection.execute(helper.current_inventory_sql(1, 2)).fetchall(), [])
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
