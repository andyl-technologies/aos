"""Checks fail-closed Meson inventory and retained result joins."""

import importlib.util
from pathlib import Path
import sys
import unittest


spec = importlib.util.spec_from_file_location("inventory", Path(sys.argv[1]))
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tests = [
            {"name": "test-crucible-hpet-phase", "suite": ["qemu:unit"]},
            {"name": "test-crucible-rc4030-period", "suite": ["qemu:unit"]},
        ]
        self.names = [
            "unit - qemu:test-crucible-hpet-phase",
            "unit - qemu:test-crucible-rc4030-period",
        ]
        self.records = [
            {"name": name, "result": "OK", "is_fail": False}
            for name in self.names
        ]

    def test_configuration_order_does_not_affect_coverage(self):
        self.assertEqual(
            inventory.validate_configuration(self.names, self.names[::-1], self.tests), 2
        )

    def test_equal_count_substitution_refuses(self):
        substituted = [self.names[0], "unit - qemu:another-test"]
        with self.assertRaisesRegex(inventory.InventoryError, "missing=.*rc4030.*unexpected"):
            inventory.validate_configuration(self.names, substituted, self.tests)

    def test_duplicate_configured_name_refuses(self):
        with self.assertRaisesRegex(inventory.InventoryError, "duplicate"):
            inventory.validate_configuration(self.names, self.names, [self.tests[0]] * 2)

    def test_missing_selected_test_refuses(self):
        with self.assertRaisesRegex(inventory.InventoryError, "missing"):
            inventory.validate_configuration(self.names, self.names[:1], self.tests)

    def test_introspection_must_match_selection(self):
        with self.assertRaisesRegex(inventory.InventoryError, "Meson introspection differs"):
            inventory.validate_configuration(self.names, self.names, self.tests[:1])

    def test_multi_suite_name_preserves_all_suite_labels(self):
        test = {"name": "migration", "suite": ["qemu:qtest", "qemu:qtest-x86_64"]}
        self.assertEqual(inventory.configured_name(test), "qtest+qtest-x86_64 - qemu:migration")

    def test_foreign_project_suite_refuses(self):
        with self.assertRaisesRegex(inventory.InventoryError, "crosses projects"):
            inventory.configured_name({"name": "timer", "suite": ["qemu:unit", "foreign:unit"]})

    def test_empty_reviewed_inventory_refuses(self):
        with self.assertRaisesRegex(inventory.InventoryError, "empty"):
            inventory.validate_configuration([], [], [])

    def test_complete_results_accept_out_of_order_completion(self):
        self.assertEqual(inventory.validate_results(self.names, self.records[::-1]), 2)

    def test_missing_and_duplicated_result_cannot_preserve_count(self):
        with self.assertRaisesRegex(inventory.InventoryError, "duplicate"):
            inventory.validate_results(self.names, [self.records[0]] * 2)

    def test_unexpected_result_cannot_replace_configured_test(self):
        substituted = [self.records[0], {"name": "unit - qemu:replacement", "result": "OK", "is_fail": False}]
        with self.assertRaisesRegex(inventory.InventoryError, "missing"):
            inventory.validate_results(self.names, substituted)

    def test_noncompleted_or_bad_result_refuses(self):
        for result in ["PENDING", "RUNNING", "TIMEOUT", "ERROR", "FAIL", "IGNORED"]:
            with self.subTest(result=result):
                records = [self.records[0], {**self.records[1], "result": result}]
                with self.assertRaisesRegex(inventory.InventoryError, "Unsuccessful"):
                    inventory.validate_results(self.names, records)

    def test_failure_flag_cannot_be_hidden_by_ok_label(self):
        with self.assertRaisesRegex(inventory.InventoryError, "Unsuccessful"):
            inventory.validate_results(self.names, [self.records[0], {**self.records[1], "is_fail": True}])

    def test_skip_is_only_an_observed_result_not_skip_authorization(self):
        self.assertEqual(
            inventory.validate_results(self.names, [self.records[0], {**self.records[1], "result": "SKIP"}]), 2
        )


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
