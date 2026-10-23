"""Preserves explicit platform case contracts across independent Rust families."""

import copy
import unittest

from verify_family_cross import platform_case_differences


class PlatformCaseTests(unittest.TestCase):
    def test_quota_family_keeps_its_exact_native_cases(self):
        expected = {"//crates/shared/aos-linux-project-quota:unit": {
            "executed": ["kernel_abi_layout_and_project_commands_are_frozen"], "ignored": [],
        }}
        original = copy.deepcopy(expected)

        differences = platform_case_differences(expected)

        self.assertEqual(differences, {})
        self.assertEqual(expected, original)

    def test_protocol_family_retains_the_foreign_rejection_contract(self):
        label = "//crates/crucible/protocol/crucible-qemu-shmem:region_layout"
        native = "region_allocation_initializes_slots_rings_and_storage"
        foreign = "region_allocation_rejects_unpinned_developer_targets"
        expected = {label: {"executed": [native, "stable_case"], "ignored": ["ignored_case"]}}

        differences = platform_case_differences(expected)

        self.assertEqual(expected[label]["executed"], [foreign, "stable_case"])
        self.assertEqual(expected[label]["ignored"], ["ignored_case"])
        self.assertEqual(differences, {label: {"native_only": [native], "foreign_only": [foreign]}})

    def test_protocol_drift_requires_review(self):
        label = "//crates/crucible/protocol/crucible-qemu-shmem:region_layout"
        native = "region_allocation_initializes_slots_rings_and_storage"
        foreign = "region_allocation_rejects_unpinned_developer_targets"
        for cases in [[], [native, native], [native, foreign], ["renamed_case"]]:
            with self.subTest(cases=cases), self.assertRaisesRegex(ValueError, "platform case contract changed"):
                platform_case_differences({label: {"executed": cases, "ignored": []}})


if __name__ == "__main__":
    unittest.main()
