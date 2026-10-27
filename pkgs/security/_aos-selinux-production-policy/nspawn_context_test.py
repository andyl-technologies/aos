"""Checks the closed conventional nspawn context replacement."""

from __future__ import annotations

import unittest

from nspawn_context import AOS_CONTEXT, NSPAWN_PATH, STOCK_CONTEXT, align_nspawn_context


class NspawnContextTests(unittest.TestCase):
    def test_exact_rule_changes_without_touching_neighboring_paths(self) -> None:
        prefix = f"{NSPAWN_PATH}-other -- {STOCK_CONTEXT}\n"
        selected = f"{NSPAWN_PATH}\t\t--\t{STOCK_CONTEXT}\n"
        suffix = f"/usr/bin/other -- {STOCK_CONTEXT}\n"

        aligned = align_nspawn_context(prefix + selected + suffix)

        self.assertEqual(aligned, prefix + selected.replace(STOCK_CONTEXT, AOS_CONTEXT) + suffix)

    def test_missing_or_duplicate_rules_are_rejected(self) -> None:
        rule = f"{NSPAWN_PATH} -- {STOCK_CONTEXT}\n"

        for source in ("", "# no conventional alias\n", rule + rule):
            with self.subTest(source=source), self.assertRaises(ValueError):
                align_nspawn_context(source)

    def test_changed_context_or_inode_kind_is_rejected(self) -> None:
        for rule in (
            f"{NSPAWN_PATH} -l {STOCK_CONTEXT}\n",
            f"{NSPAWN_PATH} -- system_u:object_r:bin_t\n",
            f"{NSPAWN_PATH} -- {AOS_CONTEXT}\n",
        ):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                align_nspawn_context(rule)


if __name__ == "__main__":
    unittest.main()
