"""Retains configured aliases without querying unused dependency branches."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "metadata"))
import declaration_query


class DeclarationQueryTests(unittest.TestCase):
    def test_configured_alias_labels_are_added_to_loaded_definition_query(self):
        reports = [{"label": "//crates/example:lib", "external": False}]
        configured = [
            "@@//third_party/rust:core_serde (123abcd)",
            "//crates/example:lib (987abcd)",
            "@@rules_rust+//rust:toolchain (456abcd)",
            "@@+source+aos_core_crates__serde-1.0.228//:serde (987abcd)",
        ]
        with patch.object(declaration_query, "reports_from_events", return_value=reports):
            query = declaration_query.query([], configured)

        self.assertEqual(query, "buildfiles(set(//crates/example:lib //third_party/rust:core_serde))\n")
        self.assertNotIn("deps(", query)

    def test_empty_configured_graph_fails(self):
        with patch.object(declaration_query, "reports_from_events", return_value=[]):
            with self.assertRaisesRegex(ValueError, "no first-party targets"):
                declaration_query.query([], ["@@external//:target (123abcd)"])


if __name__ == "__main__":
    unittest.main()
