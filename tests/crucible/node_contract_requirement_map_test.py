"""Exercises missing coverage, stale locations and false assignment controls."""

import unittest

from node_contract_requirement_map import (
    HEADER,
    declared_assignments,
    requirements_from_chapters,
    validate_map,
)


class RequirementMapTests(unittest.TestCase):
    def setUp(self):
        self.chapters = {
            "00-conventions-and-model.md": "**[CN-MODEL-1]** One requirement.\n",
            "08-conformance.md": (
                "## 8.4 Suite B: base\n**[CN-TEST-033]** Another.\n"
                "| `CN-MODEL-*` | Model | B | Other |\n"
                "| `CN-TEST-*` | Conformance | Applicable suite and claim inspection | All |\n"
                "| `CN-IPC-*` | Protocol | B | Other |\n"
            ),
            "reference/types.md": "- **[CN-IPC-99]** A nested requirement.\n",
        }
        self.plan = "## 2. P0 — Audit\n## 6. G0 and P4 — Feasibility\n**T-CN-01: Audit.**\n"
        self.rows = [
            [
                "CN-MODEL-1", "00-conventions-and-model.md", "1",
                "P0", "T-CN-01", "B", "planned",
            ],
            [
                "CN-TEST-033", "08-conformance.md", "2",
                "G0,P4", "T-CN-01", "B", "planned",
            ],
            [
                "CN-IPC-99", "reference/types.md", "1",
                "P4", "T-CN-01", "B", "planned",
            ],
        ]

    def validate(self):
        mapping = "\n".join("\t".join(row) for row in [HEADER, *self.rows]) + "\n"
        return validate_map(self.chapters, self.plan, mapping)

    def test_exact_coverage_includes_nested_chapters_and_preserves_literal_ids(self):
        report = self.validate()
        self.assertEqual(report["requirements"], 3)
        self.assertEqual(report["planning_annotations"], {"planned": 3})
        self.assertEqual(report["scope"], "documentation consistency; no implementation acceptance")

    def test_a_qualified_annotation_is_not_an_acceptance_record(self):
        self.rows[0][-1] = "qualified"
        report = self.validate()
        self.assertEqual(report["planning_annotations"], {"planned": 2, "qualified": 1})
        self.assertEqual(report["scope"], "documentation consistency; no implementation acceptance")
        self.assertNotIn("accepted", report)
        self.assertNotIn("executed_cases", report)

    def test_missing_duplicate_foreign_and_renumbered_rows_refuse(self):
        original = self.rows
        cases = [original[:-1], original + [original[0]]]
        for changed_id in ["CN-TEST-33", "CN-UNKNOWN-1"]:
            changed = [row.copy() for row in original]
            changed[1][0] = changed_id
            cases.append(changed)
        for rows in cases:
            with self.subTest(rows=rows):
                self.rows = rows
                with self.assertRaises(ValueError):
                    self.validate()

    def test_stale_chapter_line_and_noncanonical_line_numbers_refuse(self):
        for column, value in [(1, "../other.md"), (1, "08-conformance.md"), (2, "2"), (2, "01")]:
            with self.subTest(column=column, value=value):
                original = self.rows[0][column]
                self.rows[0][column] = value
                with self.assertRaisesRegex(ValueError, "stale defining location"):
                    self.validate()
                self.rows[0][column] = original

    def test_unknown_empty_duplicate_and_padded_assignments_refuse(self):
        assignments = [
            (3, ["P8", "", "P0,P0", " P0"]),
            (4, ["T-CN-99", "", "T-CN-01,T-CN-01"]),
            (5, ["X", "", "B,B", "B,"]),
        ]
        for column, values in assignments:
            for value in values:
                with self.subTest(column=column, value=value):
                    original = self.rows[0][column]
                    self.rows[0][column] = value
                    with self.assertRaises(ValueError):
                        self.validate()
                    self.rows[0][column] = original

    def test_header_field_count_and_status_are_closed(self):
        with self.assertRaisesRegex(ValueError, "exact seven-column TSV header"):
            validate_map(self.chapters, self.plan, "requirement,chapter,line\n")
        self.rows[0].append("extra")
        with self.assertRaisesRegex(ValueError, "wrong field count"):
            self.validate()
        self.rows[0].pop()
        self.rows[0][-1] = "passed"
        with self.assertRaisesRegex(ValueError, "unknown planning status"):
            self.validate()

    def test_duplicate_and_malformed_normative_anchors_refuse(self):
        for contents in ["**[CN-MODEL-1]** Duplicate.\n", "**[CN-MODEL-x]** Malformed.\n"]:
            self.chapters["reference/duplicate.md"] = contents
            with self.assertRaises(ValueError):
                self.validate()

    def test_examples_and_links_never_create_requirements(self):
        self.chapters["examples.md"] = (
            "[CN-MODEL-1](00-conventions-and-model.md)\n"
            "```text\n**[CN-MODEL-1]** Example only.\n```\n"
            "~~~~text\n**[CN-UNKNOWN-1]** Another example.\n~~~~\n"
            "````text\n```rust\n- **[CN-UNKNOWN-2]** Still an example.\n````\n"
        )
        self.assertEqual(self.validate()["requirements"], 3)
        with self.assertRaisesRegex(ValueError, "no normative requirements"):
            requirements_from_chapters({"example.md": "```text\n**[CN-X-1]**\n```\n"})

    def test_duplicate_or_missing_task_and_suite_declarations_refuse(self):
        for plan, conformance in [
            (self.plan + "**T-CN-01: Duplicate.**\n", self.chapters["08-conformance.md"]),
            (self.plan, "## 8.4 Suite B: base\n## 8.5 Suite B: duplicate\n"),
            ("", self.chapters["08-conformance.md"]),
            (self.plan, ""),
        ]:
            with self.subTest(plan=plan, conformance=conformance):
                with self.assertRaises(ValueError):
                    declared_assignments(plan, conformance)

    def test_every_declared_primary_suite_is_required_without_waiving_additional_coverage(self):
        self.chapters["08-conformance.md"] += "## 8.10 Suite F: profiles\n"
        self.chapters["08-conformance.md"] = self.chapters["08-conformance.md"].replace(
            "| Model | B | Other |", "| Model | B, F | Other |"
        )
        with self.assertRaisesRegex(ValueError, "missing primary suite coverage"):
            self.validate()

        self.rows[0][5] = "B,F"
        self.assertEqual(self.validate()["requirements"], 3)

    def test_missing_duplicate_unknown_and_undeclared_family_coverage_refuse(self):
        original = self.chapters["08-conformance.md"]
        cases = [
            "## 8.4 Suite B: base\n**[CN-TEST-033]** Another.\n",
            original + "| `CN-MODEL-*` | Model | B | Other |\n",
            original.replace("| Model | B | Other |", "| Model | X | Other |"),
            original.replace("| `CN-MODEL-*` | Model | B | Other |\n", ""),
        ]
        for conformance in cases:
            with self.subTest(conformance=conformance):
                self.chapters["08-conformance.md"] = conformance
                with self.assertRaises(ValueError):
                    self.validate()


if __name__ == "__main__":
    unittest.main()
