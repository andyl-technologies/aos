"""Exercises requirement ownership failures, range gaps and Markdown examples."""

import tempfile
import unittest
from pathlib import Path

import plan_coverage


class PlanCoverageTests(unittest.TestCase):
    """Checks mutations that must fail rather than silently reduce coverage."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "spec").mkdir()
        (self.root / "integration").mkdir()
        self.requirements = self.root / "spec/01-example.md"
        self.requirements.write_text(
            "# Example\n\n"
            "- **[EXAMPLE-1]** A writer MUST verify bytes.\n"
            "- **[EXAMPLE-2]** A reader MUST reject corruption.\n"
            "- **[EXAMPLE-3]** A cache MUST retain original bytes.\n"
        )
        self.plan = self.root / "integration/05-implementation-plan.md"
        self.plan.write_text(
            "# Plan\n\n"
            "- [ ] **T-CHECK-1** Verified reads. — satisfies EXAMPLE-1 to EXAMPLE-3; check.\n"
            "\n## Coverage\n\n"
            "| Specification file | Milestone or branch | Tasks |\n"
            "| --- | --- | --- |\n"
            "| 01 example | T1 | T-CHECK-1 |\n"
        )

    def test_inclusive_range_covers_middle_requirement(self):
        self.assertEqual(plan_coverage.check(self.root), (1, 3))

    def test_undeclared_middle_of_range_is_rejected(self):
        self.requirements.write_text(
            self.requirements.read_text().replace(
                "- **[EXAMPLE-2]** A reader MUST reject corruption.\n", ""
            )
        )
        with self.assertRaisesRegex(ValueError, "undeclared.*EXAMPLE-2"):
            plan_coverage.check(self.root)

    def test_new_mandatory_requirement_needs_a_task(self):
        with self.requirements.open("a") as output:
            output.write("- **[EXAMPLE-4]** Release MUST retain the original owner.\n")
        with self.assertRaisesRegex(ValueError, "no task.*EXAMPLE-4"):
            plan_coverage.check(self.root)

    def test_fenced_example_creates_no_duplicate_or_obligation(self):
        with self.requirements.open("a") as output:
            output.write(
                "\n````text\n- **[EXAMPLE-1]** An example MUST NOT become a declaration.\n"
                "```\n- **[EXAMPLE-99]** This is still an example MUST.\n````\n"
            )
        self.assertEqual(plan_coverage.check(self.root), (1, 3))

    def test_withdrawn_requirement_does_not_need_a_task(self):
        with self.requirements.open("a") as output:
            output.write("- **[EXAMPLE-4] (withdrawn)** A historical MUST.\n")
        self.assertEqual(plan_coverage.check(self.root), (1, 3))

    def test_duplicate_declaration_in_another_document_is_rejected(self):
        (self.root / "integration/01-example.md").write_text(
            "- **[EXAMPLE-1]** A repeated declaration MUST fail.\n"
        )
        with self.assertRaisesRegex(ValueError, "repeat across documents"):
            plan_coverage.check(self.root)

    def test_bad_range_is_not_reduced_to_endpoint_citations(self):
        for text in ("EXAMPLE-3 to EXAMPLE-1", "EXAMPLE-1 to OTHER-3"):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, "invalid requirement range"):
                    plan_coverage.expand_ids(text)

    def test_missing_covered_document_is_rejected(self):
        self.requirements.rename(self.root / "spec/02-other.md")
        with self.assertRaisesRegex(ValueError, "missing or repeated coverage document"):
            plan_coverage.check(self.root)

    def test_task_without_ownership_is_rejected(self):
        self.plan.write_text(self.plan.read_text().replace("satisfies", "references"))
        with self.assertRaisesRegex(ValueError, "no satisfies clause"):
            plan_coverage.check(self.root)


if __name__ == "__main__":
    unittest.main()
