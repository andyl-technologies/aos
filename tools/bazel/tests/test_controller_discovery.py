"""Checks that controller discovery rejects incomplete or ambiguous evidence."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from discover_controller_tests import binary_outputs, discover


LABEL = "//crates/crucible/fixture:unit_binary"


class BinaryOutputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "unit_binary"
        self.binary.write_bytes(b"compiled fixture")
        self.events = [
            {
                "id": {"namedSet": {"id": "binary"}},
                "namedSetOfFiles": {"files": [{"uri": self.binary.as_uri()}]},
            },
            {
                "id": {"targetCompleted": {"label": LABEL}},
                "completed": {
                    "success": True,
                    "outputGroup": [{"name": "default", "fileSets": [{"id": "binary"}]}],
                },
            },
        ]

    def test_default_output_resolves_through_nested_file_sets(self):
        self.events[0]["namedSetOfFiles"]["fileSets"] = [{"id": "nested"}]
        self.events.append({"id": {"namedSet": {"id": "nested"}}, "namedSetOfFiles": {}})

        self.assertEqual(binary_outputs(self.events, [LABEL], self.root), {LABEL: self.binary})

    def test_aspect_completion_cannot_replace_a_binary(self):
        self.events[1]["id"]["targetCompleted"]["aspect"] = "inventory"

        with self.assertRaisesRegex(ValueError, "omitted requested"):
            binary_outputs(self.events, [LABEL], self.root)

    def test_duplicate_configurations_are_rejected(self):
        self.events.append(json.loads(json.dumps(self.events[1])))

        with self.assertRaisesRegex(ValueError, "ambiguous completed"):
            binary_outputs(self.events, [LABEL], self.root)

    def test_unsuccessful_binary_is_rejected(self):
        self.events[1]["completed"]["success"] = False

        with self.assertRaisesRegex(ValueError, "unsuccessful test binary"):
            binary_outputs(self.events, [LABEL], self.root)

    def test_remote_output_cannot_be_used_as_local_evidence(self):
        self.events[0]["namedSetOfFiles"]["files"][0]["uri"] = "https://example.invalid/binary"

        with self.assertRaisesRegex(ValueError, "local output URI"):
            binary_outputs(self.events, [LABEL], self.root)

    def test_output_outside_private_build_is_rejected(self):
        inside = self.root / "execution"
        inside.mkdir()

        with self.assertRaisesRegex(ValueError, "outside the private execution root"):
            binary_outputs(self.events, [LABEL], inside)

    def test_multiple_default_outputs_are_rejected(self):
        second = self.root / "second_binary"
        second.write_bytes(b"second fixture")
        self.events[0]["namedSetOfFiles"]["files"].append({"uri": second.as_uri()})

        with self.assertRaisesRegex(ValueError, "exactly one binary"):
            binary_outputs(self.events, [LABEL], self.root)

    def test_cyclic_file_sets_are_rejected(self):
        self.events[0]["namedSetOfFiles"]["fileSets"] = [{"id": "binary"}]

        with self.assertRaisesRegex(ValueError, "cyclic build-event"):
            binary_outputs(self.events, [LABEL], self.root)


class CaseDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.binary = Path(self.temporary.name) / "unit_binary"
        self.binary.write_bytes(b"compiled fixture")

    def test_listing_retains_ignored_cases_without_claiming_execution(self):
        with patch("discover_controller_tests.cases", side_effect=[["active", "ignored"], ["ignored"]]) as listed:
            result = discover({LABEL: self.binary})

        self.assertEqual(listed.call_args_list[1].kwargs, {"ignored": True})
        self.assertFalse(result["test_execution_qualified"])
        self.assertEqual(result["targets"][LABEL]["cases"], ["active", "ignored"])
        self.assertEqual(result["targets"][LABEL]["ignored"], ["ignored"])

    def test_unlisted_ignored_case_is_rejected(self):
        with patch("discover_controller_tests.cases", side_effect=[["active"], ["missing"]]):
            with self.assertRaisesRegex(ValueError, "absent from the complete list"):
                discover({LABEL: self.binary})

    def test_duplicate_test_names_are_rejected(self):
        with patch("discover_controller_tests.cases", side_effect=[["duplicate", "duplicate"], []]):
            with self.assertRaisesRegex(ValueError, "duplicate libtest"):
                discover({LABEL: self.binary})


if __name__ == "__main__":
    unittest.main()
