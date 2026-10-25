"""Rejects incomplete or misattributed ABI owner qualification evidence."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from verify_abi_owners import canonical_owners, validate_selections, verify_owner


CANONICAL = (
    "require_test_set 2 protocol \\\n"
    "  canonical_case \\\n"
    "  -p protocol --test gate_abi_conformance\n"
)


class AbiOwnerEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.build = Path(self.scratch.name)
        self.evidence = self.build / "evidence"
        self.tests = self.evidence / "tests/owner"
        self.tests.mkdir(parents=True)
        self.contract = {
            "count": 2, "canonical": "canonical_case", "filter": None,
            "target": "//protocol:gate_abi_conformance",
        }
        self.action = {
            "mnemonic": "TestRunner", "targetLabel": self.contract["target"],
            "exitCode": 0, "runner": "linux-sandbox", "cacheHit": False,
            "commandArgs": ["runner", "--expected-count=2", "--require-case=canonical_case", "--jobs=1"],
        }
        self.xml = ('<testsuite tests="2" failures="0">'
                    '<testcase name="canonical_case"/><testcase name="other_case"/></testsuite>')
        self.write_evidence()

    def write_evidence(self):
        (self.evidence / "execution.json").write_text(json.dumps(self.action))
        (self.tests / "test.xml").write_text(self.xml)

    def test_canonical_inventory_refuses_missing_extra_and_changed_owners(self):
        validate_selections(CANONICAL, {"protocol": self.contract})
        for selections in [
            {}, {"protocol": self.contract, "extra": self.contract},
            {"protocol": dict(self.contract, count=1)},
            {"protocol": dict(self.contract, canonical="renamed")},
        ]:
            with self.subTest(selections=selections), self.assertRaises(ValueError):
                validate_selections(CANONICAL, selections)

    def test_canonical_inventory_refuses_unparsed_or_duplicate_guards(self):
        for source in ["", CANONICAL + CANONICAL, CANONICAL + "require_test_set unknown\n",
                       CANONICAL.replace("2 protocol", "0 protocol")]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                canonical_owners(source)

    def test_complete_sandboxed_execution_is_retained(self):
        result = verify_owner(self.build, self.contract)

        self.assertEqual(result["cases"], ["canonical_case", "other_case"])
        self.assertEqual(len(result["junit_sha256"]), 64)
        self.assertEqual(len(result["execution_sha256"]), 64)

    def test_xml_refuses_skip_failure_duplicate_and_incomplete_inventories(self):
        original = self.xml
        for xml in [
            original.replace('<testcase name="other_case"/>', ''),
            original.replace('name="other_case"', 'name="canonical_case"'),
            original.replace('name="canonical_case"', 'name="renamed"'),
            original.replace('tests="2"', 'tests="3"'),
            original.replace('<testcase name="other_case"/>', '<testcase name="other_case"><skipped/></testcase>'),
            original.replace('<testcase name="other_case"/>', '<testcase name="other_case"><failure/></testcase>'),
        ]:
            self.xml = xml
            self.write_evidence()
            with self.subTest(xml=xml), self.assertRaises(ValueError):
                verify_owner(self.build, self.contract)

    def test_action_refuses_cache_execution_failure_and_missing_guards(self):
        original = copy.deepcopy(self.action)
        for change in [
            {"cacheHit": True}, {"runner": "local"}, {"exitCode": 1},
            {"targetLabel": "//other:owner"},
            {"commandArgs": original["commandArgs"][:-1]},
            {"commandArgs": original["commandArgs"] + ["--jobs=2"]},
        ]:
            self.action = dict(original, **change)
            self.write_evidence()
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_owner(self.build, self.contract)


if __name__ == "__main__":
    unittest.main()
