"""Check exact completion forwarding with controlled codec selections.

These parser inputs are not runtime clock or permission observations.
"""

import copy
import importlib.util
from pathlib import Path
import unittest


path = Path(__file__).with_name("_hub-direct-codec-assessment.py")
specification = importlib.util.spec_from_file_location("codec_assessment", path)
assessment = importlib.util.module_from_spec(specification)
specification.loader.exec_module(assessment)


class CompletionSelectionRefusals(unittest.TestCase):
    def test_exact_proxy_observation_survives_codec_projection(self):
        selected = {"sourceDigest": "a" * 64, "completionObservedAtUnixMillis": "1770000000123",
            "originalPlan": {"file": "/controlled/original.json", "sha256": "b" * 64,
                "byteSize": 37}}
        result = assessment.direct_storage_codec_selection(selected, "a" * 64)
        self.assertEqual(result["completionObservedAtUnixMillis"], "1770000000123")
        self.assertEqual(result["originalPlan"]["byteSize"], "37")
        self.assertEqual(selected["originalPlan"]["byteSize"], 37)

        for value in (None, 0, "0", "", "01770000000123", "-1", "1.23"):
            changed = copy.deepcopy(selected)
            changed["completionObservedAtUnixMillis"] = value
            with self.assertRaises(ValueError):
                assessment.direct_storage_codec_selection(changed, "a" * 64)
        missing = copy.deepcopy(selected)
        del missing["completionObservedAtUnixMillis"]
        with self.assertRaises(ValueError):
            assessment.direct_storage_codec_selection(missing, "a" * 64)
        with self.assertRaises(ValueError):
            assessment.direct_storage_codec_selection(selected, "c" * 64)


if __name__ == "__main__":
    unittest.main()
