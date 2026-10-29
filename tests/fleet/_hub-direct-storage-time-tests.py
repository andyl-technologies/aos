"""Refuse missing, ambiguous or invented proxy completion timestamps.

These are controlled access-log parser inputs, not runtime clock observations.
"""

import copy
import importlib.util
import json
from pathlib import Path
import unittest


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


boundary = load("storage_boundary", "_hub-direct-storage-boundary.py")
observations = load("native_observations", "_hub-direct-observations.py")
boundary.NATIVE_OBSERVATION_FIELDS = observations.NATIVE_OBSERVATION_FIELDS
boundary._closed_review_json = json.loads


class CompletionClockRefusals(unittest.TestCase):
    def test_completion_requires_actual_closed_unambiguous_receipt(self):
        value = {name: "" for name in observations.NATIVE_OBSERVATION_FIELDS}
        value.update(request_id="a" * 32, completed_unix_seconds="1770000000.123")
        normalized, clocks = boundary.direct_storage_completion_receipts(json.dumps(value))
        self.assertNotIn("completed_unix_seconds", normalized[0])
        self.assertEqual(clocks, {"a" * 32: "1770000000123"})
        for changed_time in (None, 123, "", "1770000000", "01770000000.123",
                             "1770000000.12", "1770000000.1234", "-1.123"):
            changed = copy.deepcopy(value)
            if changed_time is None:
                changed.pop("completed_unix_seconds")
            else:
                changed["completed_unix_seconds"] = changed_time
            with self.assertRaises(ValueError):
                boundary.direct_storage_completion_receipts(json.dumps(changed))
        with self.assertRaises(ValueError):
            boundary.direct_storage_completion_receipts(json.dumps(value) + "\n" + json.dumps(value))
        received = {**value, "origin_request_id": "b" * 32, "caller": "192.0.2.10"}
        normalized, clocks = boundary.direct_storage_completion_receipts(json.dumps(received), True)
        self.assertEqual(clocks["a" * 32], "1770000000123")
        self.assertEqual(normalized[0]["origin_request_id"], "b" * 32)
        with self.assertRaises(ValueError):
            boundary.direct_storage_completion_receipts(json.dumps(received))


if __name__ == "__main__":
    unittest.main()
