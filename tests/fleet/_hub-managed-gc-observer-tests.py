"""Controlled scoped SDK record completeness checks, without provider effects."""

import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "sdk_observer", Path(__file__).with_name("_hub-managed-gc-observer.py"))
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def records():
    common = {"version": 1, "capture_id": "a" * 32, "request_id": "b" * 32,
              "scope": "managed_gc_guard", "key": "controlled/gc/object", "subject_id": "claim"}
    events = [
        {"kind": "request_entry"},
        {"kind": "call_invoke", "ordinal": 1, "method": "head", "range": None},
        {"kind": "call_result", "ordinal": 1, "method": "head", "outcome": {
            "kind": "object", "size": 42, "etag": '"actual-tag"', "version": "actual-upload"}},
        {"kind": "call_invoke", "ordinal": 2, "method": "delete", "range": None},
        {"kind": "call_result", "ordinal": 2, "method": "delete", "outcome": {"kind": "resolved"}},
        {"kind": "request_terminal", "healthy": True, "invoked": 2, "completed": 2, "pending": 0},
    ]
    return [{**common, "event": event} for event in events]


def collect(selected):
    return observer.collect(selected, "a" * 32, "c" * 64, [{
        "scope": "managed_gc_guard", "key": "controlled/gc/object", "subject_id": "claim",
    }])


class ObserverTests(unittest.TestCase):
    def test_exact_closed_brackets_join_actual_invocation_and_metadata(self):
        window = collect(records())
        self.assertEqual(window["coverage"], "scoped_requests_complete")
        self.assertEqual(window["calls"][0]["result"], {
            "size": 42, "etag": '"actual-tag"', "version": "actual-upload"})
        self.assertEqual(window["brackets"][0]["invoked"], 2)

    def test_missing_repeated_late_and_unknown_events_refuse(self):
        mutations = [
            lambda rows: rows.pop(0), lambda rows: rows.pop(2), lambda rows: rows.pop(),
            lambda rows: rows.insert(1, copy.deepcopy(rows[0])),
            lambda rows: rows.insert(3, copy.deepcopy(rows[2])),
            lambda rows: rows.append(copy.deepcopy(rows[2])),
            lambda rows: rows[-1]["event"].update(healthy=False),
            lambda rows: rows[-1]["event"].update(pending=1),
            lambda rows: rows[-1]["event"].update(completed=1),
            lambda rows: rows[2]["event"].update(outcome={"kind": "unknown"}),
        ]
        for mutate in mutations:
            selected = records()
            mutate(selected)
            with self.assertRaises(ValueError):
                collect(selected)

    def test_actual_empty_guard_bracket_is_required_for_zero_calls(self):
        selected = records()
        selected = [selected[0], {**selected[-1], "event": {
            "kind": "request_terminal", "healthy": True, "invoked": 0, "completed": 0, "pending": 0}}]
        self.assertEqual(collect(selected)["calls"], [])
        for invalid in ([], selected[:1]):
            with self.assertRaises(ValueError):
                collect(invalid)

    def test_foreign_scope_selection_and_byte_bounds_refuse(self):
        for field, value in (("capture_id", "d" * 32), ("subject_id", "other-claim"),
                             ("key", "other/object"), ("request_id", "B" * 32),
                             ("scope", "universal_r2")):
            selected = records()
            selected[2][field] = value
            with self.assertRaises(ValueError):
                collect(selected)
        selected = records()
        selected[2]["event"]["outcome"]["version"] = "x" * 4096
        with self.assertRaises(ValueError):
            collect(selected)
        with self.assertRaises(ValueError):
            observer.collect(records(), "a" * 32, "c" * 64, [])

    def test_range_scope_records_exact_sdk_arguments(self):
        selected = records()
        selected = [selected[0], selected[1], selected[2], selected[-1]]
        for row in selected:
            row["scope"] = "managed_inventory_range"
            row["subject_id"] = "actual-plan"
        selected[1]["event"].update(method="get", range=[65_536, 8_192])
        selected[2]["event"]["method"] = "get"
        selected[-1]["event"].update(invoked=1, completed=1)
        expected = [{"scope": "managed_inventory_range", "key": "controlled/gc/object",
                     "subject_id": "actual-plan"}]
        window = observer.collect(selected, "a" * 32, "c" * 64, expected)
        self.assertEqual(window["calls"][0]["range"], [65_536, 8_192])
        selected[1]["event"]["range"] = None
        with self.assertRaises(ValueError):
            observer.collect(selected, "a" * 32, "c" * 64, expected)


if __name__ == "__main__":
    unittest.main()
