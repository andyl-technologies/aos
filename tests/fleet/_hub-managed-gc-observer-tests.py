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


    def test_terminal_cleanup_exact_capture_scope_and_full_commitments(self):
        selected = records()
        subject = "c" * 64 + "d" * 64
        for row in selected:
            row.update(scope="managed_terminal_cleanup", subject_id=subject)
        selected.insert(3, {**selected[0], "event": {
            "kind": "call_invoke", "ordinal": 2, "method": "get", "range": None}})
        selected.insert(4, {**selected[2], "event": {
            **selected[2]["event"], "ordinal": 2, "method": "get"}})
        selected[5]["event"]["ordinal"] = 3
        selected[6]["event"]["ordinal"] = 3
        selected[-1]["event"].update(invoked=3, completed=3)
        expected = [{"scope": "managed_terminal_cleanup", "key": "controlled/gc/object",
                     "subject_id": subject}]
        window = observer.collect(selected, "a" * 32, "e" * 64, expected)
        self.assertEqual([call["method"] for call in window["calls"]], ["head", "get", "delete"])
        for field, value in (("capture_id", "f" * 32), ("scope", "managed_gc_guard"),
                             ("subject_id", "c" * 128), ("key", "other/object")):
            altered = copy.deepcopy(selected)
            altered[2][field] = value
            with self.assertRaises(ValueError):
                observer.collect(altered, "a" * 32, "e" * 64, expected)
        selected[3]["event"]["range"] = [0, 1]
        with self.assertRaises(ValueError):
            observer.collect(selected, "a" * 32, "e" * 64, expected)

    def test_terminal_cleanup_zero_requires_actual_healthy_route_footer(self):
        subject = "c" * 64 + "d" * 64
        selected = records()
        selected = [selected[0], {**selected[-1], "event": {
            "kind": "request_terminal", "healthy": True, "invoked": 0, "completed": 0, "pending": 0}}]
        for row in selected:
            row.update(scope="managed_terminal_cleanup", subject_id=subject)
        expected = [{"scope": "managed_terminal_cleanup", "key": "controlled/gc/object",
                     "subject_id": subject}]
        self.assertEqual(observer.collect(selected, "a" * 32, "e" * 64, expected)["calls"], [])
        for altered in ([], selected[:1], [selected[0], {**selected[1], "event": {
                **selected[1]["event"], "healthy": False}}]):
            with self.assertRaises(ValueError):
                observer.collect(altered, "a" * 32, "e" * 64, expected)
        for invalid in ("c" * 64, "C" * 128, "c" * 129):
            with self.assertRaises(ValueError):
                observer.collect(selected, "a" * 32, "e" * 64, [{**expected[0], "subject_id": invalid}])


if __name__ == "__main__":
    unittest.main()
