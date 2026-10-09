# SPDX-License-Identifier: Apache-2.0
"""Exercise exact receipt admission and rejected comparisons without a VM."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "comparison", Path(__file__).with_name("ram-completed-throughput-compare.py")
)
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


def fixture(cpu=None):
    """Provide synthetic arithmetic inputs, not native or timing evidence."""
    seed = 1000
    rows = []
    for target in comparison.TARGETS:
        for parallel in comparison.PARALLEL:
            for repeat in comparison.REPEATS:
                samples = []
                for _ in range(parallel):
                    samples.append({"seed": seed, "scenario": [seed % 256] * 32,
                                    "fingerprint": [1] * 32, "charged_physical_quanta": 32,
                                    "emitted_signal_events": 0, "fault_work_items": None,
                                    "resources": dict(zip(comparison.RESOURCE_FIELDS,
                                                          (1536 << 20, 4 << 30,
                                                           512 << 20, 32 << 20,
                                                           1, 1, 69, 1056))),
                                    "requested_target_bytes": target})
                    seed += 1
                rows.append({"target_divisor": target, "parallel": parallel,
                             "repeat": repeat, "elapsed_ns": 100, "completed": parallel,
                             "completed_work_cpu_ns": cpu, "failures": [], "samples": samples})
    return {"schema": comparison.SCHEMA, "quanta_per_attempt": 32,
            "scenario_corpus": [1] * 32, "scenario_seeds": list(range(1000, 1063)),
            "cache_scope": "synthetic uncontrolled cache",
            "completed_work_cpu_scope": comparison.CPU_SCOPE,
            "pinned": {"host": "synthetic host", "storage": "synthetic storage",
                       "cpu_affinity": "0", "artifact_digests": [
                           {"role": role, "bytes": 1, "blake3": [1] * 32}
                           for role in comparison.ROLES]}, "rows": rows}


class CompletedWorkAdmission(unittest.TestCase):
    def test_missing_cpu_remains_null_and_never_qualifies(self):
        result = comparison.compare(fixture(), fixture())
        self.assertFalse(result["cpu_comparison_ready"])
        self.assertFalse(result["performance_qualified"])
        self.assertEqual(len(result["rows"]), 27)
        self.assertTrue(all(row["cpu_ratio"] is None for row in result["rows"]))

    def test_cpu_and_wall_are_separate_unqualified_descriptions(self):
        candidate = fixture(120)
        candidate["rows"][0]["elapsed_ns"] = 50
        result = comparison.compare(fixture(100), candidate)
        self.assertEqual(result["rows"][0]["cpu_ratio"], {"numerator": 6, "denominator": 5})
        self.assertEqual(result["rows"][0]["wall_ratio"], {"numerator": 1, "denominator": 2})
        self.assertFalse(result["performance_qualified"])

    def test_changed_native_build_does_not_change_authored_work(self):
        candidate = fixture()
        candidate["pinned"]["artifact_digests"][0]["blake3"] = [2] * 32
        self.assertEqual(len(comparison.compare(fixture(), candidate)["rows"]), 27)

    def test_changed_guest_bytes_are_not_a_matching_baseline(self):
        candidate = fixture()
        candidate["pinned"]["artifact_digests"][2]["blake3"] = [2] * 32
        with self.assertRaisesRegex(ValueError, "guest artifact"):
            comparison.compare(fixture(), candidate)

    def test_failed_and_partial_rows_cannot_be_dropped(self):
        for mutate in (lambda row: row["failures"].append("synthetic failure"),
                       lambda row: row.update(completed=0)):
            candidate = fixture()
            mutate(candidate["rows"][0])
            with self.assertRaises(ValueError):
                comparison.compare(fixture(), candidate)

    def test_missing_duplicate_and_foreign_rows_fail(self):
        for mutate in (lambda rows: rows.pop(), lambda rows: rows.append(copy.deepcopy(rows[0])),
                       lambda rows: rows[0].update(target_divisor=3)):
            candidate = fixture()
            mutate(candidate["rows"])
            with self.assertRaises(ValueError):
                comparison.compare(fixture(), candidate)

    def test_same_seed_requires_same_state_work_and_resource_caps(self):
        changed_resources = dict(zip(
            comparison.RESOURCE_FIELDS,
            (2 << 30, 4 << 30, 512 << 20, 32 << 20, 1, 1, 69, 1056),
        ))
        for field, value in (
            ("fingerprint", [2] * 32),
            ("charged_physical_quanta", 31),
            ("resources", changed_resources),
        ):
            candidate = fixture()
            candidate["rows"][0]["samples"][0][field] = value
            with self.assertRaisesRegex(ValueError, "actual work/state"):
                comparison.compare(fixture(), candidate)

    def test_seed_reuse_and_moves_between_families_fail(self):
        candidate = fixture()
        candidate["rows"][1]["samples"][0]["seed"] = 1000
        with self.assertRaisesRegex(ValueError, "reused seed"):
            comparison.compare(fixture(), candidate)
        candidate = fixture()
        first = candidate["rows"][0]["samples"][0]
        second = candidate["rows"][1]["samples"][0]
        first["seed"], second["seed"] = second["seed"], first["seed"]
        with self.assertRaisesRegex(ValueError, "seed moved"):
            comparison.compare(fixture(), candidate)

    def test_host_storage_cpu_scope_and_nonpositive_cpu_fail(self):
        for mutate in (lambda receipt: receipt["pinned"].update(host="other host"),
                       lambda receipt: receipt["pinned"].update(storage="other storage"),
                       lambda receipt: receipt.update(completed_work_cpu_scope="controller only"),
                       lambda receipt: receipt["rows"][0].update(completed_work_cpu_ns=0)):
            candidate = fixture(100)
            mutate(candidate)
            with self.assertRaises(ValueError):
                comparison.compare(fixture(100), candidate)

    def test_same_edition_scope_is_explicit_and_never_certified(self):
        result = comparison.compare(fixture(), fixture())
        self.assertIn("same fingerprint edition", result["comparison_scope"])
        self.assertFalse(result["fingerprint_edition_verified"])
        self.assertTrue(any("cross-edition" in hold for hold in result["holds"]))

    def test_matching_forged_seed_partition_is_rejected(self):
        forged = fixture()
        first = forged["rows"][0]["samples"][0]
        second = forged["rows"][1]["samples"][0]
        first["seed"], second["seed"] = second["seed"], first["seed"]
        with self.assertRaisesRegex(ValueError, "fixed family"):
            comparison.compare(forged, copy.deepcopy(forged))

    def test_all_eight_admitted_resource_dimensions_are_required(self):
        for field in comparison.RESOURCE_FIELDS:
            forged = fixture()
            del forged["rows"][0]["samples"][0]["resources"][field]
            with self.assertRaisesRegex(ValueError, "resource vector"):
                comparison.compare(forged, copy.deepcopy(forged))
        forged = fixture()
        forged["rows"][0]["samples"][0]["resources"]["unpaid_ninth_bank"] = 0
        with self.assertRaisesRegex(ValueError, "resource vector"):
            comparison.compare(forged, copy.deepcopy(forged))

    def test_invalid_resource_counters_are_not_equal_work(self):
        for value in (-1, True, 2**64, "1"):
            forged = fixture()
            forged["rows"][0]["samples"][0]["resources"]["cpu_slots"] = value
            with self.assertRaisesRegex(ValueError, "resource field"):
                comparison.compare(forged, copy.deepcopy(forged))

    def test_empty_or_nonscalar_host_labels_fail(self):
        for value in ("", None, {}, "x" * 1025):
            forged = fixture()
            forged["pinned"]["host"] = value
            with self.assertRaisesRegex(ValueError, "profile label"):
                comparison.compare(forged, copy.deepcopy(forged))

    def test_pinned_bytes_and_duplicate_json_fields_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            raw = json.dumps(fixture()).encode()
            path.write_bytes(raw)
            expected = hashlib.sha256(raw).hexdigest()
            self.assertEqual(comparison.read_pinned(path, expected)["schema"], comparison.SCHEMA)
            path.write_bytes(raw + b" ")
            with self.assertRaisesRegex(ValueError, "receipt identity"):
                comparison.read_pinned(path, expected)
            raw = b'{"schema":1,"schema":2}'
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "duplicate JSON"):
                comparison.read_pinned(path, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()
