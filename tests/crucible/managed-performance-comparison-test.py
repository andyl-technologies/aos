"""Exercise baseline compatibility and regression refusal without native claims."""

import copy
import runpy
from pathlib import Path
import unittest

comparison = runpy.run_path(str(Path(__file__).with_name("managed-performance-comparison.py")))
compare = comparison["compare_no_regression"]


def receipt():
    return {
        "schema": comparison["SCHEMA"],
        "profile": {"host": "declared host", "storage": "declared storage", "cpu_affinity": "0-3"},
        "producer": {"qemu": "a" * 64, "plugin": "a" * 64},
        "inputs": {"guest": "a" * 64},
        "timing_contract": "spawn-to-authenticated-stop",
        "samples": [dict(workload="bios", ram_mib=64, seconds=elapsed,
                         accepted_assignment=True, managed_owner=True, native_cleanup=True)
                    for elapsed in (1.0, 2.0)],
    }


class ComparisonTests(unittest.TestCase):
    def test_same_or_faster_measured_contract_passes(self):
        baseline, candidate = receipt(), receipt()
        candidate["producer"]["qemu"] = "b" * 64
        candidate["samples"][0]["seconds"] = 0.5
        self.assertEqual(compare(baseline, candidate)[0]["repeat_count"], 2)

    def test_median_and_tail_regressions_refuse(self):
        for times in ((1.1, 2.0), (0.5, 2.1)):
            candidate = receipt()
            for sample, elapsed in zip(candidate["samples"], times):
                sample["seconds"] = elapsed
            with self.assertRaises(AssertionError):
                compare(receipt(), candidate)

    def test_other_profiles_inputs_intervals_and_counts_refuse(self):
        for field in ("profile", "inputs", "timing_contract"):
            candidate = receipt()
            if field == "profile":
                candidate[field]["storage"] = "another declared storage"
            elif field == "inputs":
                candidate[field]["guest"] = "b" * 64
            else:
                candidate[field] = "another timing interval"
            with self.assertRaises(ValueError):
                compare(receipt(), candidate)
        candidate = receipt()
        candidate["samples"].append(copy.deepcopy(candidate["samples"][0]))
        with self.assertRaises(ValueError):
            compare(receipt(), candidate)

    def test_unowned_nonfinite_and_missing_measurements_refuse(self):
        for mutation in (
            lambda value: value["samples"][0].update(native_cleanup=False),
            lambda value: value["samples"][0].update(seconds=float("nan")),
            lambda value: value["samples"][0].update(seconds=True),
            lambda value: value["samples"][0].update(ram_mib=True),
            lambda value: value.update(timing_contract=True),
            lambda value: value.update(samples=[]),
        ):
            candidate = receipt()
            mutation(candidate)
            with self.assertRaises(ValueError):
                compare(receipt(), candidate)


if __name__ == "__main__":
    unittest.main()
