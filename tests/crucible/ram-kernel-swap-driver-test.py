# SPDX-License-Identifier: Apache-2.0
"""Check fixed input binding without an experiment launch or swap mutation."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "driver", Path(__file__).with_name("ram-kernel-swap-driver.py")
)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class FixedResearchInputs(unittest.TestCase):
    def test_fixed_corpus_and_separate_baseline_keep_same_seeds(self):
        research = driver.requests("kernel-swap")
        baseline = driver.requests("resident-baseline")
        self.assertEqual(len(research), 81)
        self.assertEqual(sum(len(row["attempts"]) for row in research), 189)
        identities = set()
        for delay in driver.DELAYS_MS:
            cohort = [row for row in research if row["delay_ms"] == delay]
            self.assertEqual(len(cohort), 27)
            self.assertEqual(sum(len(row["attempts"]) for row in cohort), 63)
            self.assertEqual({attempt["seed"] for row in cohort for attempt in row["attempts"]},
                             set(range(1000, 1063)))
        for candidate, reference in zip(research, baseline):
            for current, previous in zip(candidate["attempts"], reference["attempts"]):
                self.assertEqual(current["id"], previous["id"])
                self.assertEqual(current["seed"], previous["seed"])
                self.assertEqual(previous["target_bytes"], 512 << 20)
                self.assertNotIn(current["id"], identities)
                identities.add(current["id"])
        self.assertEqual(len(identities), 189)

    def test_prepared_actual_bytes_are_pinned_but_never_authorize_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = {}
            for role in driver.ARTIFACT_ROLES:
                path = Path(directory) / role
                path.write_bytes(role.encode())
                artifacts[role] = path
            prepared = driver.prepare("kernel-swap", artifacts)
            self.assertFalse(prepared["launch_eligible"])
            self.assertEqual(prepared["materialized_bytes"], 384 << 20)
            self.assertEqual(prepared["maximum_reclaim_rounds"], 4)
            self.assertEqual(prepared["swappiness"], 200)
            self.assertEqual(prepared["swap_partition_bytes"], 4 << 30)
            self.assertEqual(prepared["attempt_count"], 189)
            for role in driver.ARTIFACT_ROLES:
                self.assertEqual(prepared["artifacts"][role]["sha256"],
                                 hashlib.sha256(role.encode()).hexdigest())
            self.assertEqual(prepared["assignment_resources"]["resident_peak_bytes"], 1536 << 20)
            self.assertEqual(prepared["assignment_resources"]["file_descriptors"], 1056)
            self.assertEqual((prepared["attempt_seconds"], prepared["matrix_seconds"],
                              prepared["outer_seconds"]), (1200, 3600, 3900))

    def test_empty_symlink_directory_and_missing_artifacts_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            empty = base / "empty"
            empty.touch()
            link = base / "link"
            link.symlink_to(empty)
            for path in (empty, link, base, base / "absent"):
                with self.assertRaises((ValueError, OSError)):
                    driver.pin_artifact(path)
            with self.assertRaisesRegex(ValueError, "artifact roles"):
                driver.prepare("kernel-swap", {})

    def test_zero_without_swapped_pages_is_not_a_reached_target(self):
        observation = {"pte_present_pages": 131072, "pte_swapped_pages": 0,
                       "pte_absent_pages": 0, "resident_pages": 131072,
                       "scan_zero_pages": 0, "sampled_swapped_nonresident_pages": 0,
                       "changed_pte_pages": 0}
        self.assertEqual(driver.target_disposition({"target_bytes": 0}, observation),
                         "TargetNotReached")
        observation.update(pte_present_pages=65536, pte_swapped_pages=65536,
                           resident_pages=65536, sampled_swapped_nonresident_pages=65536)
        self.assertEqual(driver.target_disposition({"target_bytes": 0}, observation),
                         "IntervalOnly")

    def test_interval_samples_do_not_certify_simultaneous_half_residency(self):
        observation = {"pte_present_pages": 65536, "pte_swapped_pages": 65536,
                       "pte_absent_pages": 0, "resident_pages": 65536,
                       "scan_zero_pages": 0, "sampled_swapped_nonresident_pages": 65536,
                       "changed_pte_pages": 0}
        self.assertEqual(driver.target_disposition({"target_bytes": 256 << 20}, observation),
                         "IntervalOnly")
        for field, value in (("pte_swapped_pages", 131073), ("resident_pages", True),
                             ("pte_absent_pages", 1), ("changed_pte_pages", -1)):
            malformed = dict(observation, **{field: value})
            with self.assertRaises(ValueError):
                driver.target_disposition({"target_bytes": 256 << 20}, malformed)


if __name__ == "__main__":
    unittest.main()
