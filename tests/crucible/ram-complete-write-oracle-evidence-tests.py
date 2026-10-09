"""Exercises log-contract rejection, not native or guest eligibility."""

import argparse
import importlib.util
import io
from pathlib import Path
import unittest

parser = argparse.ArgumentParser()
parser.add_argument("--evidence-tool", type=Path, default=Path(__file__).with_name("ram-complete-write-oracle-evidence.py"))
arguments, remaining = parser.parse_known_args()
specification = importlib.util.spec_from_file_location("evidence", arguments.evidence_tool)
evidence = importlib.util.module_from_spec(specification)
specification.loader.exec_module(evidence)


def fixture(negative=False):
    return [
        "complete_write_oracle_baseline raw=1 hash=" + "0" * 64,
        "crucible RAM owner diagnostic raw=700000 vmstop=1 topology=4 token=9 first=0 proc_close=0 release=0 capture_generation=2 capture=0 attempted=1",
        "complete_write_oracle_first raw=700000 hash=" + "1" * 64,
        "crucible RAM owner diagnostic raw=1400000 vmstop=2 topology=4 token=10 first=" + ("-74" if negative else "0") + " proc_close=0 release=0 capture_generation=3 capture=0 attempted=1",
        "complete_write_oracle_write raw=1400000 before=0000000000000001 after=0000000000000002",
        "complete_write_oracle_identity " + ("unavailable=true" if negative else "changed=true"),
        "complete_write_oracle_cleanup reaped=true resources_restored=true",
    ]


class LogControls(unittest.TestCase):
    def test_exact_positive_and_reached_mismatch_contracts(self):
        evidence.validate(fixture(), "oracle-positive")
        evidence.validate(fixture(True), "notification-adversary")

    def test_every_required_event_is_mandatory(self):
        original = fixture(True)
        for index in range(len(original)):
            with self.subTest(omitted=index):
                with self.assertRaises(ValueError):
                    evidence.validate(original[:index] + original[index + 1:], "notification-adversary")

    def test_every_event_is_single_use_and_ordered(self):
        original = fixture()
        for index in range(len(original)):
            with self.subTest(duplicated=index):
                with self.assertRaises(ValueError):
                    evidence.validate(original[:index] + [original[index]] + original[index:], "oracle-positive")
        changed = fixture()
        changed[2], changed[3] = changed[3], changed[2]
        with self.assertRaises(ValueError):
            evidence.validate(changed, "oracle-positive")

    def test_seed_after_candidate_cannot_authenticate_baseline(self):
        changed = fixture()
        changed[0], changed[1] = changed[1], changed[0]
        with self.assertRaises(ValueError):
            evidence.validate(changed, "oracle-positive")

    def test_unrelated_error_or_surviving_notification_does_not_pass_negative(self):
        for status in ["0", "-5", "-16", "-71"]:
            changed = fixture(True)
            changed[3] = changed[3].replace("first=-74", "first=" + status)
            with self.subTest(status=status):
                with self.assertRaises(ValueError):
                    evidence.validate(changed, "notification-adversary")

    def test_uncertain_capture_and_physical_close_are_refused(self):
        for before, after in [("capture=0", "capture=-5"), ("attempted=1", "attempted=0"), ("release=0", "release=-5"), ("proc_close=0", "proc_close=-5")]:
            changed = fixture()
            changed[3] = changed[3].replace(before, after)
            with self.subTest(field=before):
                with self.assertRaises(ValueError):
                    evidence.validate(changed, "oracle-positive")

    def test_reused_owner_drift_or_unchanged_bytes_are_refused(self):
        for before, after in [("token=10", "token=9"), ("topology=4", "topology=5"), ("vmstop=2", "vmstop=1")]:
            changed = fixture()
            changed[3] = changed[3].replace(before, after)
            with self.assertRaises(ValueError):
                evidence.validate(changed, "oracle-positive")
        changed = fixture()
        changed[4] = changed[4].replace("after=0000000000000002", "after=0000000000000001")
        with self.assertRaises(ValueError):
            evidence.validate(changed, "oracle-positive")

    def test_native_scalar_width_and_canonical_encoding_are_required(self):
        for before, after in [("token=9", "token=09"), ("token=9", "token=18446744073709551616"), ("first=0", "first=-0")]:
            changed = fixture()
            changed[1] = changed[1].replace(before, after)
            with self.assertRaises(ValueError):
                evidence.validate(changed, "oracle-positive")

    def test_bounded_reader_discards_only_unrelated_long_lines(self):
        text = ("unrelated" * 300 + "\n" + "\n".join(fixture()) + "\n").encode()
        evidence.validate(evidence.records(io.BytesIO(text)), "oracle-positive")
        with self.assertRaises(ValueError):
            list(evidence.records(io.BytesIO(("complete_write_oracle_" + "x" * 1100 + "\n").encode())))

    def test_trailing_or_noncanonical_fields_are_not_ignored(self):
        for suffix in [" extra=1", "\r", " scope=1"]:
            changed = fixture()
            changed[1] += suffix
            with self.assertRaises(ValueError):
                evidence.validate(changed, "oracle-positive")


if __name__ == "__main__":
    unittest.main(argv=[__file__, *remaining])
