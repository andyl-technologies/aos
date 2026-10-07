"""Checks invocation-local fanout summaries without provider or runtime effects."""

import importlib.util
from pathlib import Path
import unittest


specification = importlib.util.spec_from_file_location(
    "direct_publisher", Path(__file__).with_name("_hub-direct-publisher.py"))
publisher = importlib.util.module_from_spec(specification)
specification.loader.exec_module(publisher)


def summary(peaks=None):
    values = {name: 1 for name in publisher.DIRECT_CLIENT_COUNTERS}
    values.update(provider_attempts=9, provider_successes=7,
                  acknowledged_bytes=56, max_provider_active=7)
    fields = [f"{name}={values[name]}" for name in publisher.DIRECT_CLIENT_COUNTERS]
    if peaks is not None:
        fields.extend(f"{name}={value}" for name, value in
                      zip(publisher.DIRECT_CLIENT_FANOUT_COUNTERS, peaks))
    return "Direct upload client: " + " ".join(fields)


def invocation(peaks=None, label="a", exit_code=0, timed_out=False, available=True):
    return {"label": label, "result": {"exitCode": exit_code, "timedOut": timed_out},
            "terminalCountersAvailable": available, "stderr": summary(peaks)}


class ClientFanoutCompatibility(unittest.TestCase):
    def test_legacy_17_retains_counters_and_marks_fanout_unknown(self):
        actual = publisher.direct_client_observations(summary())[0]
        self.assertEqual(actual["provider_successes"], 7)
        self.assertEqual(actual["max_provider_active"], 7)
        self.assertTrue(all(actual[name] is None for name in
                            publisher.DIRECT_CLIENT_FANOUT_COUNTERS))

    def test_new_21_retains_invocation_peaks_without_global_aggregation(self):
        actual = publisher.direct_client_observations(
            summary([2, 4, 2, 3]) + "\n" + summary([1, 2, 4, 4]))
        self.assertEqual([row["max_active_bulk_files"] for row in actual], [2, 1])
        self.assertEqual([row["max_active_metadata_requests"] for row in actual], [3, 4])
        # Exercise the existing fleet aggregation contract: only legacy counters
        # are summed, with the original aggregate peak retained independently.
        aggregate = {name: sum(row[name] for row in actual)
                     for name in publisher.DIRECT_CLIENT_COUNTERS}
        aggregate["max_provider_active"] = max(row["max_provider_active"] for row in actual)
        self.assertEqual(aggregate["provider_attempts"], 18)
        self.assertEqual(aggregate["max_provider_active"], 7)
        self.assertNotIn("max_active_bulk_files", aggregate)

    def test_telemetry_loss_is_unknown_while_measured_zero_is_zero(self):
        lost = publisher.direct_client_observations(summary(["unavailable"] * 4))[0]
        zero = publisher.direct_client_observations(summary([0] * 4))[0]
        self.assertTrue(all(lost[name] is None for name in publisher.DIRECT_CLIENT_FANOUT_COUNTERS))
        self.assertTrue(all(zero[name] == 0 for name in publisher.DIRECT_CLIENT_FANOUT_COUNTERS))
        self.assertEqual(lost["provider_attempts"], 9)

    def test_closed_shape_and_bounded_values_refuse_partial_or_untrusted_fields(self):
        valid = summary([2, 4, 2, 3])
        words = valid.split()
        malformed = [
            " ".join(words[:-1]),
            valid + " extra=1",
            valid.replace("max_active_bulk_files=2", "max_active_metadata_files=2"),
            valid.replace("max_active_bulk_files=2", "max_active_bulk_files=NaN"),
            valid.replace("max_active_bulk_files=2", "max_active_bulk_files=-1"),
            valid.replace("max_active_bulk_files=2", "max_active_bulk_files=02"),
            valid.replace("max_active_bulk_files=2", "max_active_bulk_files=18446744073709551616"),
            valid.replace("max_active_bulk_files=2", "max_active_bulk_files=unavailable"),
            summary().replace("provider_successes=7", "provider_successes=10"),
        ]
        for line in malformed:
            with self.subTest(line=line), self.assertRaises(ValueError):
                publisher.direct_client_observations(line)


class MetadataFanoutQualification(unittest.TestCase):
    def test_selects_one_successful_full_corpus_invocation(self):
        records = [invocation([2, 4, 2, 3], exit_code=1),
                   invocation([2, 4, 2, 4])]

        observed = publisher.direct_metadata_fanout(records, "a")

        self.assertEqual(observed, {
            "invocationIndex": 1, "publicationLabel": "a",
            "peaks": {"max_active_metadata_files": 2, "max_active_metadata_requests": 4},
        })

    def test_bulk_overlap_or_separate_peaks_do_not_satisfy_metadata_overlap(self):
        records = [invocation([8, 8, 2, 1]), invocation([8, 8, 1, 2]),
                   invocation([8, 8, 8, 8], label="b")]

        self.assertIsNone(publisher.direct_metadata_fanout(records, "a"))

    def test_unknown_failed_or_interrupted_invocations_cannot_qualify(self):
        records = [invocation(), invocation(["unavailable"] * 4),
                   invocation([2, 4, 2, 4], exit_code=1),
                   invocation([2, 4, 2, 4], timed_out=True),
                   invocation([2, 4, 2, 4], timed_out=None),
                   invocation([2, 4, 2, 4], exit_code=False),
                   invocation([2, 4, 2, 4], available=False)]

        self.assertIsNone(publisher.direct_metadata_fanout(records, "a"))

    def test_duplicate_terminal_records_are_refused(self):
        record = invocation([2, 4, 2, 4])
        record["stderr"] += "\n" + summary([2, 4, 2, 4])

        with self.assertRaises(ValueError):
            publisher.direct_metadata_fanout([record], "a")


if __name__ == "__main__":
    unittest.main()
