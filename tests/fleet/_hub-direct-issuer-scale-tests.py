"""Controlled recorder-format regressions; these are not runtime measurements."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("issuer_scale", Path(__file__).with_name("_hub-direct-issuer-scale.py"))
scale = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scale)


SELECTED = {"runId": "a" * 32, "selectedSourceSha256": "b" * 64,
    "executableSha256": "c" * 64, "authorityConfigurationSha256": "d" * 64,
    "installationSha256": "e" * 64, "processPid": 42, "processStartTicks": "6000"}
REQUEST = {"nonce": "f" * 64, "requestDigest": "1" * 64,
    "receivedBodySha256": "2" * 64, "receivedBodyBytes": 500}


def retained(events, started_cpu=1000, finished_cpu=5000):
    rows = [("opened", None, {**SELECTED,
        "maximumRecordBytes": scale.MAX_RECORD_BYTES, "maximumRecords": scale.MAX_RECORDS,
        "maximumOutputBytes": scale.MAX_OUTPUT_BYTES, "processCpuNs": started_cpu})] + events
    result = bytearray()
    for index, (event, request, fields) in enumerate(rows, 1):
        result.extend((json.dumps({"version": 1, "sequence": index, "atUnixNs": "1700000000000000000",
            "event": event, "request": request, "fields": fields}, separators=(",", ":")) + "\n").encode())
    fields = {"precedingRecords": len(rows), "precedingBytes": len(result),
        "processCpuNs": finished_cpu, "processWindowWallNs": 10000}
    result.extend((json.dumps({"version": 1, "sequence": len(rows) + 1, "atUnixNs": "1700000000000000001",
        "event": "finished", "request": None, "fields": fields}, separators=(",", ":")) + "\n").encode())
    return bytes(result)


def events(cpu=200):
    return [("request_started", REQUEST, {}),
        ("gate_acquired", REQUEST, {"queueWaitNs": 100}),
        ("transaction_commit", REQUEST, {"kind": "lease", "wallNs": 300, "outcome": "acknowledged"}),
        ("signature", REQUEST, {"purpose": "lease", "wallNs": 250, "threadCpuNs": cpu}),
        ("request_completed", REQUEST, {"outcome": "success", "wallNs": 900})]


class RecorderTests(unittest.TestCase):
    def inspect(self, body):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            path = Path(directory) / "observations.jsonl"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(body)
            return scale.collect_local_issuer_observations(path, SELECTED)

    def test_actual_record_counts_are_not_inferred_from_sequence_or_cohort_count(self):
        selected = events() + [("transaction_commit", None,
            {"kind": "clock_observation", "wallNs": 20, "outcome": "acknowledged"})]
        result = self.inspect(retained(selected))

        self.assertEqual(len(result["requests"]), 1)
        self.assertEqual(sum(row["count"] for row in result["commits"]), 2)
        self.assertEqual(result["signatures"], {"lease": 1})
        self.assertEqual(result["wholeProcessCpuNs"], 4000)
        self.assertIsNone(result["qualification"])

    def test_missing_cpu_is_absent_and_never_a_zero_cost_claim(self):
        result = self.inspect(retained(events(None), None, None))

        self.assertEqual(result["missingSigningCpuSamples"], 1)
        self.assertIsNone(result["signingThreadCpuNsObserved"])
        self.assertIsNone(result["wholeProcessCpuNs"])
        self.assertIsNone(scale.whole_issuer_cpu_fraction(None, 1, 1000))
        self.assertIsNone(result["qualification"])

    def test_indeterminate_commit_and_abandonment_remain_actual_errors(self):
        selected = [("request_started", REQUEST, {}),
            ("transaction_commit", REQUEST, {"kind": "lease", "wallNs": 30, "outcome": "indeterminate_error"}),
            ("request_abandoned", REQUEST, {"wallNs": 40, "settlement": "unknown"})]
        result = self.inspect(retained(selected))

        self.assertEqual(result["requests"][REQUEST["nonce"]]["outcome"], "abandoned_unknown")
        self.assertEqual(result["commits"][0]["outcome"], "indeterminate_error")
        self.assertIsNone(result["qualification"])

    def test_missing_terminal_original_substitution_and_repeated_nonce_refuse(self):
        body = retained(events())
        changed = dict(REQUEST, receivedBodySha256="3" * 64)
        for bad in (body[:body.rfind(b"\n", 0, len(body) - 1) + 1],
                retained(events()[:1] + [("gate_acquired", changed, {"queueWaitNs": 10})]),
                retained(events() + [("request_started", REQUEST, {})])):
            with self.subTest(body=bad[:32]), self.assertRaises(ValueError):
                self.inspect(bad)

    def test_private_file_mode_and_healthy_tail_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            path = Path(directory) / "observations.jsonl"
            path.write_bytes(retained(events()))
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                scale.collect_local_issuer_observations(path, SELECTED)
            os.chmod(path, 0o600)
            with self.assertRaises(ValueError):
                scale.collect_local_issuer_observations(path, dict(SELECTED, executableSha256="0" * 64))

    def test_real_sample_count_and_nearest_rank_are_retained_without_padding(self):
        self.assertEqual(scale.measured_latency_summary([]), {"samples": 0, "p95Ns": None, "p99Ns": None})
        result = scale.measured_latency_summary(range(1, 101))
        self.assertEqual(result, {"samples": 100, "p95Ns": 95, "p99Ns": 99})
        self.assertEqual(scale.whole_issuer_cpu_fraction(10, 20, 1000)["numerator"], 1)
        self.assertEqual(scale.whole_issuer_cpu_fraction(10, 20, 1000)["denominator"], 2)
        with self.assertRaises(ValueError):
            scale.whole_issuer_cpu_fraction(1, 0, 1000)

    def test_policy_declares_full_prospective_geometry_not_a_small_success_case(self):
        policy = scale.LOCAL_LEASE_SCALE_POLICY
        self.assertEqual((policy["cohorts"], policy["freshWorkerdProcesses"], policy["maximumFollowersPerCohort"]), (32, 4, 32))
        self.assertEqual(policy["maximumLifetimeSecondsCases"], [8, 120])
        self.assertEqual(policy["observedRenewalsPerTtlCase"], 2)
        self.assertEqual(policy["ownerRetriesInsideOriginalWindow"], 0)
        self.assertEqual(policy["outageThroughActualExpiryCases"], 1)


if __name__ == "__main__":
    unittest.main()
