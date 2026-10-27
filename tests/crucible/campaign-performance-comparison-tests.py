# SPDX-License-Identifier: Apache-2.0
"""Finite acceptance controls; none of these artifacts is a measured baseline."""

import copy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

V = runpy.run_path(str(Path(__file__).with_name("campaign-performance-comparison.py")))


class PairedArtifactControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="campaign-paired-controls-")
        self.root = Path(self.temporary.name)
        self.store = self.root / "store"
        self.store.mkdir()
        self.reference = "a" * 40
        self.candidate = "b" * 40
        self.host = self.root / "reference-host.env"
        self.host.write_text("schema=crucible.campaign-performance.reference-host.v1\nhost_pinned_cpu=0\n")
        self.required = [
            "corpus_0_campaign_planner_queue_ns",
            "corpus_0_hot_guest_continuation_ns",
        ]
        self.plan = {
            "schema": "crucible.campaign-performance.decision.v2",
            "method": "paired-median-eight-marginal-upper-at-most-one-v2",
            "required_metrics": self.required,
            "unaffected_metrics": {name: "control fixture: outside tested metric scope" for name in V["METRICS"] if name not in self.required},
            "conditions": {key: "c" * 64 for key in V["CONDITION_KEYS"]},
            "production": {self.reference: {"original.rs": "d" * 64}, self.candidate: {"candidate.rs": "e" * 64}},
            "max_planner_queue_ratio_ppm": 49_999,
        }
        self.plan_path = self.root / "decision.json"
        self.plan_path.write_text(json.dumps(self.plan))
        self.comparison = {
            "schema": "crucible.campaign-performance.comparison.v2",
            "reference_revision": self.reference,
            "candidate_revision": self.candidate,
            "reference_host_profile_sha256": V["digest"](self.host.read_bytes()),
            "decision_plan_sha256": V["digest"](self.plan_path.read_bytes()),
            "max_planner_queue_ratio_ppm": 49_999,
            "pairs": [],
        }
        self.path = self.root / "comparison.json"
        for ordinal in range(8):
            self.comparison["pairs"].append({
                "ordinal": ordinal, "order": "AB" if ordinal % 2 == 0 else "BA",
                "reference": self.member(ordinal * 2, self.reference),
                "candidate": self.member(ordinal * 2 + 1, self.candidate),
            })

    def tearDown(self):
        self.temporary.cleanup()

    def member(self, number, revision):
        # The private parser-control root is the only substitution; public CLI
        # validation still requires actual canonical /nix/store outputs.
        output = self.store / (f"{number:032d}-control-sample")
        output.mkdir()
        sample_id = f"{number:032x}"
        source = {
            "schema": "crucible.campaign-performance.source.v2",
            "revision": revision, "sample_id": sample_id,
            "conditions": self.plan["conditions"],
            "production": self.plan["production"][revision],
        }
        (output / "performance-source-manifest.json").write_text(json.dumps(source))
        (output / "result").write_text("PASS\n")
        (output / "host-reference.env").write_text(self.host.read_text() + "host_allowed_cpus=0\nhost_boot_id=" + "a" * 8 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 12 + "\n")
        lines = [
            f"campaign_performance_sample_id={sample_id}",
            "campaign_performance_provenance_json=" + json.dumps(source),
            "campaign_guest_cpu_affinity=0", "campaign_planner_supervisor=packaged-process",
            "campaign_blob_backend=sqlite-store-graph", "campaign_short_branch_boundary=two-node-pending-selectable",
        ]
        for name in V["METRICS"]:
            lines.append(f"{name}={10 if name.endswith('planner_queue_ns') else 1000}")
        lines += ["campaign_planner_queue_total_ns=30", "hot_guest_continuation_total_ns=3000"]
        for index in range(3):
            work = json.dumps({
                "schema": "crucible.campaign-performance.work.v2", "corpus": index,
                "planner": {"queue_attempts": 1},
                "hot": {"outcomes": [{"configuration": "f" * 64, "frontier_ticks": 1}]},
                "exact": {"outcomes": [{"configuration": "f" * 64, "frontier_ticks": 1}]},
            })
            (output / f"corpus-{index}-work.json").write_text(work)
            lines.append(f"corpus_{index}_campaign_work_json={work}")
        # Match the genuine producer: independent provenance once, then live
        # tee output and a repeated final completed measurement report.
        provenance = lines.pop(1)
        report = "\n".join(lines) + "\n"
        serial = (provenance + "\n" + report + V["MEASUREMENT_BEGIN"] + "\n"
                  + report + V["MEASUREMENT_END"] + "\n")
        (output / "serial.log").write_text(serial)
        return self.rebind(output)

    def rebind(self, output):
        return {
            "output": str(output),
            **{name + "_sha256": V["digest"]((output / file).read_bytes()) for name, file in (
                ("source_manifest", "performance-source-manifest.json"), ("result", "result"),
                ("serial", "serial.log"), ("host", "host-reference.env"),
            )},
            "work_record_sha256": [V["digest"]((output / f"corpus-{index}-work.json").read_bytes()) for index in range(3)],
        }

    def timing(self, ordinal, metric, value):
        member = self.comparison["pairs"][ordinal]["candidate"]
        output = Path(member["output"])
        path = output / "serial.log"
        original_value = 10 if metric.endswith("planner_queue_ns") else 1000
        serial = path.read_text().replace(f"{metric}={original_value}\n", f"{metric}={value}\n")
        if metric == "corpus_0_campaign_planner_queue_ns":
            serial = serial.replace("campaign_planner_queue_total_ns=30\n", f"campaign_planner_queue_total_ns={value + 20}\n")
        if metric == "corpus_0_hot_guest_continuation_ns":
            serial = serial.replace("hot_guest_continuation_total_ns=3000\n", f"hot_guest_continuation_total_ns={value + 2000}\n")
        path.write_text(serial)
        self.comparison["pairs"][ordinal]["candidate"] = self.rebind(output)

    def compare(self, **kwargs):
        self.path.write_text(json.dumps(self.comparison))
        return V["compare"](self.path, self.plan_path, self.host, _store_directory=self.store, **kwargs)

    def decision_process_exit(self, report):
        # Execute the same status predicate used by the real CLI/extractor.
        # The report remains a finite synthetic parser control, not VM data.
        source = Path(__file__).with_name("campaign-performance-comparison.py")
        code = (
            "import json, runpy, sys; "
            "validator = runpy.run_path(sys.argv[1]); "
            "sys.exit(validator['decision_exit_code'](json.load(sys.stdin)))"
        )
        completed = subprocess.run(
            [sys.executable, "-B", "-c", code, str(source)],
            input=json.dumps(report), text=True, capture_output=True,
        )
        self.assertEqual(completed.stderr, "")
        return completed.returncode

    def test_equal_work_and_equality_accept_exact_median(self):
        report = self.compare()
        self.assertEqual(report["decision"], "ACCEPTED_MARGINAL_NO_REGRESSION")
        self.assertEqual(report["metrics"][self.required[0]]["paired_median"], {"numerator": 1, "denominator": 1})
        self.assertEqual(report["required_upper_limits_exceeding_one"], [])
        self.assertEqual(self.decision_process_exit(report), 0)

    def test_slower_guest_refused_even_when_old_ratio_improves(self):
        for ordinal in range(8):
            self.timing(ordinal, "corpus_0_hot_guest_continuation_ns", 1100)
        report = self.compare()
        self.assertEqual(report["slower_required_medians"], ["corpus_0_hot_guest_continuation_ns"])
        self.assertEqual(report["decision"], "REFUSED")
        self.assertEqual(self.decision_process_exit(report), 1)

    def test_individual_slow_sample_is_retained_without_maximum_rule(self):
        self.timing(7, "corpus_0_hot_guest_continuation_ns", 1200)
        report = self.compare()
        self.assertEqual(report["decision"], "ACCEPTED_MARGINAL_NO_REGRESSION")
        self.assertEqual(report["metrics"][self.required[1]]["two_sided_99_21875_percent"][1], {"numerator": 6, "denominator": 5})

    def test_passing_median_with_upper_above_one_is_inconclusive(self):
        for ordinal in (6, 7):
            self.timing(ordinal, "corpus_0_hot_guest_continuation_ns", 1100)
        report = self.compare()
        metric = report["metrics"][self.required[1]]

        self.assertEqual(metric["paired_median"], {"numerator": 1, "denominator": 1})
        self.assertEqual(metric["one_sided_upper_96_484375_percent"], {"numerator": 11, "denominator": 10})
        self.assertEqual(report["slower_required_medians"], [])
        self.assertEqual(report["required_upper_limits_exceeding_one"], [self.required[1]])
        self.assertEqual(report["decision"], "INCONCLUSIVE")
        self.assertEqual(self.decision_process_exit(report), 1)

    def test_old_median_only_method_is_refused(self):
        self.plan["method"] = "paired-median-eight-exact-v1"
        self.plan_path.write_text(json.dumps(self.plan))
        self.comparison["decision_plan_sha256"] = V["digest"](self.plan_path.read_bytes())

        with self.assertRaisesRegex(ValueError, "unsupported predeclared decision method"):
            self.compare()

    def test_one_slower_required_median_is_not_hidden_by_other_paths(self):
        for ordinal in range(5):
            self.timing(ordinal, "corpus_0_hot_guest_continuation_ns", 1001)
        self.assertEqual(self.compare()["decision"], "REFUSED")

    def test_planner_slowdown_is_not_hidden_by_faster_guest_or_case(self):
        for ordinal in range(8):
            self.timing(ordinal, "corpus_0_campaign_planner_queue_ns", 11)
            self.timing(ordinal, "corpus_0_hot_guest_continuation_ns", 900)
            self.timing(ordinal, "campaign_performance_case_elapsed_ns", 900)
        self.assertEqual(self.compare()["slower_required_medians"], ["corpus_0_campaign_planner_queue_ns"])

    def test_independent_strict_ratio_refuses_equality_and_invalid_ceiling(self):
        self.timing(0, "corpus_0_campaign_planner_queue_ns", 130)
        with self.assertRaises(ValueError):
            self.compare()
        self.comparison["max_planner_queue_ratio_ppm"] = 50_000
        with self.assertRaises(ValueError):
            self.compare()

    def test_canonical_work_mutation_and_host_mismatch_are_refused(self):
        output = Path(self.comparison["pairs"][0]["candidate"]["output"])
        work_path = output / "corpus-0-work.json"
        before = work_path.read_text()
        changed = before.replace('"frontier_ticks": 1', '"frontier_ticks": 2')
        work_path.write_text(changed)
        serial_path = output / "serial.log"
        serial_path.write_text(serial_path.read_text().replace(before, changed))
        self.comparison["pairs"][0]["candidate"] = self.rebind(output)
        with self.assertRaises(ValueError):
            self.compare()

        work_path.write_text(before)
        serial_path.write_text(serial_path.read_text().replace(changed, before))
        host_path = output / "host-reference.env"
        host_path.write_text(host_path.read_text().replace("host_allowed_cpus=0", "host_allowed_cpus=1"))
        self.comparison["pairs"][0]["candidate"] = self.rebind(output)
        with self.assertRaises(ValueError):
            self.compare()

    def test_duplicate_missing_reordered_or_legacy_members_are_refused(self):
        original = copy.deepcopy(self.comparison)
        changes = [
            lambda: self.comparison["pairs"].pop(),
            lambda: self.comparison["pairs"][0].update(order="BA"),
            lambda: self.comparison["pairs"][1].update(reference=self.comparison["pairs"][0]["reference"]),
            lambda: self.comparison.update(schema="crucible.campaign-performance.baseline.v1"),
        ]
        for change in changes:
            self.comparison = copy.deepcopy(original)
            change()
            with self.assertRaises(ValueError):
                self.compare()

    def test_tampered_or_nonpass_artifacts_are_refused(self):
        output = Path(self.comparison["pairs"][0]["candidate"]["output"])
        (output / "result").write_text("FAIL\n")
        with self.assertRaises(ValueError):
            self.compare()
        self.comparison["pairs"][0]["candidate"] = self.rebind(output)
        with self.assertRaises(ValueError):
            self.compare()

    def test_missing_duplicate_incomplete_or_wrong_identity_frames_are_refused(self):
        output = Path(self.comparison["pairs"][0]["candidate"]["output"])
        path = output / "serial.log"
        original = path.read_text()
        malformed = [
            original.replace(V["MEASUREMENT_BEGIN"] + "\n", ""),
            original.replace(V["MEASUREMENT_END"] + "\n", ""),
            original + V["MEASUREMENT_BEGIN"] + "\nextra\n" + V["MEASUREMENT_END"] + "\n",
            original.replace(V["MEASUREMENT_BEGIN"], "CONTROL_TEMPORARY_FRAME")
                    .replace(V["MEASUREMENT_END"], V["MEASUREMENT_BEGIN"])
                    .replace("CONTROL_TEMPORARY_FRAME", V["MEASUREMENT_END"]),
        ]
        for serial in malformed:
            path.write_text(serial)
            self.comparison["pairs"][0]["candidate"] = self.rebind(output)
            with self.assertRaises(ValueError):
                self.compare()

        report = V["completed_measurements"](original)
        changed = report.replace("campaign_performance_sample_id=" + "0" * 31 + "1",
                                 "campaign_performance_sample_id=" + "f" * 32)
        path.write_text(original.replace(V["MEASUREMENT_BEGIN"] + "\n" + report,
                                         V["MEASUREMENT_BEGIN"] + "\n" + changed))
        self.comparison["pairs"][0]["candidate"] = self.rebind(output)
        with self.assertRaisesRegex(ValueError, "sample identity"):
            self.compare()

    def test_duplicate_timing_inside_completed_frame_is_refused(self):
        output = Path(self.comparison["pairs"][0]["candidate"]["output"])
        path = output / "serial.log"
        path.write_text(path.read_text().replace(
            V["MEASUREMENT_END"],
            "corpus_0_hot_guest_continuation_ns=1000\n" + V["MEASUREMENT_END"],
        ))
        self.comparison["pairs"][0]["candidate"] = self.rebind(output)
        with self.assertRaisesRegex(ValueError, "one measured"):
            self.compare()

    def test_malformed_duplicate_metric_rows_are_refused(self):
        output = Path(self.comparison["pairs"][0]["candidate"]["output"])
        path = output / "serial.log"
        original = path.read_text()
        for invalid in ("bad", "-1", "", "1000x"):
            path.write_text(original.replace(
                V["MEASUREMENT_END"],
                f"corpus_0_hot_guest_continuation_ns={invalid}\n" + V["MEASUREMENT_END"],
            ))
            self.comparison["pairs"][0]["candidate"] = self.rebind(output)
            with self.assertRaisesRegex(ValueError, "one measured"):
                self.compare()

    def test_native_change_cannot_be_qualified_by_campaign_medians(self):
        self.plan["production"][self.reference]["native/atomic-patch"] = "1" * 64
        self.plan["production"][self.candidate]["native/atomic-patch"] = "2" * 64
        self.plan_path.write_text(json.dumps(self.plan))
        self.comparison["decision_plan_sha256"] = V["digest"](self.plan_path.read_bytes())
        with self.assertRaisesRegex(ValueError, "None-path"):
            self.compare()

    def test_current_consumer_and_revision_specific_sources_are_authenticated(self):
        source = self.root / "current.json"
        source.write_text(json.dumps({"schema": "crucible.campaign-performance.source.v2", "revision": "current", "sample_id": None, "conditions": self.plan["conditions"], "production": self.plan["production"][self.candidate]}))
        self.assertEqual(self.compare(current_source_path=source)["decision"], "ACCEPTED_MARGINAL_NO_REGRESSION")
        current = json.loads(source.read_text())
        current["production"] = self.plan["production"][self.reference]
        source.write_text(json.dumps(current))
        with self.assertRaises(ValueError):
            self.compare(current_source_path=source)


if __name__ == "__main__":
    unittest.main()
