# SPDX-License-Identifier: Apache-2.0
"""Check flamegraph accounting, stable labels and offline report safety."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET


SPEC = importlib.util.spec_from_file_location(
    "flamegraph", Path(__file__).with_name("tcg-profile-flamegraph.py"))
GRAPH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GRAPH)


def frame(symbol, object_path="/nix/store/example-qemu/bin/qemu-system-x86_64", offset="0x123"):
    return dict(object=object_path, symbol=symbol, offset=offset,
                pc="0xabcdef", label="ignored private address label")


def profile(records, period=10_000):
    return dict(sampling_period_us=period, total_samples=sum(count for count, _ in records),
                mapped_elf_sha256={"/nix/store/example-qemu/bin/qemu-system-x86_64": "a" * 64},
                stacks=[dict(count=count, frames=frames) for count, frames in records])


class FlamegraphTests(unittest.TestCase):
    def setUp(self):
        self.plain = profile([(2, [frame("guest_exec"), frame("worker")]),
                              (3, [frame(None, "unmapped"), frame("worker")]),
                              (1, [frame("worker")])])
        self.sim = profile([(4, [frame("timer"), frame("worker")]),
                            (2, [frame(None, "unmapped", "0x999"), frame("worker")])])

    def test_mass_is_conserved_in_each_subtree_including_prefix_stacks(self):
        report = GRAPH.build_report({"plain": self.plain, "sim": self.sim})

        def verify(node):
            self.assertAlmostEqual(node["weight"], node["self_weight"] + sum(
                child["weight"] for child in node["children"]))
            for child in node["children"]:
                verify(child)

        for item in report["profiles"]:
            verify(item["tree"])
            self.assertEqual(sum(row["count"] for row in item["stacks"]), 6)
            self.assertAlmostEqual(item["tree"]["weight"], 0.06)
        for pair in report["pairs"]:
            for metric in pair["metrics"].values():
                verify(metric["tree"])

    def test_diff_share_balances_and_cpu_seconds_use_each_input_rate(self):
        self.sim["sampling_period_us"] = 20_000
        report = GRAPH.build_report({"plain": self.plain, "sim": self.sim})
        pair = report["pairs"][0]
        for metric, expected in (("share", 0), ("cpu_seconds", 0.06)):
            comparison = pair["metrics"][metric]
            self.assertAlmostEqual(comparison["tree"]["delta"], expected)
            self.assertAlmostEqual(sum(row["delta"] for row in comparison["exclusive"]), expected)
        self.assertAlmostEqual(pair["metrics"]["cpu_seconds"]["tree"]["weight"], 0.15)

    def test_pooled_captures_use_mean_cpu_cost_without_changing_raw_mass(self):
        pooled = copy.deepcopy(self.plain)
        pooled["capture_count"] = 3
        pooled["total_samples"] *= 3
        for record in pooled["stacks"]:
            record["count"] *= 3
        report = GRAPH.build_report({"single": self.plain, "pooled": pooled})

        single, repeated = report["profiles"]
        self.assertEqual(single["capture_count"], 1)
        self.assertEqual(repeated["total_samples"], 18)
        self.assertEqual(sum(row["count"] for row in repeated["stacks"]), 18)
        self.assertAlmostEqual(repeated["sampled_cpu_seconds"], 0.18)
        self.assertAlmostEqual(repeated["sampled_cpu_seconds_per_capture"], 0.06)
        self.assertAlmostEqual(repeated["tree"]["weight"], single["tree"]["weight"])
        for comparison in report["pairs"][0]["metrics"].values():
            self.assertAlmostEqual(comparison["tree"]["delta"], 0)
            for row in comparison["exclusive"]:
                self.assertAlmostEqual(row["delta"], 0)

    def test_symbols_preserve_exact_names_without_offsets_or_absolute_paths(self):
        renamed = copy.deepcopy(self.plain)
        renamed["stacks"][0]["frames"][0]["object"] = "/tmp/elsewhere/qemu-system-x86_64"
        renamed["stacks"][0]["frames"][0]["offset"] = "0xffff"
        normalized = GRAPH.normalize_profile("plain", self.plain)
        self.assertEqual(normalized, GRAPH.normalize_profile("plain", renamed))
        encoded = json.dumps(normalized)
        self.assertNotIn("/nix/store", encoded)
        self.assertNotIn("0xabcdef", encoded)
        self.assertIn("qemu-system-x86_64:guest_exec", encoded)
        self.assertIn("[unmapped or anonymous; possible guest code]", encoded)

    def test_unknown_mapped_functions_do_not_merge_with_unmapped_frames(self):
        self.assertNotEqual(GRAPH.canonical_frame(frame(None)),
                            GRAPH.canonical_frame(frame(None, "unmapped")))
        self.assertEqual(GRAPH.canonical_frame(frame(None, "unmapped", "0x111")),
                         GRAPH.canonical_frame(frame(None, "unmapped", "0x999")))

    def test_coarsening_distinct_unknown_addresses_retains_all_their_weight(self):
        decoded = profile([(2, [frame(None, "unmapped", "0x111"), frame("worker")]),
                           (5, [frame(None, "unmapped", "0x999"), frame("worker")])])
        normalized = GRAPH.normalize_profile("plain", decoded)
        self.assertEqual(len(normalized["stacks"]), 1)
        self.assertEqual(normalized["stacks"][0]["count"], 7)

    def test_mismatched_binary_and_ambiguous_basename_are_rejected(self):
        wrong = copy.deepcopy(self.sim)
        wrong["mapped_elf_sha256"] = {"/tmp/qemu-system-x86_64": "b" * 64}
        with self.assertRaisesRegex(ValueError, "different QEMU"):
            GRAPH.build_report({"plain": self.plain, "sim": wrong})
        wrong["mapped_elf_sha256"]["/other/qemu-system-x86_64"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "conflicting ELF"):
            GRAPH.normalize_profile("sim", wrong)

    def test_bad_counts_rates_frames_and_totals_are_rejected(self):
        mutations = [("sampling_period_us", True), ("sampling_period_us", 0),
                     ("total_samples", 7), ("stacks", []), ("mapped_elf_sha256", {}),
                     ("sampled_cpu_seconds", 123), ("sampled_cpu_seconds", float("nan")),
                     ("capture_count", 0), ("capture_count", True), ("capture_count", -1),
                     ("capture_count", 1.5)]
        for key, value in mutations:
            wrong = copy.deepcopy(self.plain)
            wrong[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                GRAPH.normalize_profile("plain", wrong)
        for record in (dict(count=-1, frames=[frame("bad")]), dict(count=1, frames=[])):
            wrong = copy.deepcopy(self.plain)
            wrong["stacks"][0] = record
            with self.assertRaises(ValueError):
                GRAPH.normalize_profile("plain", wrong)

    def test_html_and_svg_escape_hostile_symbols_and_metadata(self):
        self.plain["stacks"][0]["frames"][0]["symbol"] = "<img onerror=alert(1)>"
        report = GRAPH.build_report({"plain": self.plain, "sim": self.sim},
                                    {"scope": "<script>alert(1)</script>"})
        document = GRAPH.render_html(report)
        self.assertNotIn("<img onerror=alert(1)>", document)
        self.assertNotIn("<script>alert(1)</script>", document)
        self.assertIn("\\u003cscript", document)
        svg = GRAPH.svg_text(report["profiles"][0]["tree"], "<title>&label")
        ET.fromstring(svg)
        self.assertNotIn("<img onerror", svg)
        with self.assertRaisesRegex(ValueError, "absolute path"):
            GRAPH.build_report({"plain": self.plain, "sim": self.sim}, {"path": "/tmp/private"})
        with self.assertRaisesRegex(ValueError, "absolute path"):
            GRAPH.build_report({"plain": self.plain, "sim": self.sim}, {"path": "file:///tmp/private"})
        for path in ("prefix/nix/store/private", "prefix/tmp/private", "prefix/home/private",
                     "prefix/scratch/private"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "absolute path"):
                GRAPH.build_report({"plain": self.plain, "sim": self.sim}, {"path": path})

    def test_output_is_fresh_self_contained_and_has_all_svg_exports(self):
        report = GRAPH.build_report({"plain": self.plain, "sim": self.sim})
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "report"
            GRAPH.write_report(report, output)
            self.assertEqual(len(list(output.glob("*.svg"))), 6)
            self.assertEqual(json.loads((output / "comparison.json").read_text()), report)
            document = (output / "index.html").read_text()
            self.assertNotIn('src="http', document)
            self.assertNotIn('href="http', document)
            for svg in output.glob("*.svg"):
                ET.fromstring(svg.read_text())
            with self.assertRaises(FileExistsError):
                GRAPH.write_report(report, output)


if __name__ == "__main__":
    unittest.main()
