"""Checks that measurement snapshots retain build recipes and exclude outputs."""

from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

import measure_end_to_end


class EndToEndSnapshotTests(unittest.TestCase):
    def test_source_edits_during_measurement_cannot_change_later_repetitions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "repository"
            original.mkdir()
            (original / "source.rs").write_text("original input")
            seen = []

            def measure(options, _helper, mode, repetition):
                seen.append((options.root / "source.rs").read_text())
                (original / "source.rs").write_text("concurrent edit")
                return [{"mode": mode, "repetition": repetition, "scenario": "cold", "wall_seconds": 1}]

            arguments = ["measure", "--root", str(original), "--scratch", str(root / "scratch"),
                         "--output", str(root / "output"), "--cache-root", "/cache", "--nix-tools", "/tools",
                         "--trial", "snapshot-test"]

            with patch.object(sys, "argv", arguments), patch.object(measure_end_to_end, "measure_series", side_effect=measure):
                measure_end_to_end.main()

            self.assertEqual(seen, ["original input"] * 6)
            report = json.loads((root / "output/report.json").read_text())
            self.assertEqual(len(report["samples"]), 6)
            self.assertIn("MemAvailable:", report["memory_before"])

    def test_bazel_recipes_survive_output_filtering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "pkgs/toolchain").mkdir(parents=True)
            (source / "pkgs/toolchain/bazel-9.nix").write_text("source-built Bazel recipe")
            (source / "result-parser.rs").write_text("checked-in source")
            (source / "Cargo.toml").write_text("workspace")
            (source / "target").mkdir()
            (source / "target/artifact").write_text("execution output")
            (source / "bazel-out").symlink_to(source / "target", target_is_directory=True)
            (source / "result").symlink_to(source / "target", target_is_directory=True)

            measure_end_to_end.copy_source(source, root / "snapshot")

            self.assertTrue((root / "snapshot/pkgs/toolchain/bazel-9.nix").is_file())
            self.assertTrue((root / "snapshot/result-parser.rs").is_file())
            for name in ["target", "bazel-out", "result"]:
                self.assertFalse((root / "snapshot" / name).exists())


if __name__ == "__main__":
    unittest.main()
