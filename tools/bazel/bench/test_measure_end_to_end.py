"""Checks that measurement snapshots retain build recipes and exclude outputs."""

from pathlib import Path
import tempfile
import unittest

import measure_end_to_end


class EndToEndSnapshotTests(unittest.TestCase):
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
