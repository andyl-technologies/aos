"""Exercises accepted tier exports and mutations that must block qualification."""

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from toolchain_boundaries import inspect_tier


class ExportBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.packages = {name: str(self.root / name) for name in ("gcc", "binutils", "bash")}
        self.write("bash/bin/bash", b"\x7fELFfixture")
        self.write("gcc/bin/gcc", f"#!{self.root}/bash/bin/bash\n".encode())
        for program in ("as", "ld"):
            self.write(f"binutils/bin/{program}", b"\x7fELFfixture")

        def selected(arguments, **kwargs):
            program = arguments[1].split("=")[1]
            return subprocess.CompletedProcess(arguments, 0, f"{self.root}/binutils/bin/{program}\n", "")

        self.driver = patch("toolchain_boundaries.subprocess.run", side_effect=selected)
        self.mock_driver = self.driver.start()
        self.addCleanup(self.driver.stop)

    def write(self, relative, content, executable=True):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o755 if executable else 0o644)
        return path

    def inspect(self):
        return inspect_tier("fixture", self.packages)

    def test_same_tier_interpreter_and_binutils_pass(self):
        self.assertEqual(self.inspect(), [])

    def test_old_shell_blocks_even_when_file_exists(self):
        old = self.write("previous/bash", b"\x7fELFfixture")
        self.write("gcc/bin/gcc", f"#!{old}\n".encode())

        self.assertTrue(any("interpreter leaves" in item["reason"] for item in self.inspect()))

    def test_host_shell_blocks(self):
        self.write("gcc/bin/gcc", b"#!/bin/sh\n")

        self.assertTrue(self.inspect())

    def test_current_tier_alias_to_old_tool_blocks(self):
        old = self.write("previous/as", b"\x7fELFfixture")
        selected = self.root / "binutils/bin/as"
        selected.unlink()
        selected.symlink_to(old)

        self.assertTrue(any("symlink leaves" in item["reason"] for item in self.inspect()))

    def test_driver_selecting_another_assembler_blocks(self):
        old = self.write("previous/as", b"\x7fELFfixture")
        self.mock_driver.side_effect = None
        self.mock_driver.return_value = subprocess.CompletedProcess([], 0, f"{old}\n", "")

        self.assertTrue(any("as selects" in item["reason"] for item in self.inspect()))

    def test_dangling_tool_alias_blocks(self):
        (self.root / "gcc/bin/cc").symlink_to("missing")

        self.assertTrue(any("dangling" in item["reason"] for item in self.inspect()))

    def test_interpreter_alias_cannot_hide_old_shell(self):
        old = self.write("previous/bash", b"\x7fELFfixture")
        shell = self.root / "bash/bin/bash"
        shell.unlink()
        shell.symlink_to(old)

        self.assertTrue(any("interpreter leaves" in item["reason"] for item in self.inspect()))

    def test_missing_output_blocks(self):
        self.packages["missing"] = str(self.root / "absent")

        self.assertTrue(any("unavailable output" in item["reason"] for item in self.inspect()))

    def test_metadata_reference_does_not_count_as_execution(self):
        self.write("gcc/share/build-command", b"/previous/compiler/bin/gcc\n", executable=False)

        self.assertEqual(self.inspect(), [])

    def test_driver_inspection_failure_blocks(self):
        self.mock_driver.side_effect = subprocess.TimeoutExpired("gcc", 30)

        self.assertTrue(any("cannot establish" in item["reason"] for item in self.inspect()))


if __name__ == "__main__":
    unittest.main()
