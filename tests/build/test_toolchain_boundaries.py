"""Exercises accepted tier exports and mutations that must block qualification."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from toolchain_boundaries import (
    inspect_mtrace, inspect_perl_compiler, inspect_perl_config, inspect_recipe_shell, inspect_tier,
)


class PerlCompilerContractTests(unittest.TestCase):
    def test_successful_noop_cannot_replace_the_installed_compiler(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("toolchain_boundaries.subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, "", "")

                self.assertIn(
                    "did not produce an object",
                    inspect_perl_compiler("perl", directory, {}),
                )


class PerlConfigContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.packages = {name: str(self.root / name) for name in ("gcc", "binutils", "perl")}
        for package, names in (("gcc", ("gcc",)), ("binutils", ("ar", "nm", "ranlib", "as", "ld"))):
            directory = Path(self.packages[package]) / "bin"
            directory.mkdir(parents=True)
            for name in names:
                executable = directory / name
                executable.write_text("fixture")
                executable.chmod(0o755)
        Path(self.packages["perl"]).mkdir()
        self.roots = [Path(path) for path in self.packages.values()]
        self.environment = {"PATH": os.pathsep.join(str(root / "bin") for root in self.roots)}
        self.values = ["gcc -static", "ar", "nm", "ranlib", "", "", "", ""]
        self.linker = str(Path(self.packages["binutils"]) / "bin/ld")

    def inspect(self):
        def run(command, **kwargs):
            if "-MConfig" in command:
                output = "\0".join(self.values)
            elif command[-1] == "-print-prog-name=ld":
                output = self.linker
            else:
                output = str(Path(self.packages["binutils"]) / "bin/as")
            return subprocess.CompletedProcess(command, 0, output, "")

        with patch("toolchain_boundaries.subprocess.run", side_effect=run):
            return inspect_perl_config("perl", self.packages, self.roots, self.environment)

    def test_exported_commands_are_accepted(self):
        self.assertIsNone(self.inspect())

    def test_ranlib_noop_is_accepted_when_ar_indexes_archives(self):
        self.values[3] = ":"
        self.assertIsNone(self.inspect())

    def test_compiler_and_archive_commands_cannot_be_noops(self):
        for index in (0, 1, 2):
            with self.subTest(field=index):
                original = self.values[index]
                self.values[index] = ":"
                self.assertIn("leaves exported tier", self.inspect())
                self.values[index] = original

    def test_ranlib_noop_does_not_accept_extra_commands(self):
        self.values[3] = ":; /private/ranlib"
        self.assertIn("ranlib leaves exported tier", self.inspect())

    def test_private_compiler_is_rejected(self):
        compiler = self.root / "private-cc"
        compiler.write_text("fixture")
        compiler.chmod(0o755)
        self.values[0] = str(compiler)
        self.assertIn("cc leaves exported tier", self.inspect())

    def test_private_sysroot_is_rejected(self):
        self.values[4] = "-I/nix/store/private-libc/include"
        with patch("toolchain_boundaries.inside", side_effect=lambda path, roots: not str(path).startswith("/nix/store/private")):
            self.assertIn("ccflags leaves exported tier", self.inspect())

    def test_compiler_selecting_private_linker_is_rejected(self):
        linker = self.root / "private-ld"
        linker.write_text("fixture")
        self.linker = str(linker)
        self.assertIn("Perl compiler selects", self.inspect())

    def test_missing_config_fields_are_rejected(self):
        self.values = ["gcc"]
        self.assertIn("incomplete compiler settings", self.inspect())


class MtraceContractTests(unittest.TestCase):
    def test_successful_noop_cannot_replace_the_tracing_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("toolchain_boundaries.subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, "", "")
                self.assertIsNotNone(inspect_mtrace("mtrace", directory, {}))

    def test_tool_that_always_reports_no_leaks_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("toolchain_boundaries.subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, "No memory leaks.\n", "")
                self.assertIsNotNone(inspect_mtrace("mtrace", directory, {}))


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

    def test_target_prefixed_driver_cannot_select_old_assembler(self):
        alias = self.write("gcc/bin/target-gcc", f"#!{self.root}/bash/bin/bash\n".encode())
        old = self.write("previous/as", b"\x7fELFfixture")
        selected = self.mock_driver.side_effect

        def choose(arguments, **kwargs):
            if arguments[0] == str(alias):
                return subprocess.CompletedProcess(arguments, 0, f"{old}\n", "")
            return selected(arguments, **kwargs)

        self.mock_driver.side_effect = choose

        self.assertTrue(any(
            item["path"] == str(alias) and "as selects" in item["reason"]
            for item in self.inspect()
        ))

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


class RecipeShellTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.shell = self.root / "bash/bin/bash"
        self.shell.parent.mkdir(parents=True)
        self.shell.touch()
        self.emulator = self.root / "qemu"
        self.emulator.touch()
        self.foreign = self.root / "foreign"
        self.foreign.touch()
        self.packages = {
            name: str(self.root / name) for name in ("bash", "gnumake", "coreutils")
        }

    def inspect_emulated(self, guest, executable):
        completed = subprocess.CompletedProcess([], 0, f"{guest}\n{executable}\n", "")
        with patch("toolchain_boundaries.subprocess.run", return_value=completed):
            return inspect_recipe_shell(
                self.packages, self.root, {"PATH": "/nonexistent"}, self.emulator,
            )

    def test_declared_emulator_and_current_guest_shell_pass(self):
        self.assertIsNone(self.inspect_emulated(self.shell, self.emulator))

    def test_declared_emulator_cannot_hide_an_old_guest_shell(self):
        reason = self.inspect_emulated(self.foreign, self.emulator)

        self.assertIn("Make recipe selects guest shell", reason)

    def test_current_guest_shell_cannot_hide_an_undeclared_emulator(self):
        reason = self.inspect_emulated(self.shell, self.foreign)

        self.assertIn("Make recipe selects", reason)

    def test_native_shell_can_execute_without_the_optional_emulator(self):
        self.assertIsNone(self.inspect_emulated(self.shell, self.shell))

    def test_emulated_recipe_must_report_its_guest_identity(self):
        completed = subprocess.CompletedProcess([], 0, f"{self.emulator}\n", "")
        with patch("toolchain_boundaries.subprocess.run", return_value=completed):
            reason = inspect_recipe_shell(
                self.packages, self.root, {"PATH": "/nonexistent"}, self.emulator,
            )

        self.assertIn("both its guest shell and process executable", reason)

    def test_foreign_default_shell_blocks_qualification(self):
        completed = subprocess.CompletedProcess([], 0, f"{self.foreign}\n", "")
        with patch("toolchain_boundaries.subprocess.run", return_value=completed) as run:
            reason = inspect_recipe_shell(self.packages, self.root, {"PATH": "/nonexistent"})

        self.assertIn("Make recipe selects", reason)
        self.assertNotIn("SHELL", run.call_args.kwargs["env"])
        self.assertIn("; :", (self.root / "Makefile").read_text())


if __name__ == "__main__":
    unittest.main()
