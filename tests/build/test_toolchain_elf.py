"""Exercises ELF loader and library dependencies that bypass script checks."""

from pathlib import Path
import tempfile
import unittest

from toolchain_elf import inspect_loader_output


class ElfBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.tier = self.root / "tier"
        self.libraries = self.tier / "lib"
        self.libraries.mkdir(parents=True)
        (self.libraries / "ld.so").touch()
        (self.libraries / "libc.so.6").touch()
        self.program = self.tier / "bin/program"
        self.loader = f"[Requesting program interpreter: {self.libraries}/ld.so]"
        self.needed = " (NEEDED) Shared library: [libc.so.6]"

    def inspect(self, records):
        return inspect_loader_output(self.program, [self.tier], records)

    def test_static_binary_has_no_loader_dependencies(self):
        self.assertEqual(self.inspect("There is no dynamic section in this file."), [])

    def test_recorded_tier_loader_resolves_its_library(self):
        self.assertEqual(self.inspect(self.loader + "\n" + self.needed), [])

    def test_origin_path_resolves_library(self):
        self.program.parent.mkdir()
        records = " (RUNPATH) Library runpath: [$ORIGIN/../lib]\n" + self.needed

        self.assertEqual(self.inspect(records), [])

    def test_old_loader_is_rejected(self):
        old = self.root / "old-loader"
        old.touch()

        self.assertTrue(self.inspect(f"[Requesting program interpreter: {old}]"))

    def test_missing_library_is_rejected(self):
        (self.libraries / "libc.so.6").unlink()

        self.assertTrue(self.inspect(self.loader + "\n" + self.needed))

    def test_library_alias_cannot_hide_old_tier(self):
        old = self.root / "old-libc"
        old.touch()
        library = self.libraries / "libc.so.6"
        library.unlink()
        library.symlink_to(old)

        self.assertTrue(self.inspect(self.loader + "\n" + self.needed))

    def test_empty_search_entry_is_ambient(self):
        self.assertTrue(self.inspect(f" (RUNPATH) Library runpath: [{self.libraries}:]"))

    def test_old_search_path_is_rejected_even_without_needed_library(self):
        old = self.root / "previous"
        old.mkdir()

        self.assertTrue(self.inspect(f" (RPATH) Library rpath: [{old}]"))

    def test_loader_default_directory_resolves_dso_dependency(self):
        self.assertEqual(
            inspect_loader_output(self.program, [self.tier], self.needed, [self.libraries]),
            [],
        )


if __name__ == "__main__":
    unittest.main()
