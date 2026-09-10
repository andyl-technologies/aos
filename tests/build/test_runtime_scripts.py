"""Checks installed interpreter fixups with the actual bootstrap shell tools."""

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


class RuntimeScriptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "output"
        self.output.mkdir()
        self.shell = os.environ["AOS_TEST_SHELL"]
        self.patcher = os.environ["AOS_TEST_RUNTIME_PATCHER"]

    def install(self, name, content, mode=0o755):
        path = self.output / name
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def patch(self):
        environment = {
            "PATH": os.environ["AOS_TEST_TOOLS"],
            "TMPDIR": str(self.root),
            "AOS_RUNTIME_SHELL": self.shell,
            "AOS_BUILD_SHELL": "/previous/bin/bash",
        }
        subprocess.run(
            [self.shell, self.patcher, str(self.output)],
            env=environment, check=True, capture_output=True, text=True,
        )

    def test_read_only_script_preserves_arguments_and_permissions(self):
        script = self.install("script", b"#!/bin/sh -e\nprintf 'ok\\n'\n", 0o555)

        self.patch()

        self.assertEqual(script.read_text(), f"#!{self.shell} -e\nprintf 'ok\\n'\n")
        self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o555)
        result = subprocess.run([str(script)], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, "ok\n")

    def test_env_dispatch_becomes_direct_interpreter(self):
        script = self.install("script", b"#!/usr/bin/env -S bash -e\nexit 0\n")

        self.patch()

        self.assertEqual(script.read_text(), f"#!{self.shell} -e\nexit 0\n")

    def test_source_dependency_timestamp_is_preserved(self):
        script = self.install("configure", b"#!/bin/sh\nexit 0\n")
        os.utime(script, (1234567890, 1234567890))

        self.patch()

        self.assertEqual(script.stat().st_mtime, 1234567890)
        self.assertEqual(script.read_text(), f"#!{self.shell}\nexit 0\n")

    def test_binary_and_other_languages_are_unchanged(self):
        binary = self.install("binary", b"\x7fELF\x00/bin/sh\x00")
        python = self.install("python", b"#!/specific/python\nprint('/bin/sh')\n")

        self.patch()

        self.assertEqual(binary.read_bytes(), b"\x7fELF\x00/bin/sh\x00")
        self.assertEqual(python.read_bytes(), b"#!/specific/python\nprint('/bin/sh')\n")

    def test_hard_links_and_spaces_are_preserved(self):
        script = self.install("script with spaces", b"#!/bin/sh\nexit 0\n")
        alias = self.output / "alias"
        alias.hardlink_to(script)

        self.patch()

        self.assertEqual(script.stat().st_ino, alias.stat().st_ino)
        self.assertEqual(alias.read_text(), f"#!{self.shell}\nexit 0\n")
        self.assertEqual(sorted(path.name for path in self.output.iterdir()), ["alias", "script with spaces"])

    def test_configured_shell_in_script_body_uses_runtime_shell(self):
        script = self.install("script", b"#!/previous/bin/bash\nexec /previous/bin/bash helper\n")

        self.patch()

        self.assertEqual(script.read_text(), f"#!{self.shell}\nexec {self.shell} helper\n")

    def test_fhs_defaults_change_without_corrupting_store_paths(self):
        script = self.install(
            "script",
            b"#!/bin/sh\nSHELL=${CONFIG_SHELL:-/bin/sh}\n"
            b"echo '/bin/sh /bin/bash'\nexec /nix/store/other/bin/bash helper\n",
        )

        self.patch()

        self.assertEqual(
            script.read_text(),
            f"#!{self.shell}\nSHELL=${{CONFIG_SHELL:-{self.shell}}}\n"
            f"echo '{self.shell} {self.shell}'\nexec /nix/store/other/bin/bash helper\n",
        )


class FilteredRuntimeScriptTests(RuntimeScriptTests):
    """Checks that selecting hard links preserves the original fixup contracts."""

    def patch(self):
        original = self.output
        selected = self.root / "selected-scripts"
        selected.mkdir()
        subprocess.run(
            [
                os.environ["AOS_TEST_PERL"],
                os.environ["AOS_TEST_SCRIPT_FILTER"],
                str(original),
                str(selected),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        self.output = selected
        try:
            super().patch()
        finally:
            self.output = original

        for path in selected.iterdir():
            path.unlink()
        selected.rmdir()

    def test_symlinks_and_binary_prefixes_are_not_selected(self):
        outside = self.root / "outside"
        outside.write_bytes(b"#!/bin/sh\nexit 0\n")
        (self.output / "alias").symlink_to(outside)
        binary = self.install("binary", b"\x00#! /bin/sh\n")

        self.patch()

        self.assertEqual(outside.read_bytes(), b"#!/bin/sh\nexit 0\n")
        self.assertEqual(binary.read_bytes(), b"\x00#! /bin/sh\n")


class BuildEnvironmentTests(unittest.TestCase):
    def test_target_inputs_do_not_override_native_paths_or_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            (target / "bin").mkdir(parents=True)
            (target / "lib").mkdir()
            (target / "include").mkdir()
            shell = os.environ["AOS_TEST_SHELL"]
            native_path = os.environ["AOS_TEST_TOOLS"]
            environment = {
                "PATH": native_path,
                "CONFIG_SHELL": shell,
                "out": str(root / "out"),
                "NIX_BUILD_CORES": "1",
                "buildInputs": str(target),
                "nativeBuildInputs": "",
                "propagatedBuildInputs": str(target),
                "C_INCLUDE_PATH": "/declared/include",
                "LIBRARY_PATH": "/declared/lib",
                "PKG_CONFIG_PATH": "/declared/pkgconfig",
            }
            commands = r"""
source "$1"
test "$PATH" = "$2"
test "${LD_LIBRARY_PATH+x}" != x
test "$C_INCLUDE_PATH" = /declared/include
test "$LIBRARY_PATH" = /declared/lib
test "$PKG_CONFIG_PATH" = /declared/pkgconfig
mkdir "$out/scripts"
printf '#!/usr/bin/env -S bash -e\nexit 0\n' > "$out/scripts/script with spaces"
chmod +x "$out/scripts/script with spaces"
patchShebangs "$out/scripts"
test "$(head -n 1 "$out/scripts/script with spaces")" = "#!$CONFIG_SHELL -e"
"$out/scripts/script with spaces"
makeWrapper "$CONFIG_SHELL" "$out/wrapper"
head -n 1 "$out/wrapper"
wrapProgram "$out/wrapper"
head -n 1 "$out/wrapper"
"$out/wrapper" -c 'echo wrapped'
"""

            result = subprocess.run(
                [shell, "-c", commands, "check", os.environ["AOS_TEST_SETUP"], native_path],
                env=environment, check=True, capture_output=True, text=True,
            )

            self.assertEqual(result.stdout.splitlines()[-3:], [f"#!{shell}", f"#!{shell}", "wrapped"])


if __name__ == "__main__":
    unittest.main()
