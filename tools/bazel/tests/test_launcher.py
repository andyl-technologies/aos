"""Checks launcher isolation and cache policy without invoking a compiler."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


LAUNCHER = Path(__file__).resolve().parents[1] / "launcher.py"


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.capture = self.root / "invocation.json"
        bazel = self.root / "bazel"
        bazel.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "if sys.argv[1:] == ['--version']:\n"
            "    print('bazel 9.2.0- (@non-git)')\n"
            "    raise SystemExit(0)\n"
            f"Path({str(self.capture)!r}).write_text(json.dumps({{'args': sys.argv[1:], 'env': dict(os.environ)}}))\n"
        )
        bazel.chmod(0o755)
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({
            "bazel": str(bazel), "jdk": "/declared/jdk", "bash": "/declared/bash",
            "bazel_version": "9.2.0",
            "path": "/declared/tools", "jobs": 2,
            "registry": "/declared/offline-registry",
            "modules": {"rules_rust": "/declared/rules_rust"},
            "repositories": {"aos_tools": "/declared/toolchains"},
        }))

    def invoke(self, arguments, options=()):
        environment = dict(os.environ) | {
            "RUSTFLAGS": "ambient flags", "LD_LIBRARY_PATH": "/ambient/libraries",
            "CARGO_HOME": "/ambient/cargo", "EXAMPLE_CREDENTIAL": "private",
        }
        return subprocess.run([
            sys.executable, str(LAUNCHER), "--config", str(self.config),
            "--workspace", str(self.root), "--output-base", str(self.root / "output"),
            *options, "--", *arguments,
        ], env=environment, capture_output=True, text=True)

    def test_uncached_build_is_isolated_and_cannot_enable_downloads(self):
        result = self.invoke(["build", "//:example", "--repository_disable_download=false"])
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = json.loads(self.capture.read_text())

        for variable in ["RUSTFLAGS", "LD_LIBRARY_PATH", "CARGO_HOME", "EXAMPLE_CREDENTIAL"]:
            self.assertNotIn(variable, invocation["env"])
        self.assertEqual(invocation["env"]["PATH"], "/declared/tools")
        arguments = invocation["args"]
        self.assertGreater(arguments.index("--repository_disable_download"),
                           arguments.index("--repository_disable_download=false"))
        self.assertIn("--lockfile_mode=error", arguments)
        self.assertIn("--disk_cache=", arguments)
        self.assertIn("--nocache_test_results", arguments)
        self.assertIn("--sandbox_default_allow_network=false", arguments)
        self.assertIn("--override_repository=aos_tools=/declared/toolchains", arguments)

    def test_local_cache_policy_precedes_program_arguments(self):
        result = self.invoke(["run", "//:example", "--", "argument with spaces"],
                             ["--cache", str(self.root / "cache")])
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.capture.read_text())["args"]
        self.assertLess(arguments.index(f"--disk_cache={self.root / 'cache'}"), arguments.index("--"))
        self.assertEqual(arguments[-1], "argument with spaces")

    def test_remote_cache_and_toolchain_overrides_are_rejected(self):
        for option in ["--remote_cache=https://example.invalid", "--action_env=RUSTFLAGS=bad",
                       "--override_module=rules_rust=/unreviewed"]:
            with self.subTest(option=option):
                result = self.invoke(["build", "//:example", option])
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.capture.exists())

    def test_shadow_workspace_preserves_checkout_lock_and_tracks_new_files(self):
        source = self.root / "source"
        source.mkdir()
        (source / "MODULE.bazel.lock").write_text("checked-in lock")
        (source / "first.rs").write_text("first source")
        (source / ".git").write_text("private worktree metadata")
        prepared_lock = self.root / "prepared.lock"
        prepared_lock.write_text("prepared lock")
        options = ["--workspace", str(source), "--shadow-workspace", "--lock", str(prepared_lock)]

        result = self.invoke(["build", "//:example"], options)
        self.assertEqual(result.returncode, 0, result.stderr)
        shadow = self.root / "workspace"
        self.assertEqual((shadow / "MODULE.bazel.lock").read_text(), "prepared lock")
        self.assertEqual((source / "MODULE.bazel.lock").read_text(), "checked-in lock")
        self.assertFalse((shadow / ".git").exists())
        self.assertTrue((shadow / "first.rs").is_symlink())

        (source / "first.rs").unlink()
        (source / "new.rs").write_text("new source")
        result = self.invoke(["build", "//:example"], options)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((shadow / "first.rs").is_symlink())
        self.assertEqual((shadow / "new.rs").read_text(), "new source")

    def test_shadow_workspace_refuses_unmanaged_directory(self):
        shadow = self.root / "workspace"
        shadow.mkdir()
        (shadow / "precious").write_text("user content")
        lock = self.root / "prepared.lock"
        lock.write_text("lock")
        result = self.invoke(["build", "//:example"], ["--shadow-workspace", "--lock", str(lock)])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((shadow / "precious").read_text(), "user content")


if __name__ == "__main__":
    unittest.main()
