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
        self.assertIn("--sandbox_block_path=/bin/sh", arguments)
        self.assertIn("--override_repository=aos_tools=/declared/toolchains", arguments)

    def test_local_cache_policy_precedes_program_arguments(self):
        result = self.invoke(["run", "//:example", "--", "--remote_cache=program-option", "argument with spaces"],
                             ["--cache", str(self.root / "cache")])
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.capture.read_text())["args"]
        self.assertLess(arguments.index(f"--disk_cache={self.root / 'cache'}"), arguments.index("--"))
        self.assertEqual(arguments[-1], "argument with spaces")

    def test_configured_target_platform_applies_to_analysis_commands(self):
        configuration = json.loads(self.config.read_text())
        configuration["target_platform"] = "//tools/bazel/toolchains:wasm32"
        self.config.write_text(json.dumps(configuration))

        for command in ["build", "test", "cquery", "aquery"]:
            with self.subTest(command=command):
                result = self.invoke([command, "//:example", "--platforms=//:ambient"])
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = json.loads(self.capture.read_text())["args"]
                self.assertGreater(arguments.index("--platforms=//tools/bazel/toolchains:wasm32"),
                                   arguments.index("--platforms=//:ambient"))

        result = self.invoke(["query", "//:example"])
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.capture.read_text())["args"]
        self.assertFalse(any(argument.startswith("--platforms=") for argument in arguments))

    def test_compile_only_foreign_tests_require_explicit_external_execution(self):
        configuration = json.loads(self.config.read_text())
        configuration.update(compile_only=True, target_platform="//tools/bazel/toolchains:aarch64_linux")
        self.config.write_text(json.dumps(configuration))

        result = self.invoke(["build", "//:foreign_test"])
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.capture.read_text())["args"]
        self.assertIn("--extra_execution_platforms=//tools/bazel/toolchains:aarch64_linux", arguments)

        for command in ["test", "run"]:
            with self.subTest(command=command):
                result = self.invoke([command, "//:foreign_test"])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("explicit external target execution", result.stderr)

        configuration.pop("target_platform")
        self.config.write_text(json.dumps(configuration))
        result = self.invoke(["build", "//:foreign_test"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires an explicit target platform", result.stderr)

    def test_configured_dependency_profile_applies_to_every_analysis_command(self):
        configuration = json.loads(self.config.read_text())
        configuration["dependency_profile"] = "device"
        self.config.write_text(json.dumps(configuration))

        for command in ["build", "test", "run", "cquery", "aquery"]:
            with self.subTest(command=command):
                result = self.invoke([command, "//:example", "--//tools/bazel/rules:dependency_profile=core"])
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = json.loads(self.capture.read_text())["args"]
                self.assertGreater(arguments.index("--//tools/bazel/rules:dependency_profile=device"),
                                   arguments.index("--//tools/bazel/rules:dependency_profile=core"))

        result = self.invoke(["query", "//:example"])
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.capture.read_text())["args"]
        self.assertFalse(any(argument.startswith("--//tools/bazel/rules:dependency_profile=") for argument in arguments))

    def test_declared_rustc_flags_apply_to_compilation_and_analysis(self):
        configuration = json.loads(self.config.read_text())
        configuration["rustc_flags"] = ["-Copt-level=s", "-Cdebuginfo=0"]
        self.config.write_text(json.dumps(configuration))

        for command in ["build", "test", "cquery", "aquery"]:
            with self.subTest(command=command):
                result = self.invoke([command, "//:example"])
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = json.loads(self.capture.read_text())["args"]
                self.assertIn("--@rules_rust//rust/settings:extra_rustc_flags=-Copt-level=s,-Cdebuginfo=0", arguments)

    def test_private_server_is_opt_in_and_has_bounded_idle_and_heap(self):
        configuration = json.loads(self.config.read_text())
        configuration["batch"] = False
        self.config.write_text(json.dumps(configuration))
        metrics = self.root / "metrics.json"

        result = self.invoke(["build", "//:example"], ["--metrics", str(metrics)])
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.capture.read_text())["args"]
        self.assertNotIn("--batch", arguments)
        self.assertIn("--max_idle_secs=60", arguments)
        self.assertIn("--host_jvm_args=-Xmx2g", arguments)
        self.assertIn("--host_jvm_args=-XX:ActiveProcessorCount=2", arguments)
        self.assertIsNone(json.loads(metrics.read_text())["server_after"])

        result = self.invoke(["shutdown"])
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.capture.read_text())["args"]
        self.assertEqual(arguments[-1], "shutdown")
        self.assertFalse(any(argument.startswith("--override_") for argument in arguments))
        self.assertNotIn("--repository_disable_download", arguments)

    def test_benchmark_idle_time_is_explicit_and_bounded(self):
        result = self.invoke(["build", "//:example"], ["--no-batch", "--server-idle-seconds", "3600"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--max_idle_secs=3600", json.loads(self.capture.read_text())["args"])

        for duration in ["0", "-1", "3601"]:
            with self.subTest(duration=duration):
                result = self.invoke(["build", "//:example"], ["--no-batch", "--server-idle-seconds", duration])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("between 1 and 3600", result.stderr)

    def test_batch_configuration_rejects_server_shutdown(self):
        result = self.invoke(["shutdown"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("batch=false", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_release_batch_option_overrides_private_server_configuration(self):
        configuration = json.loads(self.config.read_text())
        configuration["batch"] = False
        self.config.write_text(json.dumps(configuration))

        result = self.invoke(["build", "//:example"], ["--batch"])
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.capture.read_text())["args"]
        self.assertIn("--batch", arguments)
        self.assertNotIn("--max_idle_secs=60", arguments)

    def test_private_server_option_overrides_batch_default(self):
        result = self.invoke(["shutdown"], ["--no-batch"])
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.capture.read_text())["args"]
        self.assertNotIn("--batch", arguments)
        self.assertEqual(arguments[-1], "shutdown")

    def test_remote_cache_and_toolchain_overrides_are_rejected(self):
        for option in ["--remote_cache=https://example.invalid", "--action_env=RUSTFLAGS=bad",
                       "--override_module=rules_rust=/unreviewed", "--registry=https://example.invalid",
                       "--genrule_strategy=standalone", "--bes_backend=grpc://example.invalid",
                       "--flagfile=/unreviewed/flags", "--flag_alias=custom=registry",
                       "--sandbox_block_path=", "--extra_execution_platforms=//:unreviewed"]:
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
