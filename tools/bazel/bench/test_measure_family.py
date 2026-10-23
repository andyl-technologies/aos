"""Checks that family measurements cannot silently omit configured test targets."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "metadata"))
from measure_family import apply_edit, bazel_binaries, cargo_binaries, compilation_profile, record_cargo_commands, validate, validate_bazel_profile, validate_profile


class FamilyMeasurementTests(unittest.TestCase):
    def test_compiler_commands_preserve_wrappers_flags_and_literal_shell_characters(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "command.log"
            output = Path(temporary) / "cargo-compiler-commands.txt"
            command = '/tools/accache /tools/rustc --crate-name library -C codegen-units=256 -C incremental=/target "literal$(value)"'
            log.write_text('   Compiling library v1.0.0\n     Running `' + command + '`\n'
                           '     Running `/target/build-script-build`\n'
                           '{"reason":"compiler-artifact"}\n')

            self.assertEqual(record_cargo_commands(log, output, require_commands=True), 1)
            self.assertEqual(output.read_text(), command + "\n")

    def test_cold_compilation_requires_commands_and_warm_noop_allows_none(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "command.log"
            output = Path(temporary) / "cargo-compiler-commands.txt"
            log.write_text('       Fresh library v1.0.0\n')

            self.assertEqual(record_cargo_commands(log, output), 0)
            self.assertEqual(output.read_text(), "")
            with self.assertRaisesRegex(ValueError, "no compiler commands"):
                record_cargo_commands(log, output, require_commands=True)
            log.write_text('Running `/tools/rustc --crate-name library\n')
            with self.assertRaisesRegex(ValueError, "unterminated"):
                record_cargo_commands(log, output)

    def events(self):
        return [
            {"id": {"namedSet": {"id": "current"}}, "namedSetOfFiles": {"files": [
                {"name": "crates/device/unit_binary", "uri": "file:///current/unit_binary"}]}},
            {"id": {"namedSet": {"id": "old"}}, "namedSetOfFiles": {"files": [
                {"name": "crates/device/unit_binary", "uri": "file:///old/unit_binary"}]}},
            {"id": {"targetCompleted": {"label": "//crates/device:unit_binary"}}, "completed": {
                "success": True, "outputGroup": [{"name": "default", "fileSets": [{"id": "current"}]}]}},
            {"id": {"buildFinished": {}}, "finished": {"exitCode": {"code": 0}}},
        ]

    def test_only_current_successful_outputs_are_selected(self):
        binaries = bazel_binaries(self.events(), ["//crates/device:unit_binary"])
        self.assertEqual(binaries, {"//crates/device:unit": Path("/current/unit_binary")})

    def test_missing_requested_target_rejects_measurement(self):
        with self.assertRaisesRegex(ValueError, "missing successful"):
            bazel_binaries(self.events(), ["//crates/device:unit_binary", "//crates/device:io_binary"])

    def test_unsuccessful_build_rejects_measurement(self):
        events = self.events()
        events[-1]["finished"]["exitCode"]["code"] = 1
        with self.assertRaisesRegex(ValueError, "missing successful"):
            bazel_binaries(events, ["//crates/device:unit_binary"])

    def test_cargo_library_binary_and_integration_targets_remain_distinct(self):
        events = [{"reason": "compiler-artifact", "executable": "/target/" + name,
                   "profile": {"test": True}, "manifest_path": "/src/device/Cargo.toml",
                   "target": {"kind": [kind], "name": name}}
                  for kind, name in [("lib", "device"), ("bin", "device-tool"), ("test", "io")]]
        self.assertEqual(cargo_binaries(events, {"device": "crates/device"}), {
            "//crates/device:unit": Path("/target/device"),
            "//crates/device:bin_device-tool": Path("/target/device-tool"),
            "//crates/device:io": Path("/target/io"),
        })

    def test_duplicate_cargo_artifact_rejects_measurement(self):
        event = {"reason": "compiler-artifact", "executable": "/target/device", "profile": {"test": True},
                 "manifest_path": "/src/device/Cargo.toml", "target": {"kind": ["lib"], "name": "device"}}
        with self.assertRaisesRegex(ValueError, "ambiguous Cargo"):
            cargo_binaries([event, event], {"device": "crates/device"})

    def test_profile_records_compiled_artifacts_and_rejects_mixed_profiles(self):
        binary = Path("/target/unit")
        event = {"reason": "compiler-artifact", "executable": str(binary),
                 "profile": {"opt_level": "s", "debuginfo": 0, "debug_assertions": True, "overflow_checks": True}}
        self.assertEqual(compilation_profile([event], {"unit": binary}, True), {
            "opt_level": "s", "debug": 0, "debug_assertions": True, "overflow_checks": True, "incremental": True,
        })
        other = {**event, "profile": {**event["profile"], "opt_level": "0", "debuginfo": 2}}
        with self.assertRaisesRegex(ValueError, "ambiguous profiles"):
            compilation_profile([event, other], {"unit": binary}, True)
        with self.assertRaisesRegex(ValueError, "ambiguous profiles"):
            compilation_profile([], {"unit": binary}, True)

        for key in ["debug_assertions", "overflow_checks"]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "ambiguous profiles"):
                compilation_profile([event, {**event, "profile": {**event["profile"], key: False}}], {"unit": binary}, True)

    def test_matched_profiles_reject_disabled_assertions_and_overflow_checks(self):
        profile = {"opt_level": "s", "debug": 0, "debug_assertions": True, "overflow_checks": True}
        configuration = {"require_matched_profiles": True, "bazel_compilation_profile": profile}

        validate_profile(dict(profile, incremental=True), configuration)

        for key in ["debug_assertions", "overflow_checks"]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "compilation profile differs"):
                validate_profile({**profile, key: False}, configuration)

    def test_launcher_profile_must_explicitly_match_before_measurement(self):
        with tempfile.TemporaryDirectory() as temporary:
            launcher = Path(temporary) / "launcher.json"
            profile = {"opt_level": "s", "debug": 0, "debug_assertions": True, "overflow_checks": True}
            configuration = {"require_matched_profiles": True, "bazel_compilation_profile": profile,
                             "bazel_config": str(launcher)}
            flags = ["-Copt-level=s", "-Cdebuginfo=0", "-Cdebug-assertions=yes", "-Coverflow-checks=yes"]
            launcher.write_text(json.dumps({"rustc_flags": flags}))

            validate_bazel_profile(configuration)

            for invalid in [flags[:2], flags + ["-Cdebug-assertions=no"], [*flags[:3], "-Coverflow-checks=no"]]:
                with self.subTest(flags=invalid), self.assertRaisesRegex(ValueError, "launcher profile must declare"):
                    launcher.write_text(json.dumps({"rustc_flags": invalid}))
                    validate_bazel_profile(configuration)

    def test_declared_edits_preserve_inputs_and_reject_missing_or_escaped_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            workspace.mkdir()
            source = workspace / "lib.rs"
            source.write_text("// original source\n")
            configuration = {"edits": {"implementation-edit": "lib.rs", "public-api-edit": "lib.rs"}}

            apply_edit(workspace, configuration, "implementation-edit")
            apply_edit(workspace, configuration, "public-api-edit")

            self.assertTrue(source.read_text().startswith("// original source\n"))
            self.assertIn("fn measurement_private_edit", source.read_text())
            self.assertIn("pub fn measurement_api_edit", source.read_text())
            for path in ["missing.rs", "../outside.rs", str(source.resolve())]:
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "measurement edit"):
                    apply_edit(workspace, {"edits": {"implementation-edit": path}}, "implementation-edit")


class IsolatedValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        (self.workspace / "crates/device").mkdir(parents=True)
        self.binary = self.root / "tests"
        self.binary.write_text(f"#!{sys.executable}\n" + '''
import os, sys, time
if '--list' in sys.argv:
    if '--ignored' not in sys.argv:
        print('first: test')
        print('second: test')
    raise SystemExit(0)
assert '--exact' in sys.argv and '--test-threads=1' in sys.argv
if sys.argv[1] == 'second':
    time.sleep(float(os.environ.get('CASE_SLEEP', '0')))
raise SystemExit(int(os.environ.get('CASE_STATUS', '0')))
''')
        self.binary.chmod(0o755)
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps({"schema_version": 1, "default_timeout_seconds": 0.15,
                                           "default_termination_grace_seconds": 0.01, "overrides": []}))
        self.label = "//crates/device:unit"
        self.expected = {self.label: {"executed": ["first", "second"], "ignored": []}}
        self.environment = dict(os.environ)

    def validate(self):
        validate({self.label: self.binary}, self.expected, self.workspace, self.root, self.environment,
                 case_runner=ROOT / "testing/runner.py", policy=self.policy, jobs=2)

    def test_each_qualified_case_runs_with_the_real_policy_runner(self):
        self.validate()
        self.assertIn('tests="2"', (self.root / "validation-0.xml").read_text())

    def test_case_timeout_and_failure_reject_the_measurement(self):
        for environment in [{"CASE_SLEEP": "1"}, {"CASE_STATUS": "7"}]:
            with self.subTest(environment=environment):
                self.environment = dict(os.environ, **environment)
                with self.assertRaisesRegex(ValueError, "isolated family test execution failed"):
                    self.validate()

    def test_missing_case_is_not_hidden_by_successful_execution(self):
        self.expected[self.label]["executed"].append("missing")
        with self.assertRaisesRegex(ValueError, "discovered test inventory differs"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
