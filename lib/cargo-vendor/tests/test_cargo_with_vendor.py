"""UNRUN argv/environment DATA tests for the canonical development Cargo entry.

AOS_TEST_BASH must name the AOS-built bash. The recorder uses the exact Python
running this test (the future harness must use AOS Python); neither a host bash
nor Cargo executable is discovered through PATH. No compiler runs in these
fixtures. They exercise only the wrapper's ordinary exec/argument contract.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TEMPLATE = Path(__file__).parents[1] / "cargo-with-vendor.sh"


class CargoWithVendorTests(unittest.TestCase):
    def setUp(self):
        bash = os.environ.get("AOS_TEST_BASH")
        self.assertIsNotNone(bash, "AOS_TEST_BASH must name the source-built AOS bash")
        self.bash = Path(bash)
        self.assertTrue(self.bash.is_absolute())
        self.assertEqual(self.bash.name, "bash")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.recorder = self.root / "cargo-provider" / "bin" / "cargo"
        self.recorder.parent.mkdir(parents=True)
        self.recorder.write_text(
            f"#!{sys.executable}\n"
            "import json, os, signal, sys\n"
            "from pathlib import Path\n"
            "record = {'argv': sys.argv[1:], 'environment': dict(os.environ)}\n"
            "Path(os.environ['RECORDER_OUTPUT']).write_text(json.dumps(record))\n"
            "if os.environ.get('RECORDER_SIGNAL'):\n"
            "    os.kill(os.getpid(), int(os.environ['RECORDER_SIGNAL']))\n"
            "sys.exit(int(os.environ.get('RECORDER_STATUS', '0')))\n"
        )
        self.recorder.chmod(0o555)
        self.config = self.root / "vendor config.toml"
        self.config.write_text('[source.crates-io]\nreplace-with = "fixture"\n')
        self.wrapper = self.root / "cargo"
        body = TEMPLATE.read_text()
        body = body.replace("@bash@", str(self.bash.parent.parent))
        body = body.replace("@cargo@", str(self.recorder.parent.parent))
        body = body.replace("@vendor-config@", str(self.config))
        self.wrapper.write_text(body)
        self.wrapper.chmod(0o555)
        self.output = self.root / "record.json"
        self.environment = {
            "PATH": "",
            "RECORDER_OUTPUT": str(self.output),
            "OPENSSL_DIR": "unchanged-openssl",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "unchanged native flags",
            "RUSTFLAGS": "unchanged caller flags",
            "CARGO_HOME": "unchanged caller Cargo home",
        }

    def invoke(self, arguments, environment=None):
        return subprocess.run(
            [str(self.wrapper), *arguments],
            env=self.environment if environment is None else environment,
            capture_output=True,
            check=False,
        )

    def test_prefixes_fixed_config_and_preserves_argv_boundaries(self):
        arguments = [
            "build",
            "--manifest-path",
            "workspace with spaces/Cargo.toml",
            "--bin",
            "aos",
        ]

        result = self.invoke(arguments)

        self.assertEqual(result.returncode, 0)
        record = json.loads(self.output.read_text())
        self.assertEqual(record["argv"], ["--config", str(self.config), *arguments])
        for name, value in self.environment.items():
            self.assertEqual(record["environment"][name], value)
        self.assertFalse((self.root / "unchanged caller Cargo home").exists())

    def test_program_arguments_after_separator_are_not_reinterpreted(self):
        arguments = ["run", "--bin", "aos", "--", "--config", "secret program argument", ""]

        result = self.invoke(arguments)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            json.loads(self.output.read_text())["argv"],
            ["--config", str(self.config), *arguments],
        )

    def test_explicit_configuration_overrides_are_rejected_without_printing_values(self):
        for arguments in (["--config", "SECRET", "build"], ["build", "--config=SECRET"]):
            with self.subTest(arguments=arguments):
                result = self.invoke(arguments)

                self.assertEqual(result.returncode, 64)
                self.assertFalse(self.output.exists())
                self.assertNotIn(b"SECRET", result.stderr + result.stdout)

    def test_source_environment_overrides_are_rejected_without_printing_values(self):
        for name in (
            "CARGO_SOURCE_CRATES_IO_REPLACE_WITH",
            "CARGO_REGISTRIES_PRIVATE_INDEX",
            "CARGO_REGISTRIES_CRATES_IO_PROTOCOL",
            "CARGO_REGISTRY_INDEX",
            "CARGO_REGISTRY_DEFAULT",
        ):
            with self.subTest(name=name):
                environment = {**self.environment, name: "SECRET_CREDENTIAL_VALUE"}

                result = self.invoke(["build"], environment)

                self.assertEqual(result.returncode, 64)
                self.assertFalse(self.output.exists())
                self.assertNotIn(b"SECRET_CREDENTIAL_VALUE", result.stderr + result.stdout)

    def test_registry_credentials_are_not_treated_as_source_overrides(self):
        environment = {**self.environment, "CARGO_REGISTRIES_PRIVATE_TOKEN": "PRIVATE_TOKEN"}

        result = self.invoke(["build"], environment)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            json.loads(self.output.read_text())["environment"]["CARGO_REGISTRIES_PRIVATE_TOKEN"],
            "PRIVATE_TOKEN",
        )
        self.assertNotIn(b"PRIVATE_TOKEN", result.stderr + result.stdout)

    def test_exec_preserves_exit_status(self):
        environment = {**self.environment, "RECORDER_STATUS": "37"}

        result = self.invoke(["build"], environment)

        self.assertEqual(result.returncode, 37)

    def test_exec_preserves_terminating_signal(self):
        import signal

        environment = {**self.environment, "RECORDER_SIGNAL": str(signal.SIGTERM)}

        result = self.invoke(["build"], environment)

        self.assertEqual(result.returncode, -signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
