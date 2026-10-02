"""Executes image database hydration and its fail-closed bootstrap boundary."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BASH, COREUTILS, SCRIPT, NIX = sys.argv[1:5]
sys.argv = sys.argv[:1]


class HostStoreSeedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="host-store-seed-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.registration = self.root / "nix-registration"
        self.digest = self.root / "nix-registration.sha256"
        self.calls = self.root / "calls"
        self.loaded = self.root / "loaded"
        self.registration.write_bytes(b"exact immutable registration stream\n")
        self.digest.write_text(hashlib.sha256(self.registration.read_bytes()).hexdigest() + "\n")

        tools = self.root / "nix"
        (tools / "bin").mkdir(parents=True)
        executable = tools / "bin/nix-store"
        executable.write_text(
            f"#!{BASH}\n"
            'set -euo pipefail\n'
            # The real command must explicitly choose the local store even
            # when the caller inherited a daemon-selected login environment.
            '[[ "$1" == --store && "$2" == local ]]\n'
            '[[ "$3" == --option && "$4" == build-users-group && -z "$5" ]]\n'
            '[[ "$#" == 6 ]]\n'
            'printf "%s\\n" "$6" >> "$TEST_CALLS"\n'
            'case "$6" in\n'
            '  --init) exit "$TEST_INIT_STATUS" ;;\n'
            f'  --load-db) {COREUTILS}/bin/cat > "$TEST_LOADED"; exit "$TEST_LOAD_STATUS" ;;\n'
            '  *) exit 64 ;;\n'
            'esac\n'
        )
        executable.chmod(0o555)

        # Substitute the same executable bindings as the package installer;
        # remap only the two fixed image inputs into this private fixture.
        source = Path(SCRIPT).read_text()
        source = source.replace("/usr/lib/aos/nix-registration.sha256", str(self.digest))
        source = source.replace("/usr/lib/aos/nix-registration", str(self.registration))
        source = source.replace("@nix@", str(tools)).replace("@coreutils@", COREUTILS)
        self.script = self.root / "aos-host-store-seed"
        self.script.write_text(source)

    def run_script(self, init_status=0, load_status=0, extra_environment=None):
        environment = dict(
            os.environ, PATH="", LC_ALL="C", NIX_REMOTE="daemon",
            TEST_CALLS=str(self.calls), TEST_LOADED=str(self.loaded),
            TEST_INIT_STATUS=str(init_status), TEST_LOAD_STATUS=str(load_status),
        )
        environment.update(extra_environment or {})
        return subprocess.run([BASH, str(self.script)], env=environment,
                              capture_output=True, text=True)

    def recorded_calls(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def test_initialization_precedes_exact_local_import(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.recorded_calls(), ["--init", "--load-db"])
        self.assertEqual(self.loaded.read_bytes(), self.registration.read_bytes())

    def test_repeated_hydration_loads_same_stream(self):
        first = self.run_script()
        second = self.run_script()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.recorded_calls(), ["--init", "--load-db"] * 2)
        self.assertEqual(self.loaded.read_bytes(), self.registration.read_bytes())

    def test_real_nix_repeated_import_registers_private_store(self):
        store = self.root / "store"
        store.mkdir()
        environment = dict(
            os.environ, LC_ALL="C", NIX_STORE_DIR=str(store),
            NIX_STATE_DIR=str(self.root / "origin-state"),
            NIX_LOG_DIR=str(self.root / "logs"), NIX_REMOTE="local",
            NIX_CONF_DIR=str(self.root / "absent-config"),
        )
        command = [f"{NIX}/bin/nix-store", "--store", "local",
                   "--option", "build-users-group", ""]
        content = self.root / "content"
        content.write_text("immutable private-store test object\n")
        added = subprocess.run(command + ["--add-fixed", "sha256", str(content)],
                               env=environment, capture_output=True, text=True,
                               check=True).stdout.strip()
        registration = subprocess.run(command + ["--dump-db", added],
                                      env=environment, capture_output=True,
                                      check=True).stdout
        self.registration.write_bytes(registration)
        self.digest.write_text(hashlib.sha256(registration).hexdigest() + "\n")

        self.script.write_text(self.script.read_text().replace(
            str(self.root / "nix/bin/nix-store"), f"{NIX}/bin/nix-store"))
        environment["NIX_STATE_DIR"] = str(self.root / "hydrated-state")
        for attempt in range(2):
            with self.subTest(attempt=attempt):
                result = self.run_script(extra_environment=environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                subprocess.run(command + ["--check-validity", added],
                               env=environment, capture_output=True, check=True)

    def test_missing_registration_or_sidecar_prevents_database_mutation(self):
        for path in (self.registration, self.digest):
            with self.subTest(path=path.name):
                saved = path.read_bytes()
                path.unlink()
                result = self.run_script()
                path.write_bytes(saved)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.recorded_calls(), [])

    def test_malformed_digest_prevents_database_mutation(self):
        for digest in ("", "A" * 64, "0" * 63, "0" * 65, "0" * 64 + "\n0"):
            with self.subTest(digest=digest):
                self.digest.write_text(digest)
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("digest is malformed", result.stderr)
                self.assertEqual(self.recorded_calls(), [])

    def test_mismatched_digest_prevents_database_mutation(self):
        self.digest.write_text("0" * 64 + "\n")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest does not match", result.stderr)
        self.assertEqual(self.recorded_calls(), [])

    def test_initialization_failure_propagates_without_import(self):
        result = self.run_script(init_status=23)
        self.assertEqual(result.returncode, 23)
        self.assertEqual(self.recorded_calls(), ["--init"])
        self.assertFalse(self.loaded.exists())

    def test_import_failure_propagates(self):
        result = self.run_script(load_status=31)
        self.assertEqual(result.returncode, 31)
        self.assertEqual(self.recorded_calls(), ["--init", "--load-db"])


unittest.main()
