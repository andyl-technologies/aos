"""Exercise issuer initialization with a selected existing Native executable.

Public synthetic blocked publications exercise the real private SQLite boundary;
they grant no provider admission, qualification or runtime issuance. No operator
key material or existing issuer resource is read. The diagnostic overflow case
uses a local Python child, separately from the actual Native initialization.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


SOURCE = Path(__file__).with_name("_hub-direct-authority.py")
AUTHORITY = {"__name__": "issuer_fixture_test", "__file__": str(SOURCE)}
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), AUTHORITY)
EXECUTABLE = None


def canonical(value):
    return json.dumps(value, separators=(",", ":")).encode()


def write_private(path, body):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)


def synthetic_files(root, hub, dedicated):
    """Create public synthetic closed inputs, without a signing seed or key read."""
    authority = {"authority_id": "00000000-0000-4000-8000-000000000001",
        "guard_namespace_id": "synthetic-journal-namespace",
        "physical_resource_evidence_digest": "1" * 64,
        "qualification_digest": "2" * 64, "qualified_managed_prefix": "synthetic"}
    admission = {"authority_id": authority["authority_id"], "expected_generation": 0,
        "expected_digest": None, "guard_namespace_id": authority["guard_namespace_id"],
        "state": "blocked", "attestation_id": None, "association_ids": []}
    publication = {"authority": authority, "aliases": [], "associations": [],
        "attestation": None, "admission": admission, "generation": 1,
        "digest": hashlib.sha256(canonical(admission)).hexdigest()}
    journal = root / "journal" / "journal.sqlite" if dedicated else root / "journal.sqlite"
    if dedicated:
        journal.parent.mkdir(mode=0o700)
    configuration = {"format_version": 1, "listen": "127.0.0.1:8444",
        "journal_file": str(journal), "installation": {"format_version": 1,
            "authority": authority, "issuer_resource_id": "synthetic-issuer-resource",
            "runtime_identity": "synthetic-issuer-runtime", "executor_identity": "synthetic-executor"},
        "hub_root": str(hub), "hub_sqlite_file": None,
        "policy": {"timing_profile": {"profile_id": "synthetic-clock-profile",
            "review_digest": "3" * 64, "maximum_lifetime": "30", "maximum_clock_uncertainty": "3"}},
        "clock_uncertainty": "1", "clock_commit_latency": "1", "issuance_enabled": False,
        "publisher_key_file": str(root / "publisher.key"),
        "renewal_key_file": str(root / "renewal.key"),
        "signing_seed_file": str(root / "signing-seed.key"),
        "signing_key_id": "synthetic-issuer-key", "tls": None}
    write_private(root / "configuration.json", canonical(configuration))
    write_private(root / "publication.json", canonical(publication))
    return journal


class IssuerInitializationTests(unittest.TestCase):
    def setUp(self):
        self.retained = []
        AUTHORITY["retain_direct_flow"] = lambda label, result: self.retained.append((label, result))

    def guest(self, directory):
        def command(machine, script, timeout):
            del machine
            marker = "NATIVE_ISSUER_INITIALIZATION"
            program = script.split("<<'" + marker + "'\n", 1)[1].rsplit(marker, 1)[0]
            completed = subprocess.run([sys.executable, "-B", "-c", textwrap.dedent(program)],
                cwd=directory, capture_output=True, timeout=timeout, check=False)
            if completed.returncode:
                # The test deliberately does not expose arbitrary child stderr.
                raise RuntimeError("local diagnostic wrapper failed")
            self.driver_replies.append(completed.stdout)
            return completed.stdout.decode()
        return command

    def initialize(self, root, executable=None):
        return AUTHORITY["initialize_external_issuer"](None, sys.executable,
            executable or EXECUTABLE, str(root / "configuration.json"), str(root / "publication.json"))

    def test_real_initializer_enforces_dedicated_parent_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            hub = parent / "hub"
            hub.mkdir(mode=0o700)
            flat, dedicated = parent / "flat", parent / "dedicated"
            flat.mkdir(mode=0o700)
            dedicated.mkdir(mode=0o700)
            old_journal = synthetic_files(flat, hub, False)
            journal = synthetic_files(dedicated, hub, True)
            self.assertEqual(list(journal.parent.iterdir()), [])
            self.assertEqual(stat.S_IMODE(journal.parent.stat().st_mode), 0o700)
            self.assertEqual(journal.parent.stat().st_uid, os.geteuid())
            self.driver_replies = []
            AUTHORITY["private_guest_command"] = self.guest(parent)

            with self.assertRaisesRegex(RuntimeError, "journal_directory"):
                self.initialize(flat)
            self.assertFalse(old_journal.exists())
            failure = json.loads((flat / "initialize-result.json").read_bytes())
            self.assertEqual(self.retained[0][1], failure)
            self.assertNotEqual(failure["exitCode"], 0)
            self.assertTrue(failure["stderrComplete"])
            self.assertEqual(stat.S_IMODE((flat / "initialize.stderr").stat().st_mode), 0o600)

            result = self.initialize(dedicated)
            self.assertEqual(self.retained[1][1], result)
            self.assertNotEqual(self.retained[0][0], self.retained[1][0])
            self.assertEqual(result["exitCode"], 0)
            self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)
            self.assertEqual(journal.stat().st_uid, os.geteuid())
            self.assertEqual([path.name for path in journal.parent.iterdir()], ["journal.sqlite"])
            before = (journal.stat().st_dev, journal.stat().st_ino, journal.read_bytes())

            # Invoke the actual initializer again directly: diagnostic files are
            # create-only, and must not themselves be removed to permit a retry.
            repeated = subprocess.run([EXECUTABLE, "initialize", "--configuration",
                str(dedicated / "configuration.json"), "--publication",
                str(dedicated / "publication.json")], capture_output=True, timeout=15, check=False)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual((journal.stat().st_dev, journal.stat().st_ino, journal.read_bytes()), before)
            self.assertTrue(all(b"dedicated private directory" not in reply for reply in self.driver_replies))

    def test_stderr_overflow_is_private_bounded_and_cannot_be_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            # Python treats "initialize" as its script; no provider or issuer is
            # involved in this controlled collector-bound regression.
            sentinel = "synthetic-private-diagnostic"
            (root / "initialize").write_text("import os\nos.write(2, "
                + repr((sentinel * 5000).encode()) + ")\n")
            self.driver_replies = []
            AUTHORITY["private_guest_command"] = self.guest(root)
            with self.assertRaisesRegex(RuntimeError, "stderr_bound_exceeded"):
                self.initialize(root, sys.executable)
            result = json.loads((root / "initialize-result.json").read_bytes())
            self.assertEqual(self.retained[0][1], result)
            self.assertTrue(result["stderrOverflow"])
            self.assertEqual(result["stderrBytes"], 65536)
            self.assertEqual((root / "initialize.stderr").stat().st_size, 65536)
            self.assertEqual(stat.S_IMODE((root / "initialize.stderr").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((root / "initialize-result.json").stat().st_mode), 0o600)
            self.assertTrue(all(sentinel.encode() not in reply for reply in self.driver_replies))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check real Native issuer journal initialization.")
    parser.add_argument("--authority-executable", required=True)
    parser.add_argument("--authority-sha256", required=True)
    selected, remaining = parser.parse_known_args()
    EXECUTABLE = selected.authority_executable
    if hashlib.sha256(Path(EXECUTABLE).read_bytes()).hexdigest() != selected.authority_sha256:
        raise ValueError("selected existing authority executable differs")
    unittest.main(argv=[sys.argv[0], *remaining])
