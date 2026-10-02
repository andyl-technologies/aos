"""Executes the production seed script's durable reconciliation helpers."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


BASH, SOURCE, COREUTILS, JQ = sys.argv[1:5]
del sys.argv[1:5]
metadata_path = sys.argv.pop(1) if len(sys.argv) > 1 else None
descriptor_path = sys.argv.pop(1) if len(sys.argv) > 1 else None
source = Path(SOURCE).read_text()
library_metadata = (
    json.loads(Path(metadata_path).read_text())
    if metadata_path is not None
    else {
        "store_path": "/nix/store/selected-library",
        "nar_hash": "sha256:" + "a" * 64,
        "nar_size": 1255160,
    }
)


def shell_function(name):
    start = source.index(f"\n{name}() {{") + 1
    end = source.index("\n}\n", start) + 3
    return source[start:end]


FUNCTIONS = "\n".join(
    shell_function(name)
    for name in (
        "fail_image_identity",
        "publish_image_state",
        "update_running_image_state",
        "repair_image_retention",
        "validate_module_library_identity",
        "validate_nix_store_root",
        "validate_rooted_evaluation_descriptor",
    )
)


def identity(path):
    stat = path.lstat()
    return stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns


class SeedReconciliation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.image = self.root / "image"
        self.image.mkdir()
        self.state = self.image / "state.json"
        self.retention = self.image / "image-gen-2"
        self.retention.mkdir()
        self.spy = self.root / "sync-calls"
        self.spy.touch()
        self.targets = {
            "toplevel": "/nix/store/selected-toplevel",
            "native-executor": "/nix/store/selected-executor",
            "boot-artifact-contract": "/nix/store/selected-contract",
            "module-library": "/nix/store/selected-library",
            "evaluation-descriptor": "/nix/store/selected-deployment/evaluation-input.json",
        }
        for name, target in self.targets.items():
            (self.retention / name).symlink_to(target)

        self.document = {
            "schema": "aos.image-generation-state/v1",
            "running": 2,
            "pending": None,
            "generations": [
                {"number": 1, "toplevel": "/nix/store/previous-toplevel"},
                {"number": 2, "toplevel": self.targets["toplevel"]},
            ],
            "active_rollout": None,
        }
        self.write_state()

    def write_state(self):
        # Deliberately differs from jq's formatting: semantic steady state is
        # read-only even when an earlier publisher used another whitespace style.
        self.state.write_text(json.dumps(self.document, separators=(",", ":")))

    def run_helpers(self, commands, extra_variables=None):
        variables = {
            "image_dir": str(self.image),
            "retention": str(self.retention),
            "spy": str(self.spy),
            "toplevel": self.targets["toplevel"],
            "native_executor": self.targets["native-executor"],
            "boot_contract": self.targets["boot-artifact-contract"],
            "module_library_root": self.targets["module-library"],
            "evaluation_descriptor": self.targets["evaluation-descriptor"],
        }
        variables.update(extra_variables or {})
        assignments = "\n".join(
            f"{name}={shlex.quote(value)}" for name, value in variables.items()
        )
        script = (
            "set -euo pipefail\n"
            + assignments
            + "\n"
            + FUNCTIONS
            + '\nsync() { printf "%s\\n" "$1" >> "$spy"; }\n'
            + commands
            + "\n"
        )
        return subprocess.run(
            [BASH, "-c", script],
            env={"PATH": f"{COREUTILS}:{JQ}", "LC_ALL": "C"},
            text=True,
            capture_output=True,
            timeout=10,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)

    def retained_identities(self):
        return {
            name: identity(self.retention / name) for name in self.targets
        }

    def test_steady_boot_preserves_state_directory_and_link_metadata(self):
        before = {
            "state": identity(self.state),
            "image": identity(self.image),
            "retention": identity(self.retention),
            "links": self.retained_identities(),
        }

        result = self.run_helpers("update_running_image_state\nrepair_image_retention")

        self.assert_success(result)
        self.assertEqual(identity(self.state), before["state"])
        self.assertEqual(identity(self.image), before["image"])
        self.assertEqual(identity(self.retention), before["retention"])
        self.assertEqual(self.retained_identities(), before["links"])
        self.assertEqual(self.spy.read_text(), "")
        self.assertFalse((self.image / ".state.json.new").exists())

    def test_running_image_change_publishes_and_syncs_state(self):
        self.document["running"] = 1
        self.write_state()
        old_inode = self.state.stat().st_ino

        result = self.run_helpers("update_running_image_state")

        self.assert_success(result)
        self.assertEqual(json.loads(self.state.read_text())["running"], 2)
        self.assertNotEqual(self.state.stat().st_ino, old_inode)
        self.assertEqual(
            self.spy.read_text().splitlines(),
            [str(self.image / ".state.json.new"), str(self.image)],
        )

    def test_staged_running_candidate_advances_once(self):
        self.document["active_rollout"] = {
            "candidate": 2,
            "status": "staged",
            "unchanged_field": "preserved",
        }
        self.write_state()

        self.assert_success(self.run_helpers("update_running_image_state"))

        rollout = json.loads(self.state.read_text())["active_rollout"]
        self.assertEqual(rollout["status"], "candidate_booted")
        self.assertEqual(rollout["unchanged_field"], "preserved")
        before = identity(self.state)
        self.spy.write_text("")

        self.assert_success(self.run_helpers("update_running_image_state"))
        self.assertEqual(identity(self.state), before)
        self.assertEqual(self.spy.read_text(), "")

    def test_other_staged_candidate_is_not_changed(self):
        self.document["active_rollout"] = {"candidate": 1, "status": "staged"}
        self.write_state()
        before = identity(self.state)

        result = self.run_helpers("update_running_image_state")

        self.assert_success(result)
        self.assertEqual(identity(self.state), before)
        self.assertEqual(self.spy.read_text(), "")

    def test_missing_root_repairs_only_missing_link_and_syncs(self):
        missing = "native-executor"
        (self.retention / missing).unlink()
        before = {
            name: identity(self.retention / name)
            for name in self.targets
            if name != missing
        }

        result = self.run_helpers("repair_image_retention")

        self.assert_success(result)
        self.assertEqual(os.readlink(self.retention / missing), self.targets[missing])
        for name, metadata in before.items():
            self.assertEqual(identity(self.retention / name), metadata)
        self.assertEqual(self.spy.read_text().splitlines(), [str(self.retention)])

    def test_wrong_root_target_is_repaired(self):
        path = self.retention / "module-library"
        path.unlink()
        path.symlink_to("/nix/store/wrong-library")

        result = self.run_helpers("repair_image_retention")

        self.assert_success(result)
        self.assertEqual(os.readlink(path), self.targets["module-library"])
        self.assertEqual(self.spy.read_text().splitlines(), [str(self.retention)])

    def test_conflicting_nonlink_rejects_before_repair(self):
        (self.retention / "toplevel").unlink()
        path = self.retention / "evaluation-descriptor"
        path.unlink()
        path.write_text("external contents")
        before = identity(path)

        result = self.run_helpers("repair_image_retention")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a symbolic link", result.stderr)
        self.assertEqual(identity(path), before)
        self.assertEqual(path.read_text(), "external contents")
        self.assertFalse((self.retention / "toplevel").is_symlink())
        self.assertEqual(self.spy.read_text(), "")

    def test_native_library_metadata_is_accepted(self):
        result = self.run_helpers(
            "validate_module_library_identity",
            {"module_library": json.dumps(library_metadata)},
        )

        self.assert_success(result)

    def test_noncanonical_hashes_are_rejected(self):
        hashes = (
            "sha256-" + "A" * 43 + "=",
            "sha256:" + "A" * 64,
            "sha256:" + "a" * 63,
            "sha256:" + "a" * 65,
            "sha256:" + "g" * 64,
            "sha256:" + "a" * 64 + "\n",
            123,
        )
        for digest in hashes:
            with self.subTest(digest=digest):
                metadata = library_metadata | {"nar_hash": digest}

                result = self.run_helpers(
                    "validate_module_library_identity",
                    {"module_library": json.dumps(metadata)},
                )

                self.assertNotEqual(result.returncode, 0)

    def test_invalid_library_shape_and_size_are_rejected(self):
        cases = (
            library_metadata | {"nar_size": 0},
            library_metadata | {"nar_size": -1},
            library_metadata | {"nar_size": 1.5},
            library_metadata | {"nar_size": True},
            library_metadata | {"nar_size": "1255160"},
            library_metadata | {"unexpected": "field"},
            {key: value for key, value in library_metadata.items() if key != "nar_hash"},
        )
        for metadata in cases:
            with self.subTest(metadata=metadata):
                result = self.run_helpers(
                    "validate_module_library_identity",
                    {"module_library": json.dumps(metadata)},
                )

                self.assertNotEqual(result.returncode, 0)

    def descriptor_fixture(self):
        root = self.root / "sysroot"
        descriptor = (
            descriptor_path
            if descriptor_path is not None
            else "/nix/store/" + "0" * 32 + "-host-deployment/evaluation.json"
        )
        target = (
            os.readlink(descriptor)
            if descriptor_path is not None
            else "/nix/store/" + "1" * 32 + "-native-evaluation-inputs"
        )
        physical = root / descriptor.lstrip("/")
        physical.parent.mkdir(parents=True)
        physical.symlink_to(target)
        rooted_target = root / target.lstrip("/")
        contents = (
            Path(descriptor).read_bytes()
            if descriptor_path
            else b'{"library":"retained"}'
        )
        rooted_target.write_bytes(contents)
        return root, descriptor, physical, target, rooted_target

    def check_descriptor(self, root, descriptor):
        return self.run_helpers(
            "validate_rooted_evaluation_descriptor "
            + shlex.quote(str(root))
            + " "
            + shlex.quote(descriptor)
        )

    def test_retained_absolute_descriptor_leaf_resolves_in_host_namespace(self):
        root, descriptor, physical, target, rooted_target = self.descriptor_fixture()

        result = self.check_descriptor(root, descriptor)

        self.assert_success(result)
        self.assertEqual(os.readlink(physical), target)
        self.assertTrue(rooted_target.is_file())

    def test_direct_regular_descriptor_member_is_accepted(self):
        root, descriptor, physical, _, _ = self.descriptor_fixture()
        physical.unlink()
        physical.write_text('{"library":"retained"}')

        self.assert_success(self.check_descriptor(root, descriptor))

    def test_descriptor_target_must_be_one_regular_store_root_file(self):
        root, descriptor, physical, _, rooted_target = self.descriptor_fixture()
        rooted_target.unlink()

        self.assertNotEqual(self.check_descriptor(root, descriptor).returncode, 0)
        rooted_target.symlink_to("/nix/store/" + "2" * 32 + "-another-target")
        self.assertNotEqual(self.check_descriptor(root, descriptor).returncode, 0)
        rooted_target.unlink()
        rooted_target.mkdir()
        self.assertNotEqual(self.check_descriptor(root, descriptor).returncode, 0)

        for target in ("../relative", "/etc/passwd", "/nix/store/invalid", descriptor):
            with self.subTest(target=target):
                physical.unlink()
                physical.symlink_to(target)

                self.assertNotEqual(self.check_descriptor(root, descriptor).returncode, 0)

    def test_descriptor_member_must_be_normalized_and_confined(self):
        root, descriptor, physical, _, _ = self.descriptor_fixture()
        invalid_paths = (
            descriptor.replace("/evaluation.json", "/../evaluation.json"),
            descriptor.replace("/evaluation.json", "//evaluation.json"),
            descriptor.replace("/evaluation.json", "/./evaluation.json"),
            "/nix/store/invalid/evaluation.json",
            "/etc/evaluation.json",
        )
        for candidate in invalid_paths:
            with self.subTest(candidate=candidate):
                self.assertNotEqual(self.check_descriptor(root, candidate).returncode, 0)

        physical.unlink()
        physical.parent.rmdir()
        physical.parent.symlink_to(self.image)

        self.assertNotEqual(self.check_descriptor(root, descriptor).returncode, 0)


if __name__ == "__main__":
    unittest.main()
