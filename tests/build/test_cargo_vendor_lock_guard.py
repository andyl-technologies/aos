"""Checks raw-lockfile hints before vendoring effects and preserves ordinary sources."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch


UTILITY = Path(__file__).resolve().parents[2] / "lib/cargo-vendor/fetch-cargo-vendor-util.py"
SPEC = importlib.util.spec_from_file_location("cargo_vendor_lock_guard", UTILITY)
assert SPEC is not None and SPEC.loader is not None
vendor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vendor)

LOCAL_LOCK = b'version = 4\npackage = []\n'


def digest(contents):
    return hashlib.sha256(contents).hexdigest()


class InlinePool:
    """Runs mocked downloads synchronously; no worker or network is started."""

    def __init__(self, workers):
        self.workers = workers

    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        return False

    def starmap(self, action, rows):
        return [action(*row) for row in rows]


class ArchiveResponse(io.BytesIO):
    status = 200


def registry_fixture(root):
    """Builds one actual crate archive and its matching lockfile checksum."""
    files = {
        "Cargo.toml": b'[package]\nname = "tiny"\nversion = "1.0.0"\n',
        "src/lib.rs": b"pub const VALUE: u8 = 7;\n",
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, contents in files.items():
            entry = tarfile.TarInfo("tiny-1.0.0/" + name)
            entry.size = len(contents)
            entry.mode = 0o644
            archive.addfile(entry, io.BytesIO(contents))
    compressed = buffer.getvalue()
    lock = root / "Cargo.lock"
    lock.write_text(
        'version = 4\n\n[[package]]\nname = "tiny"\nversion = "1.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        f'checksum = "{digest(compressed)}"\n'
    )
    lock.chmod(0o640)
    return lock, compressed, files


def tree_bytes(root):
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class CargoVendorLockGuardTests(unittest.TestCase):
    def test_changed_source_lock_refuses_before_parse_download_or_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "Cargo.lock"
            lock.write_bytes(LOCAL_LOCK)
            expected = digest(LOCAL_LOCK)
            lock.write_bytes(LOCAL_LOCK + b"# patched after the hint was selected\n")
            output = root / "staging"

            with patch.object(vendor, "load_toml", side_effect=AssertionError("parsed")), \
                 patch.object(vendor.mp, "Pool", side_effect=AssertionError("workers")), \
                 patch.object(vendor, "download_git_tree", side_effect=AssertionError("git")), \
                 patch.object(vendor.urllib.request, "urlopen", side_effect=AssertionError("network")), \
                 self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                vendor.create_vendor_staging(lock, output, expected_lock_sha256=expected)

            self.assertFalse(output.exists())

    def test_changed_cached_stage_lock_refuses_before_output_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            stage.mkdir()
            (stage / "Cargo.lock").write_bytes(LOCAL_LOCK + b"# stale cached stage\n")
            output = root / "vendor"

            for preexisting in (False, True):
                with self.subTest(preexisting=preexisting):
                    if preexisting:
                        output.mkdir()
                        (output / "sentinel").write_bytes(b"unchanged")
                    with patch.object(vendor, "load_toml", side_effect=AssertionError("parsed")), \
                         patch.object(vendor.shutil, "copy", side_effect=AssertionError("copied")), \
                         patch.object(vendor.subprocess, "check_call", side_effect=AssertionError("process")), \
                         self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                        vendor.create_vendor(stage, output, expected_lock_sha256=digest(LOCAL_LOCK))
                    if preexisting:
                        self.assertEqual(tree_bytes(output), {"sentinel": b"unchanged"})
                    else:
                        self.assertFalse(output.exists())

    def test_malformed_digests_refuse_before_reading_missing_input(self):
        invalid = ("", "0" * 63, "0" * 65, "g" * 64, " " + "0" * 64, "0x" + "0" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for action in (vendor.create_vendor_staging, vendor.create_vendor):
                for expected in invalid:
                    with self.subTest(action=action.__name__, expected=expected):
                        with patch.object(Path, "read_bytes", side_effect=AssertionError("input read")), \
                             self.assertRaisesRegex(ValueError, "64 hexadecimal"):
                            action(root / "missing", root / "output", expected_lock_sha256=expected)
                        self.assertFalse((root / "output").exists())

    def test_guarded_stages_parse_and_copy_the_same_verified_snapshot(self):
        original = vendor.verified_lockfile_bytes
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for final_stage in (False, True):
                with self.subTest(final_stage=final_stage):
                    source = root / str(final_stage)
                    source.mkdir()
                    lock = source / "Cargo.lock"
                    lock.write_bytes(LOCAL_LOCK)
                    output = root / (str(final_stage) + "-output")

                    def change_after_verification(path, expected):
                        checked = original(path, expected)
                        path.write_bytes(b"not TOML and not the hinted lockfile")
                        return checked

                    action = vendor.create_vendor if final_stage else vendor.create_vendor_staging
                    argument = source if final_stage else lock
                    with patch.object(vendor, "verified_lockfile_bytes", side_effect=change_after_verification), \
                         patch.object(vendor, "load_toml", side_effect=AssertionError("reread")):
                        action(argument, output, expected_lock_sha256=digest(LOCAL_LOCK).upper())
                    self.assertEqual((output / "Cargo.lock").read_bytes(), LOCAL_LOCK)

    def test_cli_preserves_positional_commands_and_accepts_optional_hash(self):
        for command, name in (("create-vendor-staging", "create_vendor_staging"),
                              ("create-vendor", "create_vendor")):
            with self.subTest(command=command):
                with patch.object(vendor, name) as action:
                    vendor.main([command, "input", "output"])
                    action.assert_called_once_with(Path("input"), Path("output"), expected_lock_sha256=None)
                with patch.object(vendor, name) as action:
                    vendor.main([command, "input", "output", "--expected-lock-sha256", "A" * 64])
                    action.assert_called_once_with(Path("input"), Path("output"), expected_lock_sha256="a" * 64)

    def test_cli_malformed_hash_never_dispatches(self):
        for command in ("create-vendor-staging", "create-vendor"):
            with self.subTest(command=command):
                with patch.object(vendor, "create_vendor_staging") as staging, \
                     patch.object(vendor, "create_vendor") as final, \
                     patch("sys.stderr", new_callable=io.StringIO), \
                     self.assertRaises(SystemExit) as error:
                    vendor.main([command, "input", "output", "--expected-lock-sha256", "bad"])
                self.assertEqual(error.exception.code, 2)
                staging.assert_not_called()
                final.assert_not_called()

    def test_git_sources_still_use_actual_cargo_metadata_route(self):
        revision = "0123456789abcdef0123456789abcdef01234567"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            tree = stage / "git" / revision
            tree.mkdir(parents=True)
            manifest = tree / "Cargo.toml"
            manifest.write_text('[package]\nname = "tiny-git"\nversion = "1.0.0"\n')
            (tree / "lib.rs").write_bytes(b"pub const GIT: bool = true;\n")
            lock = stage / "Cargo.lock"
            lock.write_text(
                'version = 4\n[[package]]\nname = "tiny-git"\nversion = "1.0.0"\n'
                f'source = "git+https://example.invalid/tiny?rev={revision}#{revision}"\n'
            )
            metadata = json.dumps({"packages": [{"name": "tiny-git", "manifest_path": str(manifest)}]}).encode()

            for guarded in (False, True):
                with self.subTest(guarded=guarded):
                    output = root / ("vendor-" + str(guarded))
                    arguments = {"expected_lock_sha256": digest(lock.read_bytes())} if guarded else {}
                    with patch.object(vendor.subprocess, "check_output", return_value=metadata) as process:
                        vendor.create_vendor(stage, output, **arguments)
                    process.assert_called_once_with([
                        "cargo", "metadata", "--format-version", "1", "--no-deps",
                        "--manifest-path", str(manifest),
                    ])
                    self.assertEqual((output / "source-git-0/tiny-git-1.0.0/lib.rs").read_bytes(),
                                     b"pub const GIT: bool = true;\n")
                    self.assertIn('git = "https://example.invalid/tiny"',
                                  (output / ".cargo/config.toml").read_text())

    def test_registry_tarball_outputs_are_identical_without_cargo(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, compressed, files = registry_fixture(root)
            snapshots = []
            for guarded in (False, True):
                with self.subTest(guarded=guarded):
                    stage = root / ("stage-" + str(guarded))
                    output = root / ("vendor-" + str(guarded))
                    arguments = {"expected_lock_sha256": digest(lock.read_bytes())} if guarded else {}
                    with patch.object(vendor.mp, "Pool", InlinePool), \
                         patch.object(vendor.urllib.request, "urlopen", side_effect=lambda *a, **k: ArchiveResponse(compressed)) as network, \
                         patch.object(vendor, "get_manifest_metadata", side_effect=AssertionError("cargo")), \
                         patch.object(vendor.subprocess, "check_output", side_effect=AssertionError("cargo")), \
                         patch.object(vendor.subprocess, "check_call", wraps=vendor.subprocess.check_call) as process:
                        vendor.create_vendor_staging(lock, stage, **arguments)
                        vendor.create_vendor(stage, output, **arguments)
                    self.assertEqual(network.call_count, 1)
                    self.assertEqual(process.call_count, 1)
                    self.assertEqual(process.call_args.args[0][0], "tar")
                    self.assertEqual((stage / "tarballs/tiny-1.0.0.tar.gz").read_bytes(), compressed)
                    crate = output / "source-registry-0/tiny-1.0.0"
                    for name, contents in files.items():
                        self.assertEqual((crate / name).read_bytes(), contents)
                    checksum = json.loads((crate / ".cargo-checksum.json").read_bytes())
                    self.assertEqual(checksum, {"files": {}, "package": digest(compressed)})
                    self.assertEqual(stat.S_IMODE((output / "Cargo.lock").stat().st_mode), 0o640)
                    snapshots.append(tree_bytes(output))
            self.assertEqual(snapshots[0], snapshots[1])

    def test_lock_guard_does_not_bypass_registry_archive_checksum(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, compressed, _ = registry_fixture(root)
            lock.write_text(lock.read_text().replace(digest(compressed), "0" * 64))
            with patch.object(vendor.mp, "Pool", InlinePool), \
                 patch.object(vendor.urllib.request, "urlopen", return_value=ArchiveResponse(compressed)), \
                 self.assertRaisesRegex(Exception, "Hash mismatch"):
                vendor.create_vendor_staging(lock, root / "stage", expected_lock_sha256=digest(lock.read_bytes()))


if __name__ == "__main__":
    unittest.main()
