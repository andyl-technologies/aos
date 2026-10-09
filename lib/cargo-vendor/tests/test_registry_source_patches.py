"""UNRUN data-fixture regressions for exact stage-2 registry source delivery.

Positive application tests require AOS_TEST_PATCH to name the source-built AOS
patch executable. There is no PATH/host-tool fallback. Archive and source
fixtures below are synthetic DATA, not upstream-provider digests or authority.
"""

import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HELPER = Path(__file__).parents[1] / "registry-source-patches.py"
SPEC = importlib.util.spec_from_file_location("registry_source_patches", HELPER)
patches = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(patches)


def sha256(value):
    return hashlib.sha256(value).hexdigest()


class RegistrySourcePatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.staging = self.root / "staging"
        self.vendor = self.root / "vendor"
        self.crate = self.vendor / "source-registry-0" / "fixture-1.0.0"
        self.crate.mkdir(parents=True)
        (self.staging / "tarballs").mkdir(parents=True)
        self.original = {
            "Cargo.toml": b'[package]\nname = "fixture"\nversion = "1.0.0"\n',
            "src/lib.rs": b"old\n",
            "src/other.rs": b"unchanged\n",
            "README": b"readme\n",
        }
        archive = self.staging / "tarballs" / "fixture-1.0.0.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for path, content in self.original.items():
                entry = tarfile.TarInfo("fixture-1.0.0/" + path)
                entry.mode = 0o644
                entry.size = len(content)
                output.addfile(entry, io.BytesIO(content))
                destination = self.crate / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                destination.chmod(0o644)

        self.archive_sha = sha256(archive.read_bytes())
        lock = (
            'version = 3\n[[package]]\nname = "fixture"\nversion = "1.0.0"\n'
            f'source = "{patches.REGISTRY}"\nchecksum = "{self.archive_sha}"\n'
        )
        (self.staging / "Cargo.lock").write_text(lock)
        (self.vendor / "Cargo.lock").write_text(lock)
        (self.crate / patches.CHECKSUM).write_text(
            json.dumps({"files": {}, "package": self.archive_sha})
        )
        self.patch = self.root / "fixture.patch"
        self.patch.write_bytes(b"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n")
        self.record = {
            "source": patches.REGISTRY,
            "name": "fixture",
            "version": "1.0.0",
            "archiveSha256": self.archive_sha,
            "patch": str(self.patch),
            "patchSha256": sha256(self.patch.read_bytes()),
            "files": [
                {
                    "path": "src/lib.rs",
                    "beforeSha256": sha256(b"old\n"),
                    "afterSha256": sha256(b"new\n"),
                }
            ],
        }

    def patch_tool(self):
        value = os.environ.get("AOS_TEST_PATCH")
        self.assertIsNotNone(value, "AOS_TEST_PATCH must name the source-built AOS patch tool")
        return Path(value)

    def prepare(self, record=None):
        selected = self.record if record is None else record
        lock = {
            "package": [
                {
                    "source": patches.REGISTRY,
                    "name": "fixture",
                    "version": "1.0.0",
                    "checksum": self.archive_sha,
                }
            ]
        }
        return patches.selected_crate(self.staging, self.vendor, selected, lock)

    def set_patch(self, content):
        self.patch.write_bytes(content)
        self.record["patchSha256"] = sha256(content)

    def test_empty_recipe_does_not_inspect_paths_or_invoke_patch(self):
        with mock.patch.object(patches.subprocess, "run") as invoke:
            patches.apply_patches(
                Path("/missing/staging"),
                Path("/missing/vendor"),
                [],
                Path("/missing/patch"),
            )

        invoke.assert_not_called()
        self.assertFalse((self.vendor / patches.RECEIPT).exists())
        self.assertEqual((self.crate / "src/lib.rs").read_bytes(), b"old\n")

    def test_real_patch_preserves_archive_and_unselected_files_with_full_checksums(self):
        before_lock = (self.staging / "Cargo.lock").read_bytes()
        unselected = self.vendor / "source-registry-0" / "unselected-2.0.0"
        unselected.mkdir()
        (unselected / "keep").write_bytes(b"unselected")
        git_source = self.vendor / "source-git-0"
        git_source.mkdir()
        (git_source / "keep").write_bytes(b"git-source")

        patches.apply_patches(self.staging, self.vendor, [self.record], self.patch_tool())

        self.assertEqual((self.crate / "src/lib.rs").read_bytes(), b"new\n")
        self.assertEqual((self.crate / "src/other.rs").read_bytes(), b"unchanged\n")
        self.assertEqual((unselected / "keep").read_bytes(), b"unselected")
        self.assertEqual((git_source / "keep").read_bytes(), b"git-source")
        self.assertEqual((self.staging / "Cargo.lock").read_bytes(), before_lock)
        self.assertEqual(
            sha256((self.staging / "tarballs/fixture-1.0.0.tar.gz").read_bytes()),
            self.archive_sha,
        )
        checksum = json.loads((self.crate / patches.CHECKSUM).read_text())
        self.assertEqual(checksum["package"], self.archive_sha)
        self.assertEqual(list(checksum["files"]), sorted(self.original))
        self.assertEqual(
            checksum["files"],
            {
                path: sha256((self.crate / path).read_bytes())
                for path in sorted(self.original)
            },
        )
        receipt = json.loads((self.vendor / patches.RECEIPT).read_text())
        self.assertEqual(
            receipt,
            {"schema": "aos.registry-source-patches/v1", "patches": [self.record]},
        )

    def test_optimized_immutable_inputs_retain_identity_and_real_application(self):
        inputs = (
            self.patch,
            self.staging / "Cargo.lock",
            self.staging / "tarballs/fixture-1.0.0.tar.gz",
        )
        original_hashes = {}
        for index, source in enumerate(inputs):
            original_hashes[source] = sha256(source.read_bytes())
            os.link(source, self.root / ("immutable-link-" + str(index)))
            self.assertGreater(source.stat().st_nlink, 1)
            self.assertEqual(patches.file_hash(source), original_hashes[source])

        recipe = self.root / "immutable-recipe.json"
        recipe.write_text(json.dumps([self.record]))
        os.link(recipe, self.root / "immutable-recipe-link.json")
        records = patches.load_json(recipe, patches.MAXIMUM_RECIPE_BYTES)

        patches.apply_patches(self.staging, self.vendor, records, self.patch_tool())

        self.assertEqual((self.crate / "src/lib.rs").read_bytes(), b"new\n")
        for source in inputs:
            self.assertEqual(sha256(source.read_bytes()), original_hashes[source])

    def test_writable_vendor_lock_still_rejects_hardlinks_before_patch(self):
        os.link(self.vendor / "Cargo.lock", self.root / "mutable-lock-link")

        with mock.patch.object(patches.subprocess, "run") as invoke:
            with self.assertRaises(patches.PatchContractError):
                patches.apply_patches(
                    self.staging, self.vendor, [self.record], self.patch_tool()
                )

        invoke.assert_not_called()
        self.assertFalse((self.vendor / patches.RECEIPT).exists())

    def test_lf_only_lines_preserve_all_other_bytes_and_final_unterminated_data(self):
        cases = (
            (b"", []),
            (b"\n", [b"\n"]),
            (b"one\n\ntwo", [b"one\n", b"\n", b"two"]),
            (b"one\r\v\ftwo\nlast", [b"one\r\v\ftwo\n", b"last"]),
        )
        for data, expected in cases:
            with self.subTest(data=data):
                self.assertEqual(patches.split_lf_lines(data), expected)

    def test_preflight_retains_payload_bytes_and_explicit_missing_final_lf(self):
        cases = (
            (
                b"old\vpart\fend\n",
                b"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n"
                b"-old\vpart\fend\n+new\vpart\fend\n",
            ),
            (
                b"old",
                b"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n"
                b"-old\n\\ No newline at end of file\n"
                b"+new\n\\ No newline at end of file\n",
            ),
        )
        for source, data in cases:
            with self.subTest(source=source):
                (self.crate / "src/lib.rs").write_bytes(source)
                before, _directories = patches.tree_snapshot(self.crate)

                patches.check_unified_patch(data, self.crate, self.record, before)

    def test_exact_identity_schema_and_duplicate_selection_are_required(self):
        for field, value in (
            ("source", "registry+https://foreign.invalid"),
            ("name", "../fixture"),
            ("version", "bad version"),
            ("archiveSha256", "0" * 64),
        ):
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                record[field] = value
                with self.assertRaises(patches.PatchContractError):
                    patches.validate_recipe([record])

        with self.assertRaises(patches.PatchContractError):
            patches.validate_recipe([self.record, self.record])
        record = copy.deepcopy(self.record)
        record["extra"] = True
        with self.assertRaises(patches.PatchContractError):
            patches.validate_recipe([record])

    def test_missing_and_ambiguous_lock_rows_never_select_by_version_alone(self):
        for rows in (
            [],
            [{"name": "fixture", "version": "1.0.0"}],
            [self.record, self.record],
        ):
            with self.subTest(rows=rows):
                with self.assertRaises(patches.PatchContractError):
                    patches.selected_crate(
                        self.staging, self.vendor, self.record, {"package": rows}
                    )

    def test_lock_and_archive_checksum_mismatches_are_rejected(self):
        record = copy.deepcopy(self.record)
        record["archiveSha256"] = sha256(b"different")
        with self.assertRaises(patches.PatchContractError):
            self.prepare(record)

        with (self.staging / "tarballs/fixture-1.0.0.tar.gz").open("ab") as archive:
            archive.write(b"extra")
        with self.assertRaises(patches.PatchContractError):
            self.prepare()

    def test_wrong_manifest_and_assembled_extra_are_rejected(self):
        (self.crate / "extra").write_bytes(b"extra")
        with self.assertRaises(patches.PatchContractError):
            self.prepare()
        (self.crate / "extra").unlink()
        (self.crate / "Cargo.toml").write_bytes(b'[package]\nname = "wrong"\nversion = "1.0.0"\n')
        with self.assertRaises(patches.PatchContractError):
            self.prepare()

    def test_unsafe_selected_paths_and_manifest_changes_are_rejected(self):
        for path in (
            "/absolute",
            "../escape",
            "src/../escape",
            "src\\escape",
            "src/\0escape",
            "src//lib.rs",
            "Cargo.toml",
            ".cargo/config.toml",
        ):
            with self.subTest(path=path):
                record = copy.deepcopy(self.record)
                record["files"][0]["path"] = path
                with self.assertRaises(patches.PatchContractError):
                    patches.validate_recipe([record])

    def test_symlink_hardlink_and_symlink_parent_are_rejected(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                extra = self.crate / "link"
                if kind == "symlink":
                    extra.symlink_to("src/lib.rs")
                else:
                    os.link(self.crate / "src/lib.rs", extra)
                with self.assertRaises(patches.PatchContractError):
                    patches.tree_snapshot(self.crate)
                extra.unlink()

        linked = self.root / "linked"
        linked.symlink_to(self.vendor, target_is_directory=True)
        with self.assertRaises(patches.PatchContractError):
            patches.tree_snapshot(linked / "source-registry-0/fixture-1.0.0")

    def test_before_and_patch_digest_mismatches_are_rejected(self):
        record = copy.deepcopy(self.record)
        record["files"][0]["beforeSha256"] = sha256(b"wrong")
        with self.assertRaises(patches.PatchContractError):
            self.prepare(record)

        root, before, directories = self.prepare()
        record = copy.deepcopy(self.record)
        record["patchSha256"] = sha256(b"wrong")
        with self.assertRaises(patches.PatchContractError):
            patches.apply_record(
                root, before, directories, record, Path("/unused/patch")
            )

    def test_create_delete_mode_binary_rename_extra_and_offset_patch_forms_are_rejected(self):
        root, before, _directories = self.prepare()
        bad_patches = [
            b"--- /dev/null\n+++ b/src/lib.rs\n@@ -0,0 +1 @@\n+new\n",
            b"--- a/src/lib.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n",
            b"diff --git a/src/lib.rs b/src/lib.rs\nold mode 100644\nnew mode 100755\n",
            b"GIT binary patch\nliteral 1\n",
            b"--- a/src/lib.rs\n+++ b/src/new.rs\n@@ -1 +1 @@\n-old\n+new\n",
            b"--- a/README\n+++ b/README\n@@ -1 +1 @@\n-readme\n+changed\n",
            b"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -2 +2 @@\n-old\n+new\n",
            b"--- a/../escape\n+++ b/../escape\n@@ -1 +1 @@\n-old\n+new\n",
        ]
        for data in bad_patches:
            with self.subTest(data=data):
                with self.assertRaises(patches.PatchContractError):
                    patches.check_unified_patch(data, root, self.record, before)

    def test_reported_fuzz_or_offset_is_never_accepted(self):
        root, before, directories = self.prepare()
        for diagnostic in (b"Hunk #1 succeeded at 2 (offset 1 line).", b"with fuzz 1"):
            result = subprocess.CompletedProcess([], 0, diagnostic, b"")
            with mock.patch.object(patches.subprocess, "run", return_value=result):
                with self.assertRaises(patches.PatchContractError):
                    patches.apply_record(
                        root, before, directories, self.record, Path("/unused/patch")
                    )

    def test_real_after_digest_mismatch_aborts_without_receipt(self):
        self.record["files"][0]["afterSha256"] = sha256(b"wrong")

        with self.assertRaises(patches.PatchContractError):
            patches.apply_patches(self.staging, self.vendor, [self.record], self.patch_tool())

        self.assertFalse((self.vendor / patches.RECEIPT).exists())

    def test_post_patch_extra_reject_and_mode_changes_are_detected(self):
        root, before, directories = self.prepare()
        for kind in ("extra", "reject", "mode", "unselected"):
            with self.subTest(kind=kind):
                def alter(*arguments, **keywords):
                    (root / "src/lib.rs").write_bytes(b"new\n")
                    if kind in ("extra", "reject"):
                        destination = root / (
                            "extra" if kind == "extra" else "src/lib.rs.rej"
                        )
                        destination.write_bytes(b"unexpected")
                    elif kind == "mode":
                        (root / "src/lib.rs").chmod(0o755)
                    else:
                        (root / "README").write_bytes(b"unexpected")
                    return subprocess.CompletedProcess([], 0, b"", b"")

                with mock.patch.object(patches.subprocess, "run", side_effect=alter):
                    with self.assertRaises(patches.PatchContractError):
                        patches.apply_record(
                            root, before, directories, self.record, Path("/unused/patch")
                        )
                for extra in (root / "extra", root / "src/lib.rs.rej"):
                    if extra.exists():
                        extra.unlink()
                for path, content in self.original.items():
                    (root / path).write_bytes(content)
                    (root / path).chmod(0o644)

    def test_duplicate_json_keys_cannot_hide_a_recipe_field(self):
        recipe = self.root / "recipe.json"
        recipe.write_text('{"patch":"first","patch":"second"}')

        with self.assertRaises(patches.PatchContractError):
            patches.load_json(recipe, patches.MAXIMUM_RECIPE_BYTES)


if __name__ == "__main__":
    unittest.main()
