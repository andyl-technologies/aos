# SPDX-License-Identifier: MIT
"""Exercises complete archive preflight and manifest credit before allocation."""

import importlib.util
from pathlib import Path
import types
import unittest


spec = importlib.util.spec_from_file_location(
    'device_archive_custody', Path(__file__).with_name('device-archive-custody.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeImage:
    def __init__(self):
        self.hashes = []
        self.files = [(Path('/private/saved/leaf'), types.SimpleNamespace(st_size=1))]
        self.saved_bytes = 1
        self.resource_bytes = 1

    def checked_file(self, path):
        # Duplicate an existing owned descriptor; the preflight must close it.
        import os
        return os.open(__file__, os.O_RDONLY), types.SimpleNamespace(st_size=1)

    def census(self, root):
        if root == Path('/private/saved'):
            return [], self.files, self.saved_bytes
        return [], [], self.resource_bytes

    def digest(self, path):
        self.hashes.append(path)
        return 'a' * 64


class ArchiveTests(unittest.TestCase):
    def test_combined_image_saved_resource_credit_is_checked(self):
        image = FakeImage()
        image.saved_bytes = module.MAX_ARCHIVE_BYTES - 1
        with self.assertRaises(ValueError):
            module.preflight_archive(image, Path('/primary'), Path('/private/saved'), Path('/resource'))
        self.assertFalse(image.hashes)

    def test_combined_leaf_count_precedes_copying(self):
        image = FakeImage()
        image.files *= module.MAX_ARCHIVE_FILES
        with self.assertRaises(ValueError):
            module.preflight_archive(image, Path('/primary'), Path('/private/saved'), Path('/resource'))

    def test_nested_saved_leaf_refused_before_copying_or_hashing(self):
        image = FakeImage()
        image.files = [(Path('/private/saved/nested/leaf'), types.SimpleNamespace(st_size=1))]
        with self.assertRaises(ValueError):
            module.saved_manifest(image, Path('/gone/saved'), Path('/private/saved'))
        self.assertFalse(image.hashes)

    def test_ambiguous_basename_refused_before_hashing(self):
        image = FakeImage()
        image.files = [(Path('/private/saved/ambiguous\tleaf'), types.SimpleNamespace(st_size=1))]
        with self.assertRaises(ValueError):
            module.saved_manifest(image, Path('/gone/saved'), Path('/private/saved'))
        self.assertFalse(image.hashes)

    def test_manifest_row_credit_refused_before_hashing(self):
        image = FakeImage()
        image.files = [(Path('/private/saved/' + 'x' * module.MAX_MANIFEST_BYTES), types.SimpleNamespace(st_size=1))]
        with self.assertRaises(ValueError):
            module.saved_manifest(image, Path('/gone/saved'), Path('/private/saved'))
        self.assertFalse(image.hashes)

    def test_ambiguous_or_relative_original_root_refused_before_hashing(self):
        for source in (Path('relative/saved'), Path('/gone/ambiguous\nroot')):
            image = FakeImage()
            with self.assertRaises(ValueError):
                module.saved_manifest(image, source, Path('/private/saved'))
            self.assertFalse(image.hashes)

    def test_empty_roster_does_not_bypass_prefix_credit(self):
        image = FakeImage()
        image.files = []
        with self.assertRaises(ValueError):
            module.saved_manifest(image, Path('/' + 'x' * module.MAX_MANIFEST_BYTES), Path('/private/saved'))
        self.assertFalse(image.hashes)

    def test_complete_named_roster_is_original_and_sorted(self):
        image = FakeImage()
        actual = module.saved_manifest(image, Path('/gone/saved'), Path('/private/saved'))
        expected = 'crucible-saved-files-v1\n/gone/saved\n/private/saved\n' + 'a' * 64 + '\t1\tleaf\n'
        self.assertEqual(actual, expected.encode())
        self.assertEqual(image.hashes, [Path('/private/saved/leaf')])


class FuturePathTests(unittest.TestCase):
    def test_exact_original_to_fresh_mapping_never_reads_deleted_root(self):
        self.assertEqual(module.future_path_mapping(Path('/gone/source/resources'),
                                                    Path('/private/child/resources')),
                         '/gone/source/resources:/private/child/resources')

    def test_same_and_nested_roots_are_refused(self):
        for target in ('/gone/source', '/gone/source/child', '/gone'):
            with self.assertRaises(ValueError):
                module.future_path_mapping(Path('/gone/source'), Path(target))

    def test_ambiguous_roots_are_refused(self):
        for source in ('relative', '/gone/a:b', '/gone/a\nroot', '/gone/../source'):
            with self.assertRaises(ValueError):
                module.future_path_mapping(Path(source), Path('/private/child'))

    def test_native_root_buffer_is_bounded_before_restart(self):
        with self.assertRaises(ValueError):
            module.future_path_mapping(Path('/' + 'x' * 4095), Path('/private/child'))


if __name__ == '__main__':
    unittest.main()
