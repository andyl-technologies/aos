"""Exercise runtime base identity, leases, publication, and eviction recovery."""

import json
import os
import tempfile
import unittest
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from unittest.mock import patch
import subprocess

from aos_test_driver.fs import clone_or_copy
from aos_test_driver.image_cache import _digest, _require_disk, materialize, prune


def _prune_repeatedly(cache):
    for _ in range(20):
        prune(Path(cache), 0, 0)


def _copy(arguments):
    source, target = arguments
    clone_or_copy(source, target)
    return Path(target).read_bytes()


class ImageCacheTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.cache = self.root / "cache"
        self.counter = self.root / "builds"

    def recipe(self, name="recipe", script=None, dependencies=()):
        recipe = self.root / name
        recipe.mkdir()
        if script is None:
            script = 'printf build >> "$COUNTER"; printf image > "$out/disk.img"'
        (recipe / "image-recipe.json").write_text(json.dumps({
            "schema": 1,
            "cache": str(self.cache),
            "shell": os.environ["CONFIG_SHELL"],
            "environment": {"PATH": os.environ["PATH"], "COUNTER": str(self.counter)},
            "dependencies": [str(path) for path in dependencies],
            "script": script,
        }))
        return recipe

    def test_repeat_and_eviction_rebuild_already_realized_recipe(self):
        recipe = self.recipe()
        for index in range(2):
            clone_or_copy(str(recipe / "disk.img"), str(self.root / f"run{index}"))
        self.assertEqual(self.counter.read_text(), "build")

        self.assertEqual(prune(self.cache, max_bytes=0, max_age=0), 1)
        clone_or_copy(str(recipe / "disk.img"), str(self.root / "after-prune"))
        self.assertEqual(self.counter.read_text(), "buildbuild")
        self.assertEqual((self.root / "after-prune").read_bytes(), b"image")

    def test_disk_guard_uses_longest_mount_including_disk_bind_under_run(self):
        mounts = (
            "1 0 0:1 / / rw - zfs pool rw\n"
            "2 1 0:2 / /run rw - tmpfs tmpfs rw\n"
            "3 2 0:1 /cache /run/image-cache rw - zfs pool rw\n"
        )
        with patch.object(Path, "read_text", return_value=mounts):
            _require_disk(Path("/run/image-cache/base"))
            _require_disk(Path("/tmp/assembly"))
            with self.assertRaisesRegex(ValueError, "disk-backed"):
                _require_disk(Path("/run/assembly"))

    def test_corruption_and_incomplete_publication_rebuild(self):
        recipe = self.recipe()
        with materialize(recipe) as base:
            image = base / "disk.img"
        image.chmod(0o644)
        image.write_bytes(b"wrong")
        with materialize(recipe) as base:
            self.assertEqual((base / "disk.img").read_bytes(), b"image")
        (base / "image-integrity.json").unlink()
        with materialize(recipe) as base:
            self.assertEqual((base / "disk.img").read_bytes(), b"image")
        self.assertEqual(self.counter.read_text(), "buildbuildbuild")

    def test_lease_protects_base_and_lock_inode_survives_eviction(self):
        recipe = self.recipe()
        with materialize(recipe) as base:
            lock = self.cache / "locks" / base.name
            inode = lock.stat().st_ino
            self.assertEqual(prune(self.cache, 0, 0), 0)
            self.assertTrue(base.exists())
        self.assertEqual(prune(self.cache, 0, 0), 1)
        self.assertEqual(lock.stat().st_ino, inode)

    def test_concurrent_copies_materialize_once(self):
        recipe = self.recipe()
        arguments = [(str(recipe / "disk.img"), str(self.root / f"copy-{i}")) for i in range(4)]
        with ProcessPoolExecutor(max_workers=4) as pool:
            self.assertEqual(list(pool.map(_copy, arguments)), [b"image"] * 4)
        self.assertEqual(self.counter.read_text(), "build")

    def test_dependency_is_leased_until_parent_finishes(self):
        dependency = self.recipe("dependency")
        parent = self.recipe("parent", script=f'cp "{dependency}/disk.img" "$out/disk.img"', dependencies=[dependency])
        original_run = subprocess.run

        def run_with_prune(*args, **kwargs):
            command = Path(args[0][1]).read_text()
            if 'cp "' in command:
                self.assertEqual(prune(self.cache, 0, 0), 0)
            return original_run(*args, **kwargs)

        with patch("aos_test_driver.image_cache.subprocess.run", side_effect=run_with_prune):
            with materialize(parent) as base:
                self.assertEqual((base / "disk.img").read_bytes(), b"image")
        self.assertEqual(self.counter.read_text(), "build")

    def test_failed_materialization_is_never_published(self):
        recipe = self.recipe(script='printf partial > "$out/disk.img"; exit 7')
        with self.assertRaises(Exception):
            with materialize(recipe):
                self.fail("failed builder yielded a base")
        self.assertEqual(list((self.cache / "entries").iterdir()), [])
        self.assertEqual(list((self.cache / "staging").iterdir()), [])

    def test_changed_recipe_has_distinct_base(self):
        first = self.recipe("first")
        second = self.recipe("second", script='printf other > "$out/disk.img"')
        with materialize(first) as left, materialize(second) as right:
            self.assertNotEqual(left, right)

    def test_concurrent_prune_and_materialize(self):
        recipe = self.recipe()
        # Seed directories before racing maintenance with consumer leases.
        with materialize(recipe):
            pass
        with ProcessPoolExecutor(max_workers=5) as pool:
            maintenance = pool.submit(_prune_repeatedly, str(self.cache))
            arguments = [(str(recipe / "disk.img"), str(self.root / f"racing-{i}")) for i in range(12)]
            self.assertEqual(list(pool.map(_copy, arguments)), [b"image"] * 12)
            maintenance.result()

    def test_abandoned_staging_is_reclaimed_but_active_staging_is_kept(self):
        recipe = self.recipe()
        with materialize(recipe) as base:
            active = self.cache / "staging" / (base.name + "-active")
            abandoned = self.cache / "staging" / ("a" * 64 + "-abandoned")
            active.mkdir()
            abandoned.mkdir()
            (abandoned / "large-tree").write_bytes(b"scratch")
            prune(self.cache)
            self.assertTrue(active.exists())
            self.assertFalse(abandoned.exists())
        prune(self.cache)
        self.assertFalse(active.exists())

    def test_digest_detects_changes_in_holes(self):
        image = self.root / "sparse"
        with image.open("wb") as stream:
            stream.truncate(8 * 1024**2)
        before = _digest(image)
        with image.open("r+b") as stream:
            stream.seek(4 * 1024**2 + 7)
            stream.write(b"modified hole")
        self.assertNotEqual(_digest(image), before)
