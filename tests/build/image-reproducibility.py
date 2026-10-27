"""Compare independent ordinary builds and cold runtime reconstructions."""

import argparse
import filecmp
import importlib.util
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from aos_test_driver import image_cache
from aos_test_driver.fs import _clone_or_copy


def equal(first, second):
    assert filecmp.cmp(first, second, shallow=False), (first, second)
    print(f"byte-identical: {first} == {second}", flush=True)


def uuid(path):
    return subprocess.check_output(["blkid", "-p", "-s", "UUID", "-o", "value", str(path)], text=True).strip()


def local_recipe(source, root):
    """Remap test cache locations while retaining exact generated builders."""
    target = root / source.name
    if target.exists():
        return target
    target.mkdir(parents=True)
    text = (source / "image-recipe.json").read_text()
    for dependency in json.loads(text)["dependencies"]:
        text = text.replace(dependency, str(local_recipe(Path(dependency), root)))
    recipe = json.loads(text)
    recipe["cache"] = str(root / "cache")
    (target / "image-recipe.json").write_text(json.dumps(recipe))
    return target


def cold_rebuild(source, expected, name):
    root = Path.cwd() / name
    recipe = local_recipe(source, root)
    copies = []
    for run in range(2):
        # Different TMPDIRs and wall-clock seconds exercise independent staging.
        scratch = root / f"scratch-{run}"
        scratch.mkdir()
        tempfile.tempdir = str(scratch)
        with image_cache.materialize(recipe) as materialized:
            result = root / f"cold-{run}.img"
            _clone_or_copy(str(materialized / expected.name), str(result))
            copies.append(result)
        assert image_cache.prune(root / "cache", max_bytes=0, max_age=0) > 0
        time.sleep(1)
    equal(copies[0], copies[1])
    equal(copies[0], expected)


def main():
    parser = argparse.ArgumentParser()
    for name in ("root", "root-again", "changed", "shrunk", "shrunk-again", "erofs", "erofs-again", "recipe", "disk", "disk-again", "disk-recipe", "input", "input-again", "headless", "headless-recipe", "metadata"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()

    for first, second, image in ((args.root, args.root_again, "root.img"), (args.shrunk, args.shrunk_again, "root.img"), (args.erofs, args.erofs_again, "root.img"), (args.disk, args.disk_again, "disk.img"), (args.input, args.input_again, "test.img")):
        equal(first / image, second / image)
    assert uuid(args.root / "root.img") != uuid(args.changed / "root.img")
    assert not filecmp.cmp(args.root / "root.img", args.changed / "root.img", shallow=False)

    for path, entry in ((args.root / "root.img", "/payload"), (args.input / "test.img", "/test")):
        details = subprocess.check_output(["debugfs", "-R", f"stat {entry}", str(path)], text=True)
        assert "User:     0   Group:     0" in details, details
        assert "0x00000001" in details, details
    details = subprocess.check_output(["debugfs", "-R", "stat /payload", str(args.root / "root.img")], text=True)
    assert "Mode:  0640" in details, details
    hardlink = subprocess.check_output(["debugfs", "-R", "stat /payload-hardlink", str(args.root / "root.img")], text=True)
    assert details.splitlines()[0].split()[1] == hardlink.splitlines()[0].split()[1]

    table = json.loads(subprocess.check_output(["sfdisk", "--json", str(args.disk / "disk.img")], text=True))["partitiontable"]
    ids = [table["id"]] + [partition["uuid"] for partition in table["partitions"]]
    assert len(ids) == len(set(ids)) == 7
    assert [partition["name"] for partition in table["partitions"]] == ["boot", "root-a", "root-b", "swap", "aos-provenance-fallback-v1", "var"]

    # Never follow a staging symlink into the immutable store.
    spec = importlib.util.spec_from_file_location("image_metadata", args.metadata)
    metadata = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(metadata)
    tree = Path("normalization")
    tree.mkdir()
    (tree / "data").write_bytes(b"payload")
    (tree / "data").chmod(0o640)
    os.link(tree / "data", tree / "hardlink")
    source = args.metadata.stat()
    (tree / "store-link").symlink_to(args.metadata)
    before = (tree / "data").stat()
    first = metadata.tree_identity(tree, "fixture")
    assert first == metadata.tree_identity(tree, "fixture")
    after = (tree / "data").stat()
    assert (before.st_mode, before.st_uid, before.st_gid, before.st_ino) == (after.st_mode, after.st_uid, after.st_gid, after.st_ino)
    assert args.metadata.stat().st_mtime_ns == source.st_mtime_ns
    assert (tree / "store-link").is_symlink()
    assert os.readlink(tree / "store-link") == str(args.metadata)
    assert (tree / "store-link").lstat().st_mtime_ns == 1_000_000_000
    assert (tree / "hardlink").stat().st_ino == after.st_ino
    (tree / "data").write_bytes(b"changed")
    assert first != metadata.tree_identity(tree, "fixture")

    # GNU cp removes ambient Nix-store optimization links at image boundaries.
    for linked in (False, True):
        source_tree = Path(f"source-{linked}")
        source_tree.mkdir()
        (source_tree / "one").write_bytes(b"same")
        if linked:
            os.link(source_tree / "one", source_tree / "two")
        else:
            (source_tree / "two").write_bytes(b"same")
        destination = Path(f"copy-{linked}")
        subprocess.run(["cp", "-a", "--no-preserve=links", str(source_tree), str(destination)], check=True)
        assert (destination / "one").stat().st_ino != (destination / "two").stat().st_ino
    assert metadata.tree_identity(Path("copy-False"), "copy") == metadata.tree_identity(Path("copy-True"), "copy")
    assert metadata.tree_size(Path("copy-True")) == 8

    cold_rebuild(args.recipe, args.root / "root.img", "runtime-root")
    cold_rebuild(args.disk_recipe, args.disk / "disk.img", "runtime-disk")
    cold_rebuild(args.headless_recipe, args.headless / "root.img", "runtime-headless")
    print("reproducibility, ownership, timestamps, identifiers, layout, and cold reconstruction: PASS")


if __name__ == "__main__":
    main()
