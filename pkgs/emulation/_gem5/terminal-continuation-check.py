# SPDX-License-Identifier: MIT
"""Reconstructs held Terminal bytes with the entire original namespace absent."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys


MAX_RESULT_BYTES = 4 * 1024 * 1024
MAX_PRIMARY_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_FILES = 4096


def checked_file(path, maximum):
    """Checks the same no-follow regular descriptor used for every bounded read."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid() or not 0 <= metadata.st_size <= maximum
    ):
        os.close(descriptor)
        raise ValueError("terminal fixture file exceeds private regular-file credit")
    return descriptor, metadata


def fingerprint(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_nlink)


def read_result(path):
    descriptor, before = checked_file(path, MAX_RESULT_BYTES)
    with os.fdopen(descriptor, "rb") as source:
        data = source.read(MAX_RESULT_BYTES + 1)
        after = os.fstat(source.fileno())
    if len(data) > MAX_RESULT_BYTES or len(data) != before.st_size or fingerprint(before) != fingerprint(after):
        raise ValueError("terminal result changed or exceeded preflight credit")
    return json.loads(data)


def file_census(paths, maximum, total_limit=MAX_TOTAL_BYTES):
    bounded = []
    for path in paths:
        if len(bounded) >= MAX_FILES:
            raise ValueError("terminal fixture file-count credit exhausted before copy")
        bounded.append(path)
    paths = sorted(bounded, key=lambda path: path.name)
    total = 0
    census = []
    for path in paths:
        descriptor, metadata = checked_file(path, maximum)
        os.close(descriptor)
        total += metadata.st_size
        if total > total_limit:
            raise ValueError("terminal fixture total byte credit exhausted before copy")
        census.append((path, metadata))
    return census, total


def copy_checked(source, destination, original, maximum, mode=0o400):
    """Copies from one stable measured descriptor into a fresh exclusive file."""
    descriptor, before = checked_file(source, maximum)
    try:
        if fingerprint(before) != fingerprint(original):
            raise ValueError("terminal fixture source changed since bounded preflight")
        target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(descriptor, "rb", closefd=False) as reader, os.fdopen(target, "wb") as writer:
            digest = hashlib.sha256()
            copied = 0
            while part := reader.read(1024 * 1024):
                copied += len(part)
                if copied > before.st_size:
                    raise ValueError("terminal fixture copy exceeded preflight extent")
                digest.update(part)
                writer.write(part)
            after = os.fstat(descriptor)
            if copied != before.st_size or fingerprint(before) != fingerprint(after):
                raise ValueError("terminal fixture copy source changed")
            writer.flush()
            os.fchmod(writer.fileno(), mode)
            os.fsync(writer.fileno())
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def tree_census(directory):
    """Preflights the entire finite resource tree before allocating its copy."""
    pending = [(directory, 0)]
    files = []
    directories = []
    members = 0
    while pending:
        parent, depth = pending.pop()
        if depth > 32:
            raise ValueError("terminal fixture resource depth credit exhausted")
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError("terminal fixture resource directory is symbolic or unowned")
        directories.append(parent)
        for child in parent.iterdir():
            members += 1
            if members > MAX_FILES:
                raise ValueError("terminal fixture resource census exceeds finite credit")
            metadata = child.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((child, depth + 1))
            else:
                files.append(child)
    census, total = file_census(files, MAX_FILE_BYTES)
    return directories, census, total


def copy_tree(directory, target, directories, census):
    target.mkdir(mode=0o700)
    for child in sorted(directories, key=lambda path: len(path.parts)):
        if child != directory:
            (target / child.relative_to(directory)).mkdir(mode=0o700)
    for leaf, metadata in census:
        copy_checked(leaf, target / leaf.relative_to(directory), metadata, MAX_FILE_BYTES, mode=0o600)


gem5, dmtcp, guard, script, directory = sys.argv[1:6]
model_arguments = sys.argv[6:]
root = Path(directory).resolve()
root.mkdir(mode=0o700)
source = root / "source"
source.mkdir(mode=0o700)
resource = source / "resources"
resource.mkdir(mode=0o700)
images = source / "images"
images.mkdir(mode=0o700)
temporary = source / "tmp"
temporary.mkdir(mode=0o700)
owner = resource / "terminal-owner.py"
shutil.copyfile(script, owner)
owner.chmod(0o600)


def digest(path):
    descriptor, before = checked_file(path, MAX_PRIMARY_BYTES)
    with os.fdopen(descriptor, "rb") as stream:
        digest = hashlib.sha256()
        consumed = 0
        while part := stream.read(1024 * 1024):
            consumed += len(part)
            if consumed > before.st_size:
                raise ValueError("terminal fixture digest exceeded preflight extent")
            digest.update(part)
        after = os.fstat(stream.fileno())
        if consumed != before.st_size or fingerprint(before) != fingerprint(after):
            raise ValueError("terminal fixture digest source changed")
        return digest.hexdigest()


def execute(command, environment, cwd, log):
    with log.open("wb") as output:
        child = subprocess.Popen(command, env=environment, cwd=cwd,
                                 stdout=output, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            status = child.wait(timeout=180)
            if status != 0:
                raise AssertionError(log.read_text(errors="replace"))
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=10)


environment = os.environ.copy()
environment["CRUCIBLE_CAPTURE_RESOURCE_ROOT"] = str(resource)
execute([str(Path(dmtcp) / "bin/dmtcp_launch"), "--new-coordinator", "--coord-port", "0",
         "--interval", "0", "--no-gzip", "--with-plugin", guard,
         "--ckptdir", str(images), "--tmpdir", str(temporary),
         gem5, "--listener-mode=off", f"--outdir={resource / 'output'}", str(owner),
         str(resource), *model_arguments],
        environment, temporary, resource / "native.log")
expected = read_result(resource / "terminal-result.json")
image_files = list(images.glob("*.dmtcp"))
assert len(image_files) == 1
primary = image_files[0]
primary_census, primary_size = file_census([primary], MAX_PRIMARY_BYTES)
primary_digest = digest(primary)
supplementary = primary.with_name(primary.stem + "_files")
assert supplementary.is_dir() and not supplementary.is_symlink()
saved_census, saved_size = file_census(supplementary.iterdir(), MAX_FILE_BYTES)
assert saved_census
directories, resource_census, resource_size = tree_census(resource)
if primary_size + saved_size + resource_size > MAX_TOTAL_BYTES:
    raise ValueError("terminal fixture complete source-copy credit exhausted")
archive = root / "archive"
archive.mkdir(mode=0o700)
historical = archive / primary.name
assert copy_checked(primary, historical, primary_census[0][1], MAX_PRIMARY_BYTES) == primary_digest
saved = archive / supplementary.name
saved.mkdir(mode=0o700)
records = []
for leaf, metadata in saved_census:
    destination = saved / leaf.name
    sha256 = copy_checked(leaf, destination, metadata, MAX_FILE_BYTES)
    records.append((leaf.name, metadata.st_size, sha256))
preserved = root / "preserved"
copy_tree(resource, preserved, directories, resource_census)
shutil.rmtree(source)
assert not source.exists()


def reconstruct(name):
    branch = root / name
    directories, census, _ = tree_census(preserved)
    copy_tree(preserved, branch, directories, census)
    (branch / "terminal-result.json").unlink()
    imported = root / f"saved-{name}"
    imported.mkdir(mode=0o700)
    manifest = root / f"roster-{name}"
    lines = ["crucible-saved-files-v1", str(supplementary), str(imported)]
    saved_census, _ = file_census(saved.iterdir(), MAX_FILE_BYTES)
    measured = {path.name: metadata for path, metadata in saved_census}
    assert set(measured) == {leaf for leaf, _, _ in records}
    for leaf, size, sha256 in records:
        destination = imported / leaf
        assert copy_checked(saved / leaf, destination, measured[leaf], MAX_FILE_BYTES) == sha256
        assert destination.stat().st_ino != (saved / leaf).stat().st_ino
        lines.append(f"{sha256}\t{size}\t{leaf}")
    manifest.write_text("\n".join(lines) + "\n")
    manifest.chmod(0o400)
    scratch = root / f"tmp-{name}"
    scratch.mkdir(mode=0o700)
    fresh_images = root / f"images-{name}"
    fresh_images.mkdir(mode=0o700)
    environment = os.environ.copy()
    environment.update({"CRUCIBLE_RESTORE_RESOURCE_ROOT": str(branch),
                        "CRUCIBLE_GEM5_OPERATIONAL_ROOT": str(scratch),
                        "DMTCP_PATH_MAPPING": f"{resource}:{branch}",
                        "CRUCIBLE_RESTORE_SAVED_FILES_SOURCE_ROOT": str(supplementary),
                        "CRUCIBLE_RESTORE_SAVED_FILES_TARGET_ROOT": str(imported),
                        "CRUCIBLE_RESTORE_SAVED_FILES_MANIFEST": str(manifest)})
    execute([str(Path(dmtcp) / "bin/dmtcp_restart"), "--new-coordinator", "--coord-port", "0",
             "--interval", "0", "--ckptdir", str(fresh_images),
             "--tmpdir", str(scratch), str(historical)],
            environment, scratch, root / f"{name}.log")
    actual = read_result(branch / "terminal-result.json")
    assert actual == expected and not source.exists()
    assert digest(historical) == primary_digest
    return {"name": name, "held_fifo_and_future_event_unchanged": True,
            "original_namespace_absent": True}


with ThreadPoolExecutor(max_workers=2) as pool:
    branches = list(pool.map(reconstruct, ("child-a", "child-b")))
result = {"schema": "crucible.gem5.terminal-image-mechanism.v1",
          "source_exited": True, "original_namespace_absent": True,
          "image_sha256": primary_digest, "branches": branches,
          "terminal": expected, "full_system_qualified": False,
          "complete_process_closure_qualified": False}
(root / "result.json").write_text(json.dumps(result, sort_keys=True) + "\n")
print(json.dumps(result, sort_keys=True))
