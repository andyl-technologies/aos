"""Materialize development image recipes into bounded, reusable local bases.

Recipes contain resolved Nix closures, tools, environment, and assembly scripts.
Every consumer acquires a lease before resolving an image; an evicted base is
therefore rebuilt even when its recipe and test launcher are already realized.
Qualification builds never emit recipes or consult this module's cache.
"""

import argparse
import contextlib
import errno
import fcntl
import hashlib
import json
import logging
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterator

log = logging.getLogger(__name__)
_DEFAULT_BYTES = 100 * 1024**3
_DEFAULT_AGE = 14 * 86400


def _digest(path: Path) -> str:
    """Hash bytes and length, skipping holes without reading their zero bytes.

    Nonzero aligned blocks have a canonical representation independent of the
    filesystem's extent boundaries. This detects corrupt data, including writes
    into former holes, without streaming gigabytes of unallocated zero space.
    """
    digest = hashlib.sha256()
    size = path.stat().st_size
    digest.update(str(size).encode())
    block_size = 1024 * 1024

    with path.open("rb") as stream:
        offset = 0
        while offset < size:
            try:
                data = os.lseek(stream.fileno(), offset, os.SEEK_DATA)
            except OSError as error:
                if error.errno == errno.ENXIO:
                    break
                if error.errno not in (errno.EINVAL, errno.ENOTSUP):
                    raise
                data = offset

            offset = data // block_size * block_size
            stream.seek(offset)
            block = stream.read(block_size)
            if block.count(0) != len(block):
                digest.update(offset.to_bytes(8, "big"))
                digest.update(block)
            offset += len(block)

    return digest.hexdigest()


def _inventory(directory: Path) -> dict[str, str]:
    return {
        str(path.relative_to(directory)): _digest(path)
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path.name != "image-integrity.json"
    }


def _valid(entry: Path) -> bool:
    try:
        expected = json.loads((entry / "image-integrity.json").read_text())
        return bool(expected) and expected == _inventory(entry)
    except (OSError, ValueError):
        return False


def _allocated(entry: Path) -> int:
    total = 0
    for path in entry.rglob("*"):
        try:
            if path.is_file():
                total += path.stat().st_blocks * 512
        except FileNotFoundError:
            # Publication and eviction may race with status/accounting scans.
            continue
    return total


def _require_disk(path: Path) -> None:
    """Reject RAM-backed storage, including bind mounts below /run."""
    mountinfo = Path("/proc/self/mountinfo")
    if not mountinfo.exists():
        return

    location = str(path.resolve())
    selected_mount = (0, "")
    for line in mountinfo.read_text().splitlines():
        fields = line.split()
        mount = fields[4].replace("\\040", " ")
        if location == mount or location.startswith(mount.rstrip("/") + "/"):
            filesystem = fields[fields.index("-") + 1]
            selected_mount = max(selected_mount, (len(mount), filesystem))
    if selected_mount[1] in ("tmpfs", "ramfs"):
        raise ValueError("Image assembly and caches require disk-backed storage")


def _publish_files(source: Path, destination: Path) -> None:
    """Stage sparse images with directories removable by every build UID."""
    from .fs import _clone_or_copy

    destination.mkdir(mode=0o777)
    destination.chmod(0o777)
    for path in source.iterdir():
        target = destination / path.name
        if path.is_symlink():
            target.symlink_to(os.readlink(path))
        elif path.is_dir():
            _publish_files(path, target)
        else:
            _clone_or_copy(str(path), str(target))
            target.chmod(0o444)


@contextlib.contextmanager
def _publication_staging(cache: Path, key: str) -> Iterator[Path]:
    # Unlike mkdtemp's mode 0700, mode 0777 admits the shared cache's default
    # ACL at creation, so SIGKILL cannot strand a cross-UID-inaccessible tree.
    directory = cache / "staging" / (key + "-" + secrets.token_hex(16))
    directory.mkdir(mode=0o777)
    directory.chmod(0o777)
    try:
        yield directory
    finally:
        shutil.rmtree(directory)


def prune(cache: Path, max_bytes: int = _DEFAULT_BYTES, max_age: float = _DEFAULT_AGE) -> int:
    """Remove old/over-budget entries whose leases can be acquired immediately."""
    entries = cache / "entries"
    locks = cache / "locks"
    staging = cache / "staging"
    if staging.exists():
        for scratch in staging.iterdir():
            key = scratch.name.split("-", 1)[0]
            if len(key) != 64 or any(character not in "0123456789abcdef" for character in key):
                continue
            with (locks / key).open("a+b") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                # SIGKILL bypasses TemporaryDirectory cleanup; the released
                # key lease proves that this staging tree has no active builder.
                if scratch.exists():
                    shutil.rmtree(scratch)
    if not entries.exists():
        return 0

    candidates_with_age = []
    for entry in entries.iterdir():
        try:
            candidates_with_age.append((entry.stat().st_mtime, entry))
        except FileNotFoundError:
            continue
    candidates = [entry for _, entry in sorted(candidates_with_age)]
    total = sum(_allocated(entry) for entry in candidates)
    removed = 0
    for entry in candidates:
        with (locks / entry.name).open("a+b") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue

            if not entry.exists():
                continue
            age = time.time() - entry.stat().st_mtime
            if age < max_age and total <= max_bytes:
                continue
            size = _allocated(entry)
            shutil.rmtree(entry)
            total -= size
            removed += 1

    return removed


@contextlib.contextmanager
def materialize(recipe_path: Path) -> Iterator[Path]:
    """Lease an immutable base, atomically rebuilding missing/corrupt entries."""
    recipe_file = recipe_path / "image-recipe.json"
    contents = recipe_file.read_bytes()
    recipe = json.loads(contents)
    if recipe["schema"] != 1:
        raise ValueError(f"Unsupported image recipe: {recipe_file}")

    # Include this implementation as well as the complete recipe contract.
    key = hashlib.sha256(contents + Path(__file__).read_bytes()).hexdigest()
    cache = Path(recipe["cache"])
    _require_disk(cache)
    _require_disk(Path(tempfile.gettempdir()))
    for directory in (cache / "entries", cache / "locks", cache / "staging"):
        directory.mkdir(parents=True, exist_ok=True)

    entry = cache / "entries" / key
    # Lock inodes are never removed by eviction. A lease covers both dependent
    # assembly and private copies, including copies to a different filesystem.
    with (cache / "locks" / key).open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not _valid(entry):
            if entry.exists():
                shutil.rmtree(entry)
            log.info("Image cache miss: %s", key)
            with contextlib.ExitStack() as leases, tempfile.TemporaryDirectory(
                prefix="aos-image-"
            ) as scratch:
                replacements = {
                    dependency: str(leases.enter_context(materialize(Path(dependency))))
                    for dependency in recipe["dependencies"]
                }

                def resolve(value: str) -> str:
                    for source, destination in replacements.items():
                        value = value.replace(source, destination)
                    return value

                work = Path(scratch)
                # Assembly belongs to the sandbox's scratch directory. Shared
                # cache default ACLs must not become guest ACLs via mkfs -d.
                output = work / "output"
                output.mkdir()
                temporary = work / "tmp"
                temporary.mkdir()
                environment = {name: resolve(value) for name, value in recipe["environment"].items()}
                environment.update(
                    out=str(output), TMPDIR=str(temporary), HOME=str(temporary),
                    NIX_BUILD_TOP=str(work), NIX_BUILD_CORES=os.environ.get("NIX_BUILD_CORES", "1"),
                    SOURCE_DATE_EPOCH="1", TZ="UTC", LC_ALL="C",
                )
                command = work / "build.bash"
                command.write_text(resolve(recipe["script"]))
                subprocess.run([recipe["shell"], str(command)], cwd=work, env=environment, check=True)
                if not output.is_dir():
                    raise ValueError("Image recipe must produce a directory")
                inventory = _inventory(output)
                if not inventory:
                    raise ValueError("Image recipe produced no files")
                (output / "image-integrity.json").write_text(json.dumps(inventory, sort_keys=True))
                # Only final images enter shared staging. A killed builder's
                # private assembly tree is handled by ordinary sandbox cleanup;
                # abandoned publication files remain cross-UID-prunable.
                with _publication_staging(cache, key) as publication:
                    staged_output = publication / "output"
                    _publish_files(output, staged_output)
                    os.rename(staged_output, entry)
        else:
            log.info("Image cache hit: %s", key)

        os.utime(entry, None)
        prune(cache)
        try:
            yield entry
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            # Enforce the budget again after the last consumer releases its
            # lease; live bases may temporarily exceed the idle-cache bound.
            prune(cache)


@contextlib.contextmanager
def image_source(source: str) -> Iterator[str]:
    """Resolve a recipe-backed image path while holding its cache lease."""
    path = Path(source)
    if (path.parent / "image-recipe.json").is_file():
        with materialize(path.parent) as base:
            yield str(base / path.name)
    else:
        yield source


def main() -> None:
    """Provide image copying and explicit cache status/age/size maintenance."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    copy = commands.add_parser("copy")
    copy.add_argument("source")
    copy.add_argument("destination")
    for name in ("status", "prune"):
        command = commands.add_parser(name)
        command.add_argument("cache", type=Path)
        if name == "prune":
            command.add_argument("--max-gib", type=float, default=100)
            command.add_argument("--days", type=float, default=14)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    if args.command == "copy":
        from .fs import clone_or_copy
        clone_or_copy(args.source, args.destination)
    elif args.command == "prune":
        if args.max_gib < 0 or args.days < 0:
            parser.error("Cache bounds must be nonnegative")
        print(f"Removed {prune(args.cache, int(args.max_gib * 1024**3), args.days * 86400)} image bases")
    else:
        entries: list[Path] = list((args.cache / "entries").iterdir()) if (args.cache / "entries").exists() else []
        print(f"{len(entries)} image bases, {sum(_allocated(entry) for entry in entries)} allocated bytes")


if __name__ == "__main__":
    main()
