"""Exercises original chunk/index scratch custody in the native ext4 guest."""

import os
import subprocess


def run(driver, uuid):
    """Checks actual scratch refusal and cleanup before the first empty recovery."""
    empty_root = driver.root("empty")
    directory = empty_root / "chunks/ab"
    pack_directory = empty_root / "objects/pack"
    index_directory = pack_directory / "ab"
    for parent in [directory, pack_directory, index_directory]:
        parent.mkdir()
        driver.metadata(parent, 840, 845, 0o2770)
    directories = [directory, index_directory]
    original_directories = {
        parent: (parent.stat().st_dev, parent.stat().st_ino)
        for parent in [pack_directory, *directories]
    }

    first = directory / (".terrane-tmp:" + "11" * 16)
    second = directory / (".terrane-tmp:" + "22" * 16)
    alias = directory / (".terrane-tmp:" + "33" * 16)
    first_index = index_directory / (".terrane-tmp:" + "44" * 16)
    second_index = index_directory / (".terrane-tmp:" + "55" * 16)
    index_alias = index_directory / (".terrane-tmp:" + "66" * 16)
    cross_alias = index_directory / (".terrane-tmp:" + "77" * 16)
    partial = [
        b"interrupted chunk before canonical mode",
        b"interrupted verified chunk before insertion",
        b"interrupted detached index before canonical mode",
        b"interrupted detached index before no-replace insertion",
    ]
    originals = [first, second, first_index, second_index]
    for path, body, mode in zip(originals, partial, [0o600, 0o640, 0o600, 0o640]):
        path.write_bytes(body)
        driver.metadata(path, 840, 845, mode)
        with path.open("rb") as retained:
            os.fsync(retained.fileno())
    os.link(second, alias)
    os.link(second_index, index_alias)
    os.link(second, cross_alias)
    retained = [path.open("rb") for path in originals]
    policy = empty_root / "state/cache/records.toml"

    def snapshot():
        return {
            str(path.relative_to(empty_root)): (
                value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                value.st_gid, value.st_nlink, value.st_size,
                value.st_mtime_ns, value.st_ctime_ns,
            )
            for parent in directories
            for path in parent.iterdir()
            for value in [path.lstat()]
        }

    def refuses(message):
        before = snapshot()
        command = driver.role_command(840, [driver.IMAGE / "bin/host_cache_fixture", "empty"])
        result = subprocess.run(
            command, env=driver.actor_environment("empty", uuid), text=True,
            capture_output=True, timeout=30,
        )
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", flush=True)
        driver.require(
            result.returncode != 0 and message in result.stderr
            and "PASS actual empty recovery" not in result.stdout
            and not policy.exists() and snapshot() == before,
            "invalid scratch changed names, inodes or policy before refusal",
        )
        for file, body in zip(retained, partial):
            file.seek(0)
            driver.require(file.read() == body, "scratch refusal changed original partial bytes")

    try:
        # Invalid index scratch must also preserve earlier chunk candidates.
        # A canonical-looking alias participates in every refusal snapshot.
        canonical = index_directory / ("ab" + "00" * 15 + ".idx")
        os.link(second_index, canonical)
        for parent, target in [(directory, first), (index_directory, first_index)]:
            bad = parent / ".terrane-tmp:zz"
            bad.write_bytes(b"malformed generated identifier must survive")
            driver.metadata(bad, 840, 845, 0o640)
            refuses("malformed generated scratch identifier")
            bad.unlink()

            bad = parent / (".terrane-tmp:" + "ff" * 16)
            bad.symlink_to(target.name)
            refuses("generated scratch is not a regular inode")
            bad.unlink()

        fifo = index_directory / (".terrane-tmp:" + "88" * 16)
        os.mkfifo(fifo, 0o600)
        driver.metadata(fifo, 840, 845, 0o600)
        refuses("generated scratch is not a regular inode")
        fifo.unlink()
        driver.require(
            canonical.stat().st_ino == second_index.stat().st_ino
            and canonical.read_bytes() == partial[3],
            "scratch refusal changed the preexisting index alias",
        )
        canonical.unlink()

        driver.require(
            first.stat().st_nlink == first_index.stat().st_nlink == 1
            and second.stat().st_nlink == alias.stat().st_nlink == cross_alias.stat().st_nlink == 3
            and second_index.stat().st_nlink == index_alias.stat().st_nlink == 2,
            "scratch fixture lacks actual single, duplicate and cross-directory inode links",
        )
        driver.actor("empty", "empty", uuid)
        for parent, original in original_directories.items():
            driver.require(
                (parent.stat().st_dev, parent.stat().st_ino) == original,
                "recovery replaced a shard or its retained pack parent",
            )
        driver.require(
            all(list(parent.iterdir()) == [] for parent in directories),
            "recovery left generated scratch names",
        )
        for file, body in zip(retained, partial):
            file.seek(0)
            driver.require(
                os.fstat(file.fileno()).st_nlink == 0 and file.read() == body,
                "cleanup did not unlink the original retained scratch inode unchanged",
            )
        print("PASS actual generated chunk scratch cleanup preserves refusal controls and unlinks original inodes after verified preflight", flush=True)
        print("PASS actual detached-index scratch cleanup preserves cross-class refusals and original aliased inodes", flush=True)
    finally:
        for file in retained:
            file.close()
