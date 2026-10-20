"""Exercises original scratch-file refusal and cleanup in the native ext4 guest."""

import os
import subprocess


def run(driver, uuid):
    """Checks actual scratch refusal and cleanup before the first empty recovery."""
    directory = driver.root("empty") / "chunks/ab"
    directory.mkdir()
    driver.metadata(directory, 840, 845, 0o2770)
    original_directory = (directory.stat().st_dev, directory.stat().st_ino)
    first = directory / (".terrane-tmp:" + "11" * 16)
    second = directory / (".terrane-tmp:" + "22" * 16)
    alias = directory / (".terrane-tmp:" + "33" * 16)
    partial = [b"interrupted chunk before canonical mode", b"interrupted verified chunk before insertion"]
    for path, body, mode in [(first, partial[0], 0o600), (second, partial[1], 0o640)]:
        path.write_bytes(body)
        driver.metadata(path, 840, 845, mode)
        with path.open("rb") as retained:
            os.fsync(retained.fileno())
    os.link(second, alias)
    retained = [first.open("rb"), second.open("rb")]
    policy = driver.root("empty") / "state/cache/records.toml"

    def snapshot():
        return {path.name: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                            value.st_gid, value.st_nlink, value.st_size,
                            value.st_mtime_ns, value.st_ctime_ns)
                for path in directory.iterdir() for value in [path.lstat()]}

    def refuses(message):
        before = snapshot()
        result = subprocess.run(driver.role_command(840, [driver.IMAGE / "bin/host_cache_fixture", "empty"]),
                                env=driver.actor_environment("empty", uuid), text=True,
                                capture_output=True, timeout=30)
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", flush=True)
        driver.require(result.returncode != 0 and message in result.stderr
                and "PASS actual empty recovery" not in result.stdout
                and not policy.exists() and snapshot() == before,
                "invalid chunk scratch changed names, inodes or policy before refusal")
        for file, body in zip(retained, partial):
            file.seek(0)
            driver.require(file.read() == body, "scratch refusal changed original partial bytes")

    try:
        bad = directory / ".terrane-tmp:zz"
        bad.write_bytes(b"malformed generated identifier must survive")
        driver.metadata(bad, 840, 845, 0o640)
        refuses("malformed generated chunk scratch identifier")
        bad.unlink()

        bad = directory / (".terrane-tmp:" + "ff" * 16)
        bad.symlink_to(first.name)
        refuses("generated chunk scratch is not a regular inode")
        bad.unlink()

        driver.require(first.stat().st_nlink == 1 and second.stat().st_nlink == alias.stat().st_nlink == 2,
                "scratch fixture lacks actual single and duplicate inode links")
        driver.actor("empty", "empty", uuid)
        driver.require((directory.stat().st_dev, directory.stat().st_ino) == original_directory
                and list(directory.iterdir()) == [],
                "recovery replaced the shard or left generated scratch names")
        for file, body in zip(retained, partial):
            file.seek(0)
            driver.require(os.fstat(file.fileno()).st_nlink == 0 and file.read() == body,
                    "cleanup did not unlink the original retained scratch inode unchanged")
        print("PASS actual generated chunk scratch cleanup preserves refusal controls and unlinks original inodes after verified preflight", flush=True)
    finally:
        for file in retained:
            file.close()
