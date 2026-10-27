"""Checks actual expired removal and conservative lost-deadline reconstruction."""

import errno
import fcntl
import hashlib
import os
import struct
import time
import tomllib


FAMILIES = {
    "pending": ("seed-pending-inline", None),
    "pending-raw": ("seed-pending-raw", 0),
    "pending-zstd": ("seed-pending-zstd", 1),
    "pending-dictionary": ("seed-pending-dictionary", 2),
}
CASES = [family + "-" + phase for family in FAMILIES for phase in ["expired", "unknown"]]


def seed(driver, uuid):
    """Retains actual sealed and encoded inodes before native role startup."""
    originals = {}
    for case in CASES:
        selector, codec = FAMILIES[case.rsplit("-", 1)[0]]
        result = driver.run(
            driver.admin_command(driver.SEED_CAPS, [
                driver.IMAGE / "bin/host_cache_fixture", selector,
            ]), env=driver.actor_environment(case, uuid), text=True, capture_output=True,
        )
        driver.require(result.stdout.splitlines() == [
            "SEEDED actual " + ("sealed" if codec is None else "encoded")
            + " pending inode without a retirement deadline"
        ], "pending fixture omitted its actual administrative seed")
        root = driver.root(case)
        paths = list((root / "pending-delete").iterdir())
        driver.require(len(paths) == 1 and not list((root / "state/publication").iterdir())
                       and not list((root / "state/cache").iterdir()),
                       "pending seed fabricated native authority or a retirement lease")
        file = paths[0].open("rb")
        value = os.fstat(file.fileno())
        expected = (841, 841, 0o400) if codec is None else (840, 845, 0o640)
        driver.require((value.st_uid, value.st_gid, value.st_mode & 0o7777) == expected,
                       "pending seed has another actual custody kind")
        # FS_IOC_MEASURE_VERITY reads actual kernel state. Supply the available
        # digest capacity so a sealed file returns its measured digest.
        measurement = bytearray(68)
        struct.pack_into("<HH", measurement, 0, 0, 64)
        try:
            fcntl.ioctl(file, 0xc0046686, measurement, True)
        except OSError as error:
            driver.require(codec is not None and error.errno == errno.ENODATA,
                           "pending seed lost its expected actual kernel seal state")
        else:
            algorithm, width = struct.unpack_from("<HH", measurement)
            driver.require(codec is None and (algorithm, width) in {(1, 32), (2, 64)},
                           "encoded pending seed acquired a kernel seal")
        if codec is not None:
            driver.require(file.read(1) == bytes([codec])
                           and not list((root / "objects").rglob("*.pack")),
                           "encoded seed codec or intentionally absent dictionary sources differ")
            file.seek(0)
        originals[case] = (paths[0], file, (value.st_dev, value.st_ino),
                           hashlib.file_digest(file, "sha256").hexdigest())
    return originals


def run(driver, uuid, originals):
    """Runs genuine owner restarts while keeping original bytes and clocks intact."""

    def refusal(case):
        label = "encoded pending" if FAMILIES[case.rsplit("-", 1)[0]][1] is not None else "pending"
        return f"PASS actual unexpired {label} inode refused; original bootstrap holds retained; no Resume"

    def mode(case, action):
        suffix = "chunk" if FAMILIES[case.rsplit("-", 1)[0]][1] is not None else "inline"
        return f"{action}-pending-{suffix}"

    def policy(case):
        path = driver.root(case) / "state/cache/records.toml"
        return tomllib.loads(path.read_text()) if path.exists() else {
            "reservations": [], "pins": [], "leases": [], "residences": [],
        }

    def actor(case, mode):
        before = policy(case)
        output = driver.actor(case, mode, uuid)
        after = policy(case)
        driver.require(len(after["reservations"]) == len(before["reservations"]) + 1
                       and all(after["reservations"].count(row) == 1
                               for row in before["reservations"])
                       and all(row["owner"] == driver.owner(case) and row["bytes"] == 262144
                               for row in after["reservations"])
                       and len({row["id"] for row in after["reservations"]}) == len(after["reservations"])
                       and all(after[group] == [] for group in ["pins", "leases", "residences"]),
                       "pending restart cleared, reused or changed actual funding")
        return output

    def unchanged(case):
        path, file, identity, digest = originals[case]
        value = path.stat()
        file.seek(0)
        driver.require((value.st_dev, value.st_ino) == identity and value.st_nlink == 1
                       and hashlib.file_digest(file, "sha256").hexdigest() == digest,
                       "unexpired or unknown retirement changed its original pending inode")

    def lease(case):
        paths = list((driver.root(case) / "state/publication").glob("retirement-*.toml"))
        driver.require(len(paths) == 1, "actual pending inspection omitted a durable deadline")
        value = tomllib.loads(paths[0].read_text())
        original = originals[case][1]
        metadata = os.fstat(original.fileno())
        driver.require(value["version"] == 1 and value["domain"] == driver.domain(case)
                       and (value["device"], value["inode"]) == (metadata.st_dev, metadata.st_ino)
                       and value["changed_seconds"] == metadata.st_ctime_ns // 1_000_000_000
                       and value["changed_nanoseconds"] == metadata.st_ctime_ns % 1_000_000_000,
                       "retirement lease names another original inode")
        return paths[0], value

    try:
        deadlines = {}
        for case in CASES:
            started = time.time_ns() // 1_000_000
            output = actor(case, mode(case, "refuse"))
            driver.require(output.splitlines() == [refusal(case)], "unexpired pending recovery did not refuse")
            unchanged(case)
            _, value = lease(case)
            driver.require(value["deadline_unix_ms"] >= started + 30000,
                           "unknown deadline was treated as expired instead of reconstructed")
            deadlines[case] = value["deadline_unix_ms"]

        # Wait for the actual persisted deadline, without changing the configured
        # retirement interval or manufacturing lease bytes. Existing descriptors
        # keep the inode charged even after its last namespace link disappears.
        for family, (_, codec) in FAMILIES.items():
            expired, unknown = family + "-expired", family + "-unknown"
            remaining = (deadlines[expired] - time.time_ns() // 1_000_000) / 1000
            driver.require(remaining <= 31, "pending interval exceeds the bounded native policy")
            if remaining > 0:
                time.sleep(remaining + 0.05)
            output = actor(expired, mode(expired, "recover"))
            label = "encoded pending" if codec is not None else "pending"
            driver.require(output.splitlines() == [
                f"PASS actual expired {label} inode removed before completed recovery and acknowledged Resume; original holds retained; no Ready"
            ] and not originals[expired][0].exists()
                           and os.fstat(originals[expired][1].fileno()).st_nlink == 0,
                           "expired recovery did not remove the actual original pending inode")
            original_file = originals[expired][1]
            original_file.seek(0)
            driver.require(hashlib.file_digest(original_file, "sha256").hexdigest()
                           == originals[expired][3],
                           "ordinary pending removal changed retained original bytes")

            # Explicit administrative fault injection loses only the actual
            # deadline. The fresh physical owner must reconstruct it even though
            # the original interval passed; every cache hold remains original.
            path, _ = lease(unknown)
            path.unlink()
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            started = time.time_ns() // 1_000_000
            output = actor(unknown, mode(unknown, "refuse"))
            driver.require(output.splitlines() == [refusal(unknown)], "lost deadline permitted immediate removal")
            unchanged(unknown)
            _, value = lease(unknown)
            driver.require(value["deadline_unix_ms"] >= started + 30000
                           and value["deadline_unix_ms"] > deadlines[unknown],
                           "state loss reused the expired deadline")
            if codec is None:
                print("PASS actual pending startup removed only the expired original inode and reconstructed a lost deadline before refusing removal; original policy holds retained", flush=True)
            else:
                print(f"PASS actual encoded pending startup codec={codec} removed only the expired original inode and reconstructed a lost deadline; no plaintext or dictionary authority; original holds retained", flush=True)
    finally:
        for _, file, _, _ in originals.values():
            file.close()
