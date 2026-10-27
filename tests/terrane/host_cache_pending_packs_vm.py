"""Checks actual pending pack units, missing peers and foreign charge ownership."""

import contextlib
import fcntl
import hashlib
import os
import struct
import time
import tomllib


CASES = {
    "pending-pack-expired": {"pack": "pending", "idx": "pending"},
    "pending-pack-unknown": {"pack": "pending", "idx": "pending"},
    "pending-pack-split-pack": {"pack": "pending", "idx": "canonical"},
    "pending-pack-split-index": {"pack": "canonical", "idx": "pending"},
    "pending-pack-orphan-index": {"idx": "pending"},
    "pending-pack-orphan-pack": {"pack": "pending"},
    "pending-pack-foreign": {"pack": "pending", "idx": "canonical"},
}
REFUSAL = "PASS actual unexpired pending pack unit refused; original bootstrap holds retained; no Resume"
RECOVERED = "PASS actual expired pending pack unit removed before completed recovery and acknowledged Resume; original holds retained; no Ready"
FOREIGN = "PASS actual foreign-project pending pack refused before namespace mutation; original bootstrap holds retained; no Resume"


def project(file):
    """Reads the actual Linux FS_IOC_FSGETXATTR project field, without setters."""
    attributes = bytearray(28)
    fcntl.ioctl(file, 0x801c581f, attributes, True)
    return struct.unpack_from("<I", attributes, 12)[0]


def digest(file):
    """Hashes original retained bytes independently of current name lookup."""
    file.seek(0)
    return hashlib.file_digest(file, "sha256").hexdigest()


def body_paths(root):
    """Lists every actual pending and canonical pack-member name."""
    return list((root / "pending-delete").iterdir()) + list((root / "objects/pack").glob("*/*"))


@contextlib.contextmanager
def seed_namespace(driver, case):
    """Injects foreign custody before startup, then restores directory inheritance."""
    if case != "pending-pack-foreign":
        yield
        return

    path = driver.root(case) / "pending-delete"
    driver.require(not any(path.iterdir()), "foreign seed namespace is not empty")
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        original = bytearray(28)
        fcntl.ioctl(directory, 0x801c581f, original, True)
        flags = struct.unpack_from("<I", original)[0]
        driver.require(flags & 0x200 and struct.unpack_from("<I", original, 12)[0]
                       == driver.project(case), "foreign seed lost its inheriting project root")
        before = os.fstat(directory)

        # ext4 refuses a foreign-project rename into a PROJINHERIT directory.
        # Only root administration, before either role starts, relaxes this
        # directory flag for fault injection. Neither inode's project changes.
        temporary = bytearray(original)
        struct.pack_into("<I", temporary, 0, flags & ~0x200)
        fcntl.ioctl(directory, 0x401c5820, temporary)
        try:
            os.fsync(directory)
            yield
        finally:
            fcntl.ioctl(directory, 0x401c5820, original)
            os.fsync(directory)
            restored = bytearray(28)
            fcntl.ioctl(directory, 0x801c581f, restored, True)
            after = os.fstat(directory)
            driver.require(restored[:8] == original[:8] and restored[12:] == original[12:]
                           and (after.st_dev, after.st_ino, after.st_uid, after.st_gid,
                                after.st_mode) == (before.st_dev, before.st_ino, before.st_uid,
                                                   before.st_gid, before.st_mode),
                           "foreign seed failed to restore original directory custody")
    finally:
        os.close(directory)


def seed(driver, uuid):
    """Retains real administrative inputs before either native role starts."""
    originals = {}
    for case, locations in CASES.items():
        with seed_namespace(driver, case):
            result = driver.run(driver.admin_command(driver.SEED_CAPS, [
                driver.IMAGE / "bin/host_cache_fixture", "seed-pending-pack",
            ]), env=driver.actor_environment(case, uuid), text=True, capture_output=True)
        driver.require(result.stdout.splitlines() == [
            "SEEDED actual pending pack/index candidates; no content or retirement authority"
        ], "pending pack seed omitted actual administrative inputs")
        root = driver.root(case)
        driver.require(not list((root / "state/publication").iterdir())
                       and not list((root / "state/cache").iterdir()),
                       "pending pack seed fabricated policy or retirement authority")
        members = {}
        for path in body_paths(root):
            file = path.open("rb")
            data = file.read()
            kind = "pack" if data[-4:] == b"TRPE" else "idx"
            driver.require(data[:4] == b"TRPK" and data[4:6] == b"\x01\x00"
                           and (kind == "pack" or data[24:28] == b"TRIX")
                           and kind not in members and kind in locations,
                           "pending pack seed has an unknown or repeated encoded member")
            metadata = os.fstat(file.fileno())
            identity = (metadata.st_dev, metadata.st_ino)
            expected_project = driver.project("source-cleanup-foreign") if (
                case == "pending-pack-foreign" and kind == "pack") else driver.project(case)
            driver.require((metadata.st_uid, metadata.st_gid, metadata.st_mode & 0o7777)
                           == (840, 845, 0o640) and metadata.st_nlink == 1
                           and project(file) == expected_project,
                           "pack seed omitted its actual original custody or project")
            pack_id = data[8:24]
            canonical = root / "objects/pack" / pack_id.hex()[:2] / (pack_id.hex() + "." + kind)
            driver.require((path == canonical) == (locations[kind] == "canonical"),
                           "pack seed has the wrong initial retirement split")
            members[kind] = {"file": file, "identity": identity, "hash": digest(file),
                             "project": expected_project, "id": pack_id, "canonical": canonical}
        driver.require(set(members) == set(locations)
                       and len({member["id"] for member in members.values()}) == 1,
                       "pack seed omitted or mismatched its original retirement members")
        originals[case] = members
    return originals


def run(driver, uuid, originals, exercise_chunk_cases):
    """Checks genuine pair reconciliation, deadlines and original surviving inodes."""

    def policy(case):
        path = driver.root(case) / "state/cache/records.toml"
        return tomllib.loads(path.read_text()) if path.exists() else {"reservations": []}

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
                       and all(not after[group] for group in ["pins", "leases", "residences"]),
                       "pending pack recovery changed or reused original funding")
        return output

    def unchanged(case, links):
        for member in originals[case].values():
            file = member["file"]
            metadata = os.fstat(file.fileno())
            driver.require((metadata.st_dev, metadata.st_ino) == member["identity"]
                           and metadata.st_nlink == links and digest(file) == member["hash"]
                           and project(file) == member["project"],
                           "pending pack recovery replaced bytes, links or charge ownership")

    def leases(case):
        root = driver.root(case)
        records = list((root / "state/publication").glob("retirement-*.toml"))
        driver.require(len(records) == len(originals[case]),
                       "pending pack unit omitted an actual member deadline")
        deadlines = {}
        for path in records:
            value = tomllib.loads(path.read_text())
            matched = []
            for kind, member in originals[case].items():
                metadata = os.fstat(member["file"].fileno())
                if (value["device"], value["inode"]) == member["identity"]:
                    matched.append(kind)
                    driver.require(value["version"] == 1 and value["domain"] == driver.domain(case)
                                   and value["key"] == [2, *member["id"], 0 if kind == "pack" else 1]
                                   and value["changed_seconds"] == metadata.st_ctime_ns // 1_000_000_000
                                   and value["changed_nanoseconds"] == metadata.st_ctime_ns % 1_000_000_000,
                                   "pending unit deadline names another actual member")
            driver.require(len(matched) == 1 and matched[0] not in deadlines,
                           "pending pack unit duplicated or substituted a member lease")
            deadlines[matched[0]] = (path, value["deadline_unix_ms"])
        return deadlines

    try:
        deadlines = {}
        for case in CASES:
            root = driver.root(case)
            if case == "pending-pack-foreign":
                before = {str(path): (path.stat().st_dev, path.stat().st_ino) for path in body_paths(root)}
                output = actor(case, "refuse-pending-pack-foreign")
                after = {str(path): (path.stat().st_dev, path.stat().st_ino) for path in body_paths(root)}
                driver.require(output.splitlines() == [FOREIGN] and before == after
                               and not list((root / "state/publication").iterdir()),
                               "foreign-project unit mutated namespace or created a deadline")
                unchanged(case, 1)
                continue
            started = time.time_ns() // 1_000_000
            output = actor(case, "refuse-pending-pack")
            driver.require(output.splitlines() == [REFUSAL]
                           and not list((root / "objects/pack").glob("*/*"))
                           and len(list((root / "pending-delete").iterdir())) == len(originals[case]),
                           "pending unit did not reconcile every original member before refusal")
            unchanged(case, 1)
            observed = leases(case)
            driver.require(all(deadline >= started + 30000 for _, deadline in observed.values()),
                           "unknown unit deadline was treated as expired")
            deadlines[case] = max(deadline for _, deadline in observed.values())

        # Exercise the independent chunk controls during these real intervals.
        # Every deadline remains kernel-clock based and is checked again below.
        exercise_chunk_cases()
        for case, deadline in deadlines.items():
            if case == "pending-pack-unknown":
                continue
            remaining = (deadline - time.time_ns() // 1_000_000) / 1000
            driver.require(remaining <= 31, "pack interval exceeds its bounded actual policy")
            if remaining > 0:
                time.sleep(remaining + 0.05)
            output = actor(case, "recover-pending-pack")
            driver.require(output.splitlines() == [RECOVERED]
                           and not body_paths(driver.root(case)),
                           "expired pack unit left a member or manufactured a missing peer")
            unchanged(case, 0)
            print(f"PASS actual {case} removed only the original reconciled retirement members after every actual deadline; missing peers remain absent", flush=True)

        case = "pending-pack-unknown"
        old = leases(case)
        for path, _ in old.values():
            path.unlink()
        directory = os.open(driver.root(case) / "state/publication", os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        started = time.time_ns() // 1_000_000
        output = actor(case, "refuse-pending-pack")
        driver.require(output.splitlines() == [REFUSAL], "lost unit deadlines permitted removal")
        unchanged(case, 1)
        rebuilt = leases(case)
        driver.require(all(deadline >= started + 30000 and deadline > old[kind][1]
                           for kind, (_, deadline) in rebuilt.items()),
                       "lost unit state reused an expired member deadline")
        print("PASS actual pending pack deadline loss reconstructed both bounded member leases and retained original inodes, bytes and policy holds", flush=True)
        print("PASS actual foreign-project pending pack refused before any rename, lease creation or project reassignment", flush=True)
    finally:
        for members in originals.values():
            for member in members.values():
                member["file"].close()
