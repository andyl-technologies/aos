"""Checks actual missing-index recovery and refusal custody on native ext4."""

import hashlib
import os
import struct
import tomllib


CASES = [
    ("index-recovery", "seed-index-recovery", "recover-index-recovery"),
    ("index-disabled", "seed-index-disabled", "refuse-index-disabled"),
    ("index-bound", "seed-index-bound", "refuse-index-bound"),
    ("index-mismatch", "seed-index-mismatch", "refuse-index-mismatch"),
]


def digest(file):
    """Hashes original retained bytes independently of canonical name lookup."""
    file.seek(0)
    return hashlib.file_digest(file, "sha256").hexdigest()


def seed(driver, uuid):
    """Seeds untrusted inputs before publisher startup and retains original inodes."""
    seeded = {}
    for case, mode, _ in CASES:
        result = driver.run(
            driver.admin_command(driver.SEED_CAPS, [driver.IMAGE / "bin/host_cache_fixture", mode]),
            env=driver.actor_environment(case, uuid), text=True, capture_output=True,
        )
        driver.require(result.stdout.splitlines() == [
            "SEEDED actual cold manifest candidate; no publication or recovery authority"
        ], "missing actual index-recovery seed witness: " + case)
        root = driver.root(case)
        packs = list((root / "objects/pack").glob("*/*.pack"))
        indexes = list((root / "objects/pack").glob("*/*.idx"))
        bodies = list((root / "sealed").glob("*/*"))
        driver.require(len(packs) == len(indexes) == len(bodies) == 1
                       and indexes[0] == packs[0].with_suffix(".idx")
                       and not list((root / "state/publication").iterdir())
                       and not list((root / "state/cache").iterdir()),
                       "index seed omitted actual bytes or fabricated policy: " + case)
        pack, index, body = packs[0], indexes[0], bodies[0]
        packed = pack.read_bytes()
        offset = struct.unpack_from("<Q", packed, len(packed) - 16)[0]
        expected_index = packed[:24] + packed[offset:-16]
        driver.require(packed[:4] == b"TRPK" and packed[-4:] == b"TRPE"
                       and 24 <= offset < len(packed) - 16
                       and packed[offset:offset + 4] == b"TRIX"
                       and index.read_bytes() == expected_index,
                       "seed index differs from its authoritative pack bytes")
        retained_pack = pack.open("rb")
        retained_body = body.open("rb")
        if case == "index-mismatch":
            with index.open("r+b") as writer:
                writer.seek(-1, os.SEEK_END)
                writer.write(bytes([expected_index[-1] ^ 1]))
                writer.flush()
                os.fsync(writer.fileno())
        retained_index = index.open("rb")
        original = {
            "pack": pack, "index": index, "body": body,
            "retained": [retained_pack, retained_index, retained_body],
            "identities": [(os.fstat(file.fileno()).st_dev, os.fstat(file.fileno()).st_ino)
                           for file in [retained_pack, retained_index, retained_body]],
            "hashes": [digest(file) for file in [retained_pack, retained_index, retained_body]],
            "expected_index": expected_index,
        }
        if case != "index-mismatch":
            index.unlink()
            directory = os.open(index.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            driver.require(os.fstat(retained_index.fileno()).st_nlink == 0,
                           "missing index still has its original canonical link")
        seeded[case] = original
    return seeded


def run(driver, uuid, seeded):
    """Checks actual actor results, exact repair bytes and original refusal inodes."""
    try:
        for case, _, mode in CASES:
            original = seeded[case]
            output = driver.actor(case, mode, uuid)
            root = driver.root(case)
            state = tomllib.loads((root / "state/cache/records.toml").read_text())
            for file, identity, expected in zip(
                    original["retained"], original["identities"], original["hashes"]):
                observed = os.fstat(file.fileno())
                driver.require((observed.st_dev, observed.st_ino) == identity
                               and digest(file) == expected,
                               "index recovery changed original retained bytes: " + case)
            for name, position in [("pack", 0), ("body", 2)]:
                observed = original[name].stat()
                driver.require((observed.st_dev, observed.st_ino) == original["identities"][position],
                               "index recovery replaced an original pack or sealed body")
            if case == "index-recovery":
                marker = "PASS actual startup index repair retained only bootstrap and verified metadata funding before Resume"
                driver.require(output.splitlines().count(marker) == 1
                               and output.splitlines().count("PASS actual manifest recovery reconstructed verified residences and acknowledged Resume; no Ready") == 1
                               and output.splitlines().count("PASS actual recovered manifest ranges read while embedded policy held; original custody unchanged") == 2,
                               "missing actual recovered index custody and Running read witness")
                index = original["index"]
                observed = index.stat()
                driver.require(index.read_bytes() == original["expected_index"]
                               and (observed.st_dev, observed.st_ino) != original["identities"][1]
                               and observed.st_uid == 840 and observed.st_gid == 845
                               and observed.st_mode & 0o7777 == 0o640 and observed.st_nlink == 1
                               and all(not row["owner"].startswith("index-repair:")
                                       for row in state["pins"] + state["leases"]),
                               "repaired index or remaining policy differs from actual completion")
                print("PASS actual startup reconstructed the detached index from original verified pack bytes before adopted reads and retained exact native custody", flush=True)
            else:
                label = {"index-disabled": "disabled index repair",
                         "index-bound": "bounded index repair",
                         "index-mismatch": "mismatching detached index"}[case]
                marker = f"PASS actual {label} retained bootstrap-only funding and faulted custody; no Resume"
                driver.require(output.splitlines().count(marker) == 1
                               and len(state["reservations"]) == 1
                               and not state["pins"] and not state["leases"]
                               and not state["residences"]
                               and not list((root / "state/publication").iterdir()),
                               "index refusal changed exact unadopted native policy")
                if case == "index-mismatch":
                    observed = original["index"].stat()
                    driver.require((observed.st_dev, observed.st_ino) == original["identities"][1]
                                   and hashlib.sha256(original["index"].read_bytes()).hexdigest() == original["hashes"][1],
                                   "recovery replaced or changed the mismatching index")
                else:
                    driver.require(not original["index"].exists(),
                                   "disabled or oversized repair created an index")
                print(f"PASS actual {label} preserved original bytes, bootstrap funding and missing-or-mismatching index without adoption", flush=True)
    finally:
        for original in seeded.values():
            for file in original["retained"]:
                file.close()
