"""Observes actual cold whole-file consumers independently of their native actor."""

import hashlib
import pathlib
import re


CASE = "sealed-consumer-cold"
WITNESS = ("PASS actual recovered whole inline and distinct manifest inodes sharing every chunk; "
           "no pre-Resume grant or range substitution; retained descriptors survive release")


def observe(vm):
    files = list((vm.root(CASE) / "sealed").glob("*/*"))
    vm.require(len(files) == 3, "cold whole-file fixture omitted original physical files")
    observed = {}
    for path in files:
        info = path.stat()
        vm.require(info.st_uid == 841 and info.st_gid == 841
                   and info.st_nlink == 1 and info.st_mode & 0o7777 == 0o400
                   and vm.kernel_seal(path) is not None,
                   "cold whole-file seed lacks actual immutable publisher custody")
        observed[path.name] = {"inode": info.st_ino, "bytes": info.st_size,
                               "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    vm.require(len({row["inode"] for row in observed.values()}) == 3,
               "cold whole-file seed reuses an original inode")
    vm.require(sorted(row["bytes"] for row in observed.values())
               == [len(vm.INLINE_BYTES), 262145, 262145],
               "cold fixture lacks its inline body and two complete assembled bodies")
    return observed


def seed(vm, uuid):
    result = vm.run(vm.admin_command(vm.SEED_CAPS, [vm.IMAGE / "bin/host_cache_fixture",
                                                   "seed-sealed-consumer-cold"]),
                    env=vm.actor_environment(CASE, uuid), text=True, capture_output=True)
    vm.require(result.stdout.splitlines() == [
        "SEEDED actual cold whole-file candidates; no publication or recovery authority"
    ], "missing actual cold whole-file seed witness")
    vm.require(not list((vm.root(CASE) / "state/cache").iterdir())
               and not list((vm.root(CASE) / "state/publication").iterdir()),
               "cold whole-file seed fabricated policy or publication authority")
    packs = list((vm.root(CASE) / "objects/pack").glob("*/*"))
    vm.require(len(packs) == 2 and sorted(path.suffix for path in packs) == [".idx", ".pack"],
               "cold whole-file seed lacks its actual canonical metadata pair")
    return {"files": observe(vm),
            "packs": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in packs}}


def run(vm, uuid, originals):
    result = vm.actor("sealed-consumer-cold", CASE, uuid)
    vm.require(result.splitlines().count(WITNESS) == 1,
               "missing genuine cold whole-file consumer witness")
    rows = re.findall(r"^COLD_SEALED_OBJECT hash=([a-f0-9]{64}) inode=([0-9]+) bytes=([0-9]+)$",
                      result, re.MULTILINE)
    vm.require(len(rows) == 3 and len({row[0] for row in rows}) == 3,
               "cold whole-file actor omitted original descriptor observations")
    vm.require({name: {"inode": int(inode), "bytes": int(length)}
                for name, inode, length in rows}
               == {name: {key: row[key] for key in ["inode", "bytes"]}
                   for name, row in originals["files"].items()},
               "consumer descriptors differ from the independently observed original inodes")
    vm.require(observe(vm) == originals["files"]
               and all(hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() == digest
                       for path, digest in originals["packs"].items()),
               "cold whole-file lease changed the original sealed or canonical metadata bytes")
    print("PASS independent observer matches recovered whole-file descriptors to all three original sealed inodes", flush=True)
