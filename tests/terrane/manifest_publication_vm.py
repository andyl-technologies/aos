"""Checks real Running manifest publication under the verified native supervisor."""

import pathlib
import signal
import stat
import time
import tomllib


def run(driver, publisher, uuid):
    """Checks actual original inodes, repeated ranges, cancellation and failed output."""
    published = []
    reference = None
    for suffix in ["", "-cancel", "-bad-whole", "-dictionary"]:
        case = "publication-manifest" + suffix
        process = driver.controlled_actor(case, "publish-manifest" + suffix, uuid)
        stopped = False
        try:
            lines = driver.Lines(process)
            lines.until("READY actual manifest sources and metadata admitted; wait for publication control")
            print(driver.process_status(process, 840), flush=True)
            root = driver.root(case)
            staging = root / "staging" / str(publisher.pid)
            staged_inode = (staging.stat().st_dev, staging.stat().st_ino)
            sources = list((root / "chunks").glob("*/*"))
            dictionary_backed = suffix == "-dictionary"
            driver.require(len(sources) == (3 if dictionary_backed else 2),
                           "manifest lacks its original admitted source/dependency inodes")
            original = {}
            for path in sources:
                metadata = path.stat()
                digest, separator, codec = path.name.partition(".")
                content = path.read_bytes()
                driver.require(separator and len(digest) == 64 and codec in (["0", "2"] if dictionary_backed else ["0"])
                               and content[0] == int(codec)
                               and path.parent.name == digest[:2] and metadata.st_uid == 840
                               and metadata.st_gid == 845 and metadata.st_nlink == 1
                               and metadata.st_mode & 0o7777 == 0o640,
                               "manifest source has another canonical/native custody")
                original[digest] = (path, metadata.st_dev, metadata.st_ino, content)
            if dictionary_backed:
                driver.require(reference is not None, "dictionary publication lacks an independent raw reference")
                first_hash, first_length, tail_hash, expected_bytes = reference
                first, tail = original[first_hash], original[tail_hash]
                dependencies = {digest: value for digest, value in original.items()
                                if digest not in [first_hash, tail_hash]}
                driver.require(len(dependencies) == 1 and first[3][0] == 2
                               and first[0].name == first_hash + ".2" and len(first[3]) < first_length * 97 // 100,
                               "dictionary case does not use actual compressed source custody")
                dictionary_hash, dictionary = next(iter(dependencies.items()))
                driver.require(first[3][1:33].hex() == dictionary_hash
                               and dictionary[3] == b"\x00" + expected_bytes[1:first_length],
                               "compressed source does not name its actual independently admitted dictionary")
            else:
                ordered = sorted(original.items(), key=lambda item: len(item[1][3]), reverse=True)
                first_hash, first = ordered[0]
                tail_hash, tail = ordered[1]
                first_length = len(first[3]) - 1
                driver.require(first_length > 256 * 1024 and len(tail[3]) == 32,
                               "manifest fixture lacks its honest nonfinal and bounded final chunks")
                expected_bytes = first[3][1:] * 2 + tail[3][1:]
                if suffix == "":
                    reference = (first_hash, first_length, tail_hash, expected_bytes)
                dependencies = {}
            transferred = {digest: value for digest, value in original.items() if digest not in dependencies}
            metadata_files = list((root / "objects/pack").glob("*/*"))
            driver.require(len(metadata_files) == 2, "manifest lacks one ordinary pack/index pair")
            metadata = {path: (path.stat().st_ino, path.read_bytes()) for path in metadata_files}
            snapshot = root / "state/cache/records.toml"
            if suffix == "-cancel":
                publisher.send_signal(signal.SIGSTOP)
                stopped = True
                deadline = time.monotonic() + 4
                while True:
                    status = pathlib.Path(f"/proc/{publisher.pid}/status").read_text()
                    driver.require(publisher.poll() is None, "manifest publisher exited before stop")
                    if any(line.startswith("State:\tT") or line.startswith("State:\tt")
                           for line in status.splitlines()):
                        break
                    driver.require(time.monotonic() < deadline, "manifest publisher did not stop")
                    time.sleep(0.005)
            process.stdin.write(b"start\n")
            process.stdin.flush()
            if suffix == "-cancel":
                lines.until("QUEUED actual manifest publication; wait for durable funding control")
                deadline = time.monotonic() + 4
                while True:
                    state = tomllib.loads(snapshot.read_text())
                    driver.require(process.poll() is None and time.monotonic() < deadline,
                                   "manifest publication did not synchronize real funding")
                    if (len(state["reservations"]), len(state["pins"]), len(state["leases"])) == (6, 7, 5):
                        driver.require(state["residences"] == [], "stopped publisher supplied manifest ranges")
                        break
                    time.sleep(0.005)
                driver.require(list((root / "sealed").glob("*/*")) == []
                               and list((root / "pending-delete").iterdir()) == [],
                               "stopped publisher supplied backing or retired an original source")
                for path, device, inode, content in original.values():
                    driver.require((path.stat().st_dev, path.stat().st_ino, path.read_bytes()) == (device, inode, content),
                                   "stopped manifest copy changed an original source")
                process.stdin.write(b"cancel\n")
                process.stdin.flush()
                lines.until("CANCELLED manifest waiter; original physical source and metadata custody retained")
                publisher.send_signal(signal.SIGCONT)
                stopped = False
            if suffix == "-bad-whole":
                lines.until("REFUSED actual wrong whole-file hash with durable manifest funding and no residence; no Ready")
                anonymous = []
                for path in pathlib.Path(f"/proc/{process.pid}/fd").iterdir():
                    try:
                        observed = path.stat()
                        if (stat.S_ISREG(observed.st_mode) and observed.st_nlink == 0
                                and observed.st_uid == 840 and observed.st_size == len(expected_bytes)):
                            anonymous.append(path.read_bytes())
                    except FileNotFoundError:
                        continue
                driver.require(anonymous == [expected_bytes],
                               "failed whole hash lost its actual funded anonymous output")
            control = b"resumed\n" if suffix == "-cancel" else b"finish\n" if suffix == "-bad-whole" else None
            output, error = process.communicate(control, timeout=30)
            print(output.decode(), end="", flush=True)
            if error:
                print(error.decode(), end="", flush=True)
            expected_result = ("PASS actual wrong whole-file hash retained the funded anonymous output without publisher submission; no Ready"
                               if suffix == "-bad-whole" else
                               "PASS actual dictionary-backed manifest publication retained its original dictionary inode, pins and holds while retiring repeated sources; no Ready"
                               if dictionary_backed else
                               "PASS actual manifest publication retained metadata, repeated-chunk ranges and pending original sources across later work; no Ready")
            driver.require(process.returncode == 0 and output.decode().splitlines() == [expected_result],
                           "missing exact actual manifest publication result: " + case)
            state = tomllib.loads(snapshot.read_text())
            for path, previous in metadata.items():
                driver.require((path.stat().st_ino, path.read_bytes()) == previous,
                               "manifest publication rewrote its actual reconstruction metadata")
            bodies = list((root / "sealed").glob("*/*"))
            if suffix == "-bad-whole":
                driver.require(bodies == [] and state["residences"] == []
                               and list((root / "pending-delete").iterdir()) == [],
                               "unverified whole hash supplied sealed backing, retirement or ranges")
                for path, device, inode, content in original.values():
                    driver.require((path.stat().st_dev, path.stat().st_ino, path.read_bytes()) == (device, inode, content),
                                   "failed whole hash changed an actual canonical source")
            else:
                driver.require(len(bodies) == 1 and bodies[0].read_bytes() == expected_bytes
                               and bodies[0].stat().st_mode & 0o7777 == 0o400
                               and bodies[0].stat().st_uid == bodies[0].stat().st_gid == 841,
                               "actual manifest sealed bytes or native custody differ")
                published.append((bodies[0].stat().st_dev, bodies[0].stat().st_ino))
                object_hash = bodies[0].name
                driver.require(state["residences"] == [
                    {"chunk": row[0], "object": object_hash, "offset": row[1], "length": row[2]}
                    for row in sorted([(first_hash, 0, first_length),
                                       (tail_hash, 2 * first_length, len(tail[3]) - 1)])
                ], "manifest ranges do not select the exact first repeated occurrence")
                driver.require(set((root / "chunks").glob("*/*")) == {value[0] for value in dependencies.values()},
                               "manifest publication lost a dependency or left duplicate standalone chunks")
                for digest, (path, device, inode, content) in dependencies.items():
                    observed = path.stat()
                    driver.require((observed.st_dev, observed.st_ino, path.read_bytes()) == (device, inode, content),
                                   "manifest publication changed its original dictionary inode")
                    owners = {row["owner"] for row in state["pins"] if row["hash"] == digest
                              and row["expires"] == 9223372036854775807}
                    driver.require(len(owners) == 2 and all(any(
                        lease["owner"] == owner and lease["expires"] == 9223372036854775807
                        for lease in state["leases"]) for owner in owners),
                        "dictionary lost either original admission pin/lease")
                pending = list((root / "pending-delete").iterdir())
                leases = [tomllib.loads(path.read_text()) for path in (root / "state/publication").glob("retirement-*.toml")]
                driver.require(len(pending) == len(leases) == 2, "manifest lost actual paired retirement custody")
                for digest, (path, device, inode, content) in transferred.items():
                    retired = root / "pending-delete" / digest
                    observed = retired.stat()
                    driver.require(not path.exists() and (observed.st_dev, observed.st_ino, retired.read_bytes()) == (device, inode, content)
                                   and observed.st_nlink == 1 and any(
                                       lease["domain"] == driver.domain(case) and lease["device"] == device
                                       and lease["inode"] == inode and lease["deadline_unix_ms"] > 0
                                       and lease["changed_seconds"] == observed.st_ctime_ns // 1_000_000_000
                                       and lease["changed_nanoseconds"] == observed.st_ctime_ns % 1_000_000_000
                                       for lease in leases), "manifest retirement replaced an inode or lost its actual lease")
            driver.require(not staging.is_symlink() and (staging.stat().st_dev, staging.stat().st_ino) == staged_inode
                           and staging.stat().st_uid == staging.stat().st_gid == 841
                           and staging.stat().st_mode & 0o7777 == 0o700 and list(staging.iterdir()) == [],
                           "manifest publication changed or leaked private publisher staging")
        finally:
            if stopped and publisher.poll() is None:
                publisher.send_signal(signal.SIGCONT)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    driver.require(len(published) == len(set(published)) == 3,
                   "manifest sealed inodes were unexpectedly shared across distinct domains")
