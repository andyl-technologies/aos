"""Checks real Running manifest publication under the verified native supervisor."""

import pathlib
import signal
import stat
import time
import tomllib


def check_recovered_reassembly(driver, case, output, original):
    """Compares actual new sealed bytes and retirement against original recovery custody."""
    rows = [line.split() for line in output.splitlines()
            if line.startswith("RECOVERED_ASSEMBLY ")]
    driver.require(len(rows) == 1 and len(rows[0]) == 5,
                   "missing exact recovered reassembly native observations")
    _, manifest, prefix, inode, length = rows[0]
    driver.require(all(len(value) == 64 and all(char in "0123456789abcdef" for char in value)
                       for value in [manifest, prefix]), "invalid recovered reassembly identity")
    inode, length = int(inode), int(length)
    root = driver.root(case)
    body = root / "sealed" / manifest[:2] / manifest
    retired = root / "pending-delete" / prefix
    encoded = retired.read_bytes()
    actual = body.read_bytes()
    observed = retired.stat()
    sealed = body.stat()
    driver.require(len(encoded) == length + 1 and encoded[0] == 0
                   and actual == encoded[1:] + original["body"].read_bytes(),
                   "recovered assembly differs from actual original body and retired prefix")
    driver.require(observed.st_ino == inode and observed.st_nlink == 1
                   and observed.st_dev == original["body"].stat().st_dev
                   and sealed.st_uid == sealed.st_gid == 841
                   and sealed.st_nlink == 1 and sealed.st_mode & 0o7777 == 0o400,
                   "recovered reassembly changed actual native inode custody")
    driver.require(set((root / "pending-delete").iterdir()) == {retired}
                   and not list((root / "chunks" / prefix[:2]).glob(prefix + ".*")),
                   "recovered reassembly retired extra bodies or left duplicate new sources")
    leases = [tomllib.loads(path.read_text()) for path in
              (root / "state/publication").glob("retirement-*.toml")]
    driver.require(len(leases) == 1 and leases[0]["domain"] == driver.domain(case)
                   and leases[0]["device"] == observed.st_dev and leases[0]["inode"] == inode
                   and leases[0]["deadline_unix_ms"] > 0
                   and leases[0]["changed_seconds"] == observed.st_ctime_ns // 1_000_000_000
                   and leases[0]["changed_nanoseconds"] == observed.st_ctime_ns % 1_000_000_000,
                   "new prefix lost actual original-inode retirement registration")
    state = tomllib.loads((root / "state/cache/records.toml").read_text())
    driver.require(len(state["reservations"]) == 7 and len(state["leases"]) == 6
                   and len(state["pins"]) == 9, "recovered reassembly lost exact policy closure")
    new = [row for row in state["residences"] if row["chunk"] == prefix]
    old = [row for row in state["residences"] if row["chunk"] != prefix]
    driver.require(new == [{"chunk": prefix, "object": manifest, "offset": 0, "length": length}]
                   and old and all(row["object"] == original["body"].name for row in old),
                   "recovered reassembly replaced original residences with new offsets")
    driver.require(all(not list((root / "chunks" / row["chunk"][:2]).glob(row["chunk"] + ".*"))
                       for row in old), "recovered range gained another encoded canonical body")
    expected = "PASS actual reassembly reused recovered manifest ranges, preserved original residences and retired only its new standalone prefix; no Ready"
    driver.require(output.splitlines().count(expected) == 1,
                   "missing actual retained recovered source and new-prefix read results")


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
                               "PASS actual dictionary-backed manifest publication retained its original dictionary inode, pins and holds while retiring repeated sources; checked retained range reads with embedded state locked; no Ready"
                               if dictionary_backed else
                               "PASS actual manifest publication retained metadata, repeated-chunk ranges and pending original sources across later work; checked retained range reads with embedded state locked; no Ready")
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
    run_reuse(driver, publisher, uuid)


def run_reuse(driver, publisher, uuid):
    """Exercises actual resident sources for both valid and wrong whole-file hashes."""
    for suffix in ["", "-bad-whole"]:
        reuse_case(driver, publisher, uuid, suffix)


def reuse_case(driver, publisher, uuid, suffix):
    """Checks original native custody while a second object reuses sealed ranges."""
    case = "publication-manifest-reuse" + suffix
    process = driver.controlled_actor(case, "publish-manifest-reuse" + suffix, uuid)
    try:
        lines = driver.Lines(process)
        lines.until("READY original manifest backing and new standalone tail retained; wait for range reuse control")
        print(driver.process_status(process, 840), flush=True)
        root = driver.root(case)
        bodies = list((root / "sealed").glob("*/*"))
        pending = list((root / "pending-delete").iterdir())
        chunks = list((root / "chunks").glob("*/*"))
        metadata_files = list((root / "objects/pack").glob("*/*"))
        driver.require(len(bodies) == len(chunks) == 1 and len(pending) == 2
                       and len(metadata_files) == 4, "reuse lacks actual first backing and new input pair")
        first = bodies[0]
        first_identity = (first.stat().st_dev, first.stat().st_ino, first.read_bytes())
        prior = {path.name: (path.stat().st_dev, path.stat().st_ino, path.read_bytes()) for path in pending}
        ordered = sorted(prior.items(), key=lambda item: len(item[1][2]), reverse=True)
        repeated_hash, repeated = ordered[0]
        old_tail_hash, old_tail = ordered[1]
        driver.require(repeated[2][0] == old_tail[2][0] == 0 and len(repeated[2]) > 256 * 1024
                       and first_identity[2] == repeated[2][1:] * 2 + old_tail[2][1:],
                       "first reuse backing differs from its actual original sources")
        new_tail = chunks[0]
        new_stat = new_tail.stat()
        new_content = new_tail.read_bytes()
        new_hash, separator, codec = new_tail.name.partition(".")
        driver.require(separator and codec == "0" and new_content == b"\x00" + bytes([100]) * 31
                       and new_stat.st_uid == 840 and new_stat.st_gid == 845
                       and new_stat.st_mode & 0o7777 == 0o640 and new_stat.st_nlink == 1,
                       "new reuse tail lacks canonical admission custody")
        snapshot = root / "state/cache/records.toml"
        original_rows = tomllib.loads(snapshot.read_text())["residences"]
        first_length = len(repeated[2]) - 1
        driver.require(original_rows == [
            {"chunk": row[0], "object": first.name, "offset": row[1], "length": row[2]}
            for row in sorted([(repeated_hash, 0, first_length),
                               (old_tail_hash, 2 * first_length, len(old_tail[2]) - 1)])
        ], "reuse first ranges do not match actual original metadata")
        metadata = {path: (path.stat().st_ino, path.read_bytes()) for path in metadata_files}
        old_leases = {path: (path.stat().st_ino, path.read_bytes())
                      for path in (root / "state/publication").glob("retirement-*.toml")}
        driver.require(len(old_leases) == 2, "reuse first sources lost their original retirement records")
        staging = root / "staging" / str(publisher.pid)
        staging_inode = (staging.stat().st_dev, staging.stat().st_ino)
        expected_bytes = repeated[2][1:] * 2 + new_content[1:]
        if suffix:
            process.stdin.write(b"publish\n")
            process.stdin.flush()
            lines.until("REFUSED resident reassembly whole hash; original source still readable and anonymous output retained; no Ready")
            anonymous = []
            for path in pathlib.Path(f"/proc/{process.pid}/fd").iterdir():
                try:
                    observed = path.stat()
                    if (stat.S_ISREG(observed.st_mode) and observed.st_nlink == 0
                            and observed.st_uid == 840 and observed.st_size == len(expected_bytes)):
                        anonymous.append(path.read_bytes())
                except FileNotFoundError:
                    continue
            driver.require(anonymous == [expected_bytes], "failed resident whole hash lost its actual anonymous output")
        output, error = process.communicate(b"finish\n" if suffix else b"publish\n", timeout=30)
        print(output.decode(), end="", flush=True)
        if error:
            print(error.decode(), end="", flush=True)
        expected_result = ("PASS actual resident reassembly rejected the wrong whole hash, retained anonymous output and preserved original backing, ranges and sources; no Ready"
                           if suffix else
                           "PASS actual manifest reassembly reused pinned sealed ranges, retained original residences and retired only its new standalone source; no Ready")
        driver.require(process.returncode == 0 and output.decode().splitlines() == [expected_result],
                       "missing exact actual range reuse result: " + case)
        driver.require((first.stat().st_dev, first.stat().st_ino, first.read_bytes()) == first_identity,
                       "second assembly replaced or changed its original backing")
        for digest, previous in prior.items():
            path = root / "pending-delete" / digest
            driver.require((path.stat().st_dev, path.stat().st_ino, path.read_bytes()) == previous,
                           "reuse changed an original pending source inode")
        for path, previous in {**metadata, **old_leases}.items():
            driver.require((path.stat().st_ino, path.read_bytes()) == previous,
                           "reuse rewrote an original metadata or retirement record")
        driver.require((staging.stat().st_dev, staging.stat().st_ino) == staging_inode
                       and list(staging.iterdir()) == [], "reuse changed or leaked publisher staging")
        state = tomllib.loads(snapshot.read_text())
        bodies = list((root / "sealed").glob("*/*"))
        if suffix:
            driver.require(bodies == [first] and state["residences"] == original_rows
                           and list((root / "chunks").glob("*/*")) == [new_tail]
                           and (new_tail.stat().st_dev, new_tail.stat().st_ino, new_tail.read_bytes())
                               == (new_stat.st_dev, new_stat.st_ino, new_content)
                           and len(list((root / "pending-delete").iterdir())) == 2
                           and len(list((root / "state/publication").glob("retirement-*.toml"))) == 2,
                           "wrong whole hash created backing, moved original ranges or retired a source")
            return
        second = [path for path in bodies if path != first]
        driver.require(len(bodies) == 2 and len(second) == 1, "reuse lacks distinct actual second backing")
        second = second[0]
        second_stat = second.stat()
        driver.require((second_stat.st_dev, second_stat.st_ino) != first_identity[:2]
                       and second_stat.st_uid == second_stat.st_gid == 841
                       and second_stat.st_mode & 0o7777 == 0o400 and second_stat.st_nlink == 1
                       and second.read_bytes() == repeated[2][1:] * 2 + new_content[1:],
                       "second sealed bytes, inode or native custody differ")
        state = tomllib.loads(snapshot.read_text())
        expected_rows = original_rows + [{"chunk": new_hash, "object": second.name,
                                         "offset": 2 * first_length, "length": len(new_content) - 1}]
        driver.require(sorted(state["residences"], key=lambda row: row["chunk"]) == sorted(expected_rows, key=lambda row: row["chunk"])
                       and list((root / "chunks").glob("*/*")) == [],
                       "reuse moved an original range or left a duplicate standalone source")
        retired = root / "pending-delete" / new_hash
        driver.require((retired.stat().st_dev, retired.stat().st_ino, retired.read_bytes())
                       == (new_stat.st_dev, new_stat.st_ino, new_content)
                       and len(list((root / "pending-delete").iterdir())) == 3,
                       "reuse lost the new tail's actual native retirement")
        leases = [tomllib.loads(path.read_text()) for path in (root / "state/publication").glob("retirement-*.toml")]
        driver.require(len(leases) == 3 and any(lease["domain"] == driver.domain(case)
                       and lease["device"] == new_stat.st_dev and lease["inode"] == new_stat.st_ino
                       and lease["deadline_unix_ms"] > 0
                       and lease["changed_seconds"] == retired.stat().st_ctime_ns // 1_000_000_000
                       and lease["changed_nanoseconds"] == retired.stat().st_ctime_ns % 1_000_000_000
                       for lease in leases),
                       "reuse new source lacks its actual original-inode retirement lease")

    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
