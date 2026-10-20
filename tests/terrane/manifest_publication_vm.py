"""Checks real Running manifest publication under the verified native supervisor."""

import json
import os
import pathlib
import signal
import stat
import time
import tomllib


def seed_cold_policy(driver, case, body, companions):
    """Seeds durable policy candidates; actual roles must verify their backing."""
    if case not in {"manifest-sealed-writable", "manifest-mixed"}:
        return None

    pinned = body if case == "manifest-sealed-writable" else companions[0]
    cold = {
        "pins": [{"owner": "fixture-cold-consumer", "hash": pinned.name,
                  "expires": 9223372036854775807}],
        "leases": [{"owner": "fixture-cold-consumer", "expires": 9223372036854775807}],
        "reservations": [],
        "residences": [],
    }
    if case == "manifest-sealed-writable":
        cold["reservations"] = [{"id": "fixture-cold-hold", "owner": driver.owner(case),
                                 "bytes": 262144}]
    else:
        cold["residences"] = [{"chunk": pinned.name, "object": pinned.name,
                               "offset": 0, "length": len(driver.INLINE_BYTES)}]

    lines = ["version = 1"]
    for group, rows in cold.items():
        if not rows:
            lines.append(group + " = []")
    for group, rows in cold.items():
        for row in rows:
            lines.append("[[" + group + "]]")
            lines.extend(key + " = " + json.dumps(value) for key, value in row.items())

    policy = driver.root(case) / "state/cache/records.toml"
    policy.write_text("\n".join(lines) + "\n")
    driver.metadata(policy, 840, 844, 0o660)
    with policy.open("rb") as stream:
        os.fsync(stream.fileno())
    directory = os.open(policy.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return cold


def check_cold_policy(driver, case, output, original):
    """Checks original cold policy after real recovery and subsequent writes."""
    if original["cold_policy"] is None:
        return

    actual = tomllib.loads((driver.root(case) / "state/cache/records.toml").read_text())
    for group, rows in original["cold_policy"].items():
        driver.require(all(actual[group].count(row) == 1 for row in rows),
                       "recovery changed or removed original cold " + group)
    driver.require("PASS actual cold consumer pins, leases and holds reconciled with verified native backing; original records retained"
                   in output.splitlines(), "missing actual cold policy recovery control")
    print("PASS actual native recovery retained original cold policy and verified backing: " + case,
          flush=True)


def run_mixed_source_pin(driver, helper, uuid, original):
    """Drops a real inline source waiter with Q stopped, then checks unique durable custody."""
    case = "manifest-mixed"
    process = driver.controlled_actor(case, "recover-mixed-manifest", uuid)
    stopped = False
    lines = driver.Lines(process)
    try:
        lines.until("READY actual mixed recovery and old source retained; wait for inline pin control")
        print(driver.process_status(process, 840), flush=True)
        snapshot = driver.root(case) / "state/cache/records.toml"
        before = tomllib.loads(snapshot.read_text())
        helper.send_signal(signal.SIGSTOP)
        stopped = True
        deadline = time.monotonic() + 2
        while True:
            status = (pathlib.Path("/proc") / str(helper.pid) / "status").read_text()
            if any(line.startswith("State:\tT") for line in status.splitlines()):
                break
            driver.require(helper.poll() is None and time.monotonic() < deadline,
                           "actual quota helper did not enter stopped state")
            time.sleep(0.005)
        process.stdin.write(b"pin\n")
        process.stdin.flush()
        lines.until("CANCELLED accepted inline source waiter; original sealed source read while quota helper stopped")
        helper.send_signal(signal.SIGCONT)
        stopped = False
        # The first command must write its actual pin before a second request
        # can conceal cancellation by independently doing the work itself.
        deadline = time.monotonic() + 10
        while True:
            pending = tomllib.loads(snapshot.read_text())
            source_pins = [row for row in pending["pins"] if row["owner"].startswith("source:")]
            if len(source_pins) == 1:
                break
            driver.require(process.poll() is None and time.monotonic() < deadline,
                           "dropped source waiter cancelled actual physical pin work")
            time.sleep(0.01)
        process.stdin.write(b"resumed\n")
        process.stdin.flush()
        lines.until("READY original recovered inline pin checked; wait for assembly control")
        full = lines.bytes.decode()
        result = "PASS actual recovered inline source retained its durable pin after a dropped waiter and read with policy held; repeated preparation preserved the original hold; no Ready"
        driver.require(full.splitlines().count(result) == 1, "missing actual retained inline source result")
        after = tomllib.loads(snapshot.read_text())
        driver.require(after["residences"] == before["residences"],
                       "source pin changed actual original recovered residences")
        added = {}
        for group in ["pins", "leases", "reservations"]:
            driver.require(all(row in after[group] for row in before[group])
                           and len(after[group]) == len(before[group]) + 1,
                           "inline source pin lost original durable " + group)
            added[group] = [row for row in after[group] if row not in before[group]]
            driver.require(len(added[group]) == 1, "inline source duplicated actual " + group)
        pin, lease, hold = added["pins"][0], added["leases"][0], added["reservations"][0]
        body = original["companions"][0][0]
        driver.require(pin["hash"] == body.name and pin["owner"] == lease["owner"] == "source:" + hold["id"]
                       and pin["expires"] == lease["expires"] == 9223372036854775807
                       and hold["owner"] == driver.owner(case) and hold["bytes"] == 256 * 1024,
                       "inline source lacks original object, lease, future hold or expiry")
        print("PASS actual dropped inline waiter completed one durable source pin before re-request; original custody and repeated hold verified", flush=True)
        output, _ = process.communicate(b"assemble\n", timeout=15)
        print(output.decode(), end="", flush=True)
        driver.require(process.returncode == 0, "actual recovered inline reassembly actor failed")
        full = (lines.bytes + output).decode()
        check_recovered_reassembly(driver, case, full, {"body": body}, prior=after)
        print("PASS actual new assembly reused original pinned inline recovery and retained its original residence; no Ready", flush=True)
        return full
    finally:
        if stopped and helper.poll() is None:
            helper.send_signal(signal.SIGCONT)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def check_recovered_reassembly(driver, case, output, original, prior=None):
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
    expected = {"reservations": 7, "leases": 6, "pins": 10} if prior is None else {
        "reservations": len(prior["reservations"]) + 4,
        "leases": len(prior["leases"]) + 4, "pins": len(prior["pins"]) + 7}
    driver.require(all(len(state[group]) == count for group, count in expected.items()),
                   "recovered reassembly lost exact policy closure")
    # Every recovered range in this assembly comes from this actual original
    # sealed inode. Its independent producer pin must survive the copy even
    # when the old recovery owner releases its own protection later.
    producers = [row for row in state["pins"]
                 if row["hash"] == manifest and row["owner"].startswith("publication:")]
    driver.require(len(producers) == 1, "recovered assembly lacks one actual producer")
    producer = producers[0]
    driver.require(sorted(row["hash"] for row in state["pins"]
                          if row["owner"] == producer["owner"]
                          and row["expires"] == producer["expires"])
                   == sorted([manifest, original["body"].name]),
                   "recovered assembly lost its exact original backing dependency pin")
    new = [row for row in state["residences"] if row["chunk"] == prefix]
    old = [row for row in state["residences"] if row["chunk"] != prefix]
    old_match = old and (all(row["object"] == original["body"].name for row in old)
                        if prior is None else
                        sorted(old, key=lambda row: row["chunk"]) ==
                        sorted(prior["residences"], key=lambda row: row["chunk"]))
    driver.require(new == [{"chunk": prefix, "object": manifest, "offset": 0, "length": length}]
                   and old_match,
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
                        publication = [row for row in state["leases"] if row["owner"].startswith("publication:")]
                        driver.require(len(publication) == 1, "stopped publication lost its actual owner")
                        token = publication[0]["owner"].removeprefix("publication:")
                        driver.require({"id": token, "owner": driver.owner(case),
                                        "bytes": 262144 + 2 * len(expected_bytes)} in state["reservations"],
                                       "stopped manifest copy released its actual overlap budget")
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
            publication_leases = [row for row in state["leases"] if row["owner"].startswith("publication:")]
            driver.require(len(publication_leases) == 1, "missing actual publication funding owner")
            publication_id = publication_leases[0]["owner"].removeprefix("publication:")
            publication_holds = [row for row in state["reservations"] if row["id"] == publication_id]
            driver.require(publication_holds == [{"id": publication_id, "owner": driver.owner(case),
                                                  "bytes": 262144 + (2 * len(expected_bytes) if suffix == "-bad-whole" else 0)}],
                           "publication settled uncertain copy capacity or retained completed overlap")
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
        expected_lines = [expected_result] if suffix else [
            "PASS native shared-directory manifest ranges, original residences, held-policy reads and independent release revocation",
            expected_result,
        ]
        driver.require(process.returncode == 0 and output.decode().splitlines() == expected_lines,
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
        # The three actual grants protect backing objects, including two
        # different ranges in the first inode. Release preserves those promises
        # through real grace; shared-directory clones create no extra grants.
        grace_leases = [row for row in state["leases"] if row["owner"].startswith("consumer-grace:")]
        grace_pins = [row for row in state["pins"] if row["owner"].startswith("consumer-grace:")]
        driver.require(len(grace_leases) == len(grace_pins) == 3
                       and len({row["owner"] for row in grace_leases}) == 3
                       and sorted(row["hash"] for row in grace_pins)
                           == sorted([first.name, first.name, second.name])
                       and not any(row["owner"].startswith("consumer:") for row in state["leases"]),
                       "shared manifest ranges lack independent original backing protection")
        for lease in grace_leases:
            token = lease["owner"].removeprefix("consumer-grace:")
            driver.require(len(token) == 32 and all(character in "0123456789abcdef" for character in token)
                           and lease["expires"] > int(time.time())
                           and len([row for row in grace_pins
                                    if row["owner"] == lease["owner"] and row["expires"] == lease["expires"]]) == 1
                           and state["reservations"].count({"id": token, "owner": driver.owner(case),
                                                           "bytes": 262144}) == 1,
                           "shared manifest release lost its actual grace or distinct future funding")
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


def run_consumer_leases(driver, helper, uuid):
    """Checks actual durable consumer effects independently of opaque API replies."""
    import subprocess

    case = "consumer-leases"
    environment = driver.actor_environment(case, uuid)
    environment.update(TERRANE_LEASE_FOREIGN_ROOT=str(driver.root("lease-foreign")),
                       TERRANE_LEASE_FOREIGN_PROJECT=str(driver.project("lease-foreign")))
    process = subprocess.Popen(driver.role_command(840, [driver.IMAGE / "bin/host_cache_fixture", "consumer-leases"]),
                               env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    lines = driver.Lines(process)
    stopped = False
    policy = driver.root(case) / "state/cache/records.toml"
    plaintext = b"actual consumer lease retains original immutable backing"
    try:
        lines.until("actual pin and policy-held read checked", timeout=20)
        print(driver.process_status(process, 840), flush=True)
        ready = [row.split() for row in lines.bytes.decode().splitlines()
                 if row.startswith("READY consumer lease ")]
        driver.require(len(ready) == 1, "missing actual consumer pin completion")
        name, expiry, inode = ready[0][3:6]
        expiry, inode = int(expiry), int(inode[:-1])
        token = name.removeprefix("consumer:")
        driver.require(name == "consumer:" + token and len(token) == 32
                       and all(c in "0123456789abcdef" for c in token),
                       "consumer owner is not a unique operation identifier")
        initial = tomllib.loads(policy.read_text())
        pins = [row for row in initial["pins"] if row["owner"] == name]
        driver.require(len(pins) == 1 and pins[0]["expires"] == expiry,
                       "acknowledged consumer pin missing from actual snapshot")
        digest = pins[0]["hash"]
        body = driver.root(case) / "sealed" / digest[:2] / digest
        metadata = body.stat()
        driver.require(body.read_bytes() == plaintext and metadata.st_ino == inode
                       and metadata.st_uid == metadata.st_gid == 841
                       and metadata.st_nlink == 1 and metadata.st_mode & 0o7777 == 0o400,
                       "consumer backing differs from original actual sealed inode")
        held = {"id": token, "owner": driver.owner(case), "bytes": 262144}
        leased = {"owner": name, "expires": expiry}
        driver.require(initial["reservations"].count(held) == 1
                       and initial["leases"].count(leased) == 1
                       and len(initial["reservations"]) == 3 and len(initial["pins"]) == 2
                       and len(initial["leases"]) == 2 and len(initial["residences"]) == 1,
                       "consumer pin lacks exact own future hold or producer policy")
        baseline = {group: [row for row in rows if row != removed]
                    for group, rows, removed in [
                        ("pins", initial["pins"], pins[0]),
                        ("leases", initial["leases"], leased),
                        ("reservations", initial["reservations"], held)]}
        baseline["residences"] = initial["residences"]
        publication = [row for row in baseline["leases"] if row["owner"].startswith("publication:")]
        driver.require(len(publication) == 1 and publication[0]["expires"] == 9223372036854775807
                       and baseline["pins"] == [{"owner": publication[0]["owner"], "hash": digest,
                                                "expires": 9223372036854775807}]
                       and sorted(row["bytes"] for row in baseline["reservations"])
                       == [262144, 262144],
                       "consumer baseline lost independently funded original publication")
        foreign = tomllib.loads((driver.root("lease-foreign") / "state/cache/records.toml").read_text())
        driver.require(len(foreign["reservations"]) == 1
                       and foreign["reservations"][0]["owner"] == driver.owner("lease-foreign")
                       and foreign["reservations"][0]["bytes"] == 262144
                       and all(foreign[group] == [] for group in ["pins", "leases", "residences"]),
                       "foreign actual native owner changed policy during misrouted commands")

        helper.send_signal(signal.SIGSTOP)
        stopped = True
        deadline = time.monotonic() + 1
        while True:
            status = (pathlib.Path("/proc") / str(helper.pid) / "status").read_text()
            if any(row.startswith("State:\tT") for row in status.splitlines()):
                break
            driver.require(helper.poll() is None and time.monotonic() < deadline,
                           "quota helper did not acknowledge actual stopped renewal control")
            time.sleep(0.005)
        process.stdin.write(b"renew\n")
        process.stdin.flush()
        lines.until("CANCELLED consumer renewal waiter; original grant read while quota helper stopped", timeout=1)
        driver.require(time.monotonic() < deadline,
                       "consumer read or cancellation stalled on actual embedded/quota locks")
        driver.require(tomllib.loads(policy.read_text()) == initial,
                       "stopped quota preflight already changed acknowledged consumer policy")
        helper.send_signal(signal.SIGCONT)
        stopped = False
        deadline = time.monotonic() + 10
        while True:
            renewed = tomllib.loads(policy.read_text())
            if {"owner": name, "expires": expiry + 90} in renewed["leases"]:
                break
            driver.require(process.poll() is None and time.monotonic() < deadline,
                           "dropped renewal waiter cancelled physical durable work")
            time.sleep(0.01)
        expected = dict(initial)
        expected["leases"] = [dict(row, expires=expiry + 90) if row["owner"] == name else row
                              for row in initial["leases"]]
        expected["pins"] = [dict(row, expires=expiry + 90) if row["owner"] == name else row
                            for row in initial["pins"]]
        driver.require(renewed == expected,
                       "accepted abandoned renewal changed unrelated actual policy or funding")
        print("PASS actual dropped consumer renewal completed durable update before any barrier; original grant read with quota helper stopped", flush=True)
        process.stdin.write(b"completed\n")
        process.stdin.flush()
        lines.until("release grace retained without inode duplication")
        repins = [row.split() for row in lines.bytes.decode().splitlines()
                  if row.startswith("READY consumer re-pin ")]
        driver.require(len(repins) == 1, "missing actual consumer re-pin completion")
        second, second_expiry, grace = repins[0][3:6]
        second_expiry, grace = int(second_expiry), int(grace[:-1])
        during = tomllib.loads(policy.read_text())
        grace_owner = "consumer-grace:" + token
        driver.require(second != name and grace > int(time.time())
                       and {"owner": grace_owner, "expires": grace} in during["leases"]
                       and {"owner": grace_owner, "hash": digest, "expires": grace} in during["pins"]
                       and {"owner": second, "expires": second_expiry} in during["leases"]
                       and {"owner": second, "hash": digest, "expires": second_expiry} in during["pins"]
                       and len(during["leases"]) == len(during["pins"]) == 3
                       and len(during["reservations"]) == 4 and held in during["reservations"]
                       and {"id": second.removeprefix("consumer:"), "owner": driver.owner(case),
                            "bytes": 262144} in during["reservations"]
                       and during["residences"] == baseline["residences"]
                       and body.stat().st_ino == inode and body.read_bytes() == plaintext,
                       "release or immediate re-pin lost grace or duplicated native backing")
        process.stdin.write(b"expiry\n")
        process.stdin.flush()
        lines.until("EXPIRED actual consumer grant; renewal refused while durable grace remains", timeout=10)
        driver.require(tomllib.loads(policy.read_text()) == during,
                       "expiry was acknowledged as an early decrement before original grace")
        output, _ = process.communicate(timeout=40)
        print(output.decode(), end="", flush=True)
        full = (lines.bytes + output).decode()
        result = "PASS actual consumer pin, held-policy read, cancelled renewal, foreign-owner refusal, release, re-pin and periodic expiry; original inode and producer records retained"
        driver.require(process.returncode == 0 and full.splitlines().count(result) == 1,
                       "native consumer lifecycle did not actually complete")
        shared_result = "PASS native shared-directory sealed fallback, original grant, finite inventory, foreign-layout refusal, held-policy read and release revocation"
        driver.require(full.splitlines().count(shared_result) == 1,
                       "native shared-directory controls did not actually complete")
        final = tomllib.loads(policy.read_text())
        driver.require(all(final[group] == rows for group, rows in baseline.items())
                       and body.stat().st_ino == inode and body.read_bytes() == plaintext,
                       "periodic expiry failed actual own-hold cleanup or changed original backing")
        print("PASS actual consumer release grace and periodic expiry removed exactly their own durable holds, pins and leases; original producer and inode preserved", flush=True)
    finally:
        if stopped and helper.poll() is None:
            helper.send_signal(signal.SIGCONT)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
