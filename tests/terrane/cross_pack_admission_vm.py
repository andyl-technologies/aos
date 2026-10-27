"""Observes original cross-pack dictionary ranges, funding and cache handoff."""

import os
import signal
import struct
import time
import tomllib

from encoded_eviction_vm import Original
from source_cleanup_vm import files, quota


def records(driver, root, byte, count):
    """Parses the actual original pair without relying on actor-reported ranges."""
    prefix = root / "objects/pack" / f"{byte:02x}" / (f"{byte:02x}" * 16)
    pair = prefix.with_suffix(".pack").read_bytes()
    index = prefix.with_suffix(".idx").read_bytes()
    driver.require(pair[:8] == b"TRPK\x01\0\0\0"
                   and pair[8:24] == bytes([byte]) * 16 and pair[-4:] == b"TRPE",
                   "cross-pack observer found another original data header")
    offset = struct.unpack_from("<Q", pair, len(pair) - 16)[0]
    driver.require(pair[offset:offset + 4] == b"TRIX"
                   and struct.unpack_from("<Q", pair, offset + 4)[0] == count
                   and offset + 12 + count * 56 == len(pair) - 16
                   and index == pair[:24] + pair[offset:-16],
                   "cross-pack observer lost the original detached index binding")
    result = {}
    for position in range(count):
        record = pair[offset + 12 + position * 56:offset + 12 + (position + 1) * 56]
        start, size, length, codec, kind = struct.unpack_from("<QIIBB", record, 32)
        driver.require(24 <= start < start + size <= offset and kind == 0
                       and codec in (0, 2) and record[50:] == bytes(6)
                       and pair[start] == codec and record[:32].hex() not in result,
                       "cross-pack observer found invalid original chunk metadata")
        result[record[:32].hex()] = (length, codec, pair[start:start + size])
    return pair, index, result


def run(driver, uuid):
    """Checks two actual pairs and a consumer spanning source protection changes."""
    case = "admission-cross-pack"
    root = driver.root(case)
    snapshot = root / "state/cache/records.toml"
    process = driver.controlled_actor(case, "admit-cross-pack", uuid)
    lines = driver.Lines(process)
    originals = []

    def control(value):
        process.stdin.write((value + "\n").encode())
        process.stdin.flush()

    try:
        lines.until("READY cross-pack dictionary graph retains two funded original pairs", timeout=30)
        driver.require(lines.bytes.decode().splitlines().count(
            "ACK actual empty recovery Resume; no Ready") == 1,
            "cross-pack actor lacks genuine empty recovery and Resume")
        print(driver.process_status(process, 840), flush=True)
        paths = sorted((root / "objects/pack").glob("*/*"))
        driver.require(len(paths) == 4 and len({path.stem for path in paths}) == 2,
                       "cross-pack observer did not find two complete original pairs")
        for path in paths:
            originals.append(Original(driver, case, path, 840))
        driver.require(len({original.key[:2] for original in originals}) == 4,
                       "cross-pack members alias an original inode")
        source, source_index, dictionary_records = records(driver, root, 122, 2)
        dependent, dependent_index, root_records = records(driver, root, 121, 1)
        terminal = b"producer packed terminal vocabulary " * 16
        middle = b"producer packed terminal vocabulary intermediate " * 64
        content = b"producer packed terminal vocabulary intermediate content " * 128
        by_length = {length: (digest, codec, body)
                     for digest, (length, codec, body) in dictionary_records.items()}
        driver.require(set(by_length) == {len(terminal), len(middle)},
                       "dictionary pair contains another original record graph")
        terminal_id, terminal_codec, terminal_body = by_length[len(terminal)]
        middle_id, middle_codec, middle_body = by_length[len(middle)]
        root_id, (root_length, root_codec, root_body) = next(iter(root_records.items()))
        driver.require(terminal_codec == 0 and terminal_body == b"\0" + terminal
                       and middle_codec == root_codec == 2 and root_length == len(content)
                       and middle_body[1:33].hex() == terminal_id
                       and root_body[1:33].hex() == middle_id
                       and root_id not in dictionary_records,
                       "cross-pack observer found another original dictionary edge")
        before = files(root / "objects/pack")
        policy = tomllib.loads(snapshot.read_text())
        groups = {}
        for row in policy["pins"]:
            driver.require(row["owner"].startswith("admission:"),
                           "cross-pack producer unexpectedly lost original protection")
            groups.setdefault(row["owner"], set()).add(row["hash"])
        driver.require(len(groups) == 2 and sorted(map(len, groups.values())) == [3, 4],
                       "cross-pack producer pin closure differs from actual jobs")
        source_pins = next(value for value in groups.values() if len(value) == 3)
        dependent_pins = next(value for value in groups.values() if len(value) == 4)
        containers = source_pins - set(dictionary_records)
        driver.require(set(dictionary_records) <= source_pins and len(containers) == 1
                       and {root_id, middle_id} | containers <= dependent_pins
                       and len(dependent_pins - ({root_id, middle_id} | containers)) == 1,
                       "dependent funding omits the actual dictionary pack container")
        holds = [262144, 262144 + len(source) + len(source_index),
                 262144 + len(dependent) + len(dependent_index)]
        driver.require(sorted(row["bytes"] for row in policy["reservations"]) == sorted(holds)
                       and len(policy["leases"]) == 2
                       and quota(driver, case) + sum(holds) <= 6 * 1024 * 1024
                       and not files(root / "chunks") and not files(root / "pending-delete"),
                       "cross-pack producer funding or physical namespace differs")

        control("handoff-cross-pack")
        lines.until("READY cross-pack reads retain original pairs through dictionary cache handoff", timeout=30)
        policy = tomllib.loads(snapshot.read_text())
        dependencies = [row for row in policy["pins"]
                        if row["owner"].startswith("cache-dependency:")]
        driver.require(len(dependencies) == 2
                       and {row["hash"] for row in dependencies} == {middle_id} | containers
                       and len(policy["reservations"]) == 1
                       and policy["reservations"][0]["bytes"] == 262144
                       and not any(row["owner"].startswith("admission:") for row in policy["pins"])
                       and files(root / "objects/pack") == before
                       and not files(root / "chunks") and not files(root / "pending-delete"),
                       "cross-pack cache handoff lost source container custody or extracted data")
        for original in originals:
            original.check(1)
        control("cross-pack-observed")
        remaining, error = process.communicate(timeout=10)
        driver.require(process.returncode == 0 and not error and remaining.decode().splitlines() == [
            "PASS actual cross-pack dictionary reads retain both original pairs through producer and cache handoff without extraction; no Ready"
        ], "cross-pack native actor did not complete original consumer reads")
        print("PASS independent observer verifies four original cross-pack inodes, exact dictionary edges and durable container protection", flush=True)
    except BaseException:
        print(lines.bytes[lines.printed:].decode(), end="", flush=True)
        if process.poll() is None:
            process.kill()
        remaining, error = process.communicate(timeout=5)
        print(remaining.decode(), end="", flush=True)
        if error:
            print(error.decode(), end="", flush=True)
        raise
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for original in originals:
            original.close()


def run_standalone(driver, uuid):
    """Checks a real standalone root retaining its original packed dictionaries."""
    case = "admission-packed-dictionary"
    root = driver.root(case)
    snapshot = root / "state/cache/records.toml"
    process = driver.controlled_actor(case, "admit-packed-dictionary", uuid)
    lines = driver.Lines(process)
    originals = []

    def control(value):
        process.stdin.write((value + "\n").encode())
        process.stdin.flush()

    try:
        lines.until("READY standalone root retains one funded chunk and original dictionary pair", timeout=30)
        driver.require(lines.bytes.decode().splitlines().count(
            "ACK actual empty recovery Resume; no Ready") == 1,
            "standalone packed-dictionary actor lacks genuine recovery and Resume")
        print(driver.process_status(process, 840), flush=True)
        pair_paths = sorted((root / "objects/pack").glob("*/*"))
        chunk_paths = sorted((root / "chunks").glob("*/*"))
        driver.require(len(pair_paths) == 2 and len(chunk_paths) == 1,
                       "standalone admission lost original pair or extracted dictionaries")
        for path in pair_paths + chunk_paths:
            originals.append(Original(driver, case, path, 840))
        driver.require(len({original.key[:2] for original in originals}) == 3,
                       "standalone packed-dictionary members alias an original inode")
        pair, index, dictionary_records = records(driver, root, 122, 2)
        terminal = b"producer packed terminal vocabulary " * 16
        middle = b"producer packed terminal vocabulary intermediate " * 64
        by_length = {length: (digest, codec, body)
                     for digest, (length, codec, body) in dictionary_records.items()}
        driver.require(set(by_length) == {len(terminal), len(middle)},
                       "standalone dictionary pair contains unexpected records")
        terminal_id, terminal_codec, terminal_body = by_length[len(terminal)]
        middle_id, middle_codec, middle_body = by_length[len(middle)]
        body = chunk_paths[0].read_bytes()
        root_id = chunk_paths[0].name.removesuffix(".2")
        driver.require(chunk_paths[0].name.endswith(".2") and len(root_id) == 64
                       and body[0] == middle_codec == 2 and terminal_codec == 0
                       and terminal_body == b"\0" + terminal
                       and middle_body[1:33].hex() == terminal_id
                       and body[1:33].hex() == middle_id and root_id not in dictionary_records,
                       "standalone original envelope has different dictionary edges")
        namespace = {name: files(root / name) for name in ["chunks", "objects/pack", "pending-delete"]}
        policy = tomllib.loads(snapshot.read_text())
        groups = {}
        for row in policy["pins"]:
            driver.require(row["owner"].startswith("admission:"), "standalone producer lost native funding")
            groups.setdefault(row["owner"], set()).add(row["hash"])
        driver.require(len(groups) == 2 and all(len(group) == 3 for group in groups.values()),
                       "standalone producer pin closure differs from actual source units")
        source_pins = next((group for group in groups.values() if set(dictionary_records) <= group), set())
        containers = source_pins - set(dictionary_records)
        driver.require(len(containers) == 1
                       and {root_id, middle_id} | containers in groups.values(),
                       "standalone funding omits its actual dictionary container")
        holds = [262144, 262144 + len(pair) + len(index), 262144 + len(body)]
        driver.require(sorted(row["bytes"] for row in policy["reservations"]) == sorted(holds)
                       and len(policy["leases"]) == 2
                       and quota(driver, case) + sum(holds) <= 6 * 1024 * 1024
                       and not namespace["pending-delete"],
                       "standalone original quota and funding differ")
        control("handoff-packed-dictionary")
        lines.until("READY standalone reads preserve original packed dictionaries across cache handoff", timeout=30)
        policy = tomllib.loads(snapshot.read_text())
        dependencies = [row for row in policy["pins"] if row["owner"].startswith("cache-dependency:")]
        driver.require(len(dependencies) == 2
                       and {row["hash"] for row in dependencies} == {middle_id} | containers
                       and len(policy["reservations"]) == 1
                       and policy["reservations"][0]["bytes"] == 262144
                       and not any(row["owner"].startswith("admission:") for row in policy["pins"])
                       and {name: files(root / name) for name in namespace} == namespace,
                       "standalone handoff changed original custody, protection or names")
        for original in originals:
            original.check(1)
        control("packed-dictionary-observed")
        remaining, error = process.communicate(timeout=10)
        driver.require(process.returncode == 0 and not error and remaining.decode().splitlines() == [
            "PASS actual standalone consumers retain original nested packed dictionaries through producer and cache handoff without extraction; no Ready"
        ], "standalone packed-dictionary actor did not complete original reads")
        print("PASS independent observer verifies original standalone chunk, dictionary pair, funding and container protection", flush=True)
    except BaseException:
        print(lines.bytes[lines.printed:].decode(), end="", flush=True)
        if process.poll() is None:
            process.kill()
        remaining, error = process.communicate(timeout=5)
        print(remaining.decode(), end="", flush=True)
        if error:
            print(error.decode(), end="", flush=True)
        raise
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for original in originals:
            original.close()


def run_publications(driver, uuid, processes):
    """Checks real packed-dictionary publication, handoff and waiter cancellation."""
    for cancelled in (False, True):
        case = "publication-packed-dictionary" + ("-cancel" if cancelled else "")
        mode = "publish-packed-dictionary" + ("-cancel" if cancelled else "")
        publisher = processes[driver.CASES.index(case) // driver.CASES_PER_PARTITION][1]
        root = driver.root(case)
        snapshot = root / "state/cache/records.toml"
        process = driver.controlled_actor(case, mode, uuid)
        lines = driver.Lines(process)
        originals = []
        stopped = False

        def control(value):
            process.stdin.write((value + "\n").encode())
            process.stdin.flush()

        def wait_for(predicate, message):
            deadline = time.monotonic() + 30
            while not predicate():
                driver.require(process.poll() is None and publisher.poll() is None
                               and time.monotonic() < deadline, message)
                time.sleep(0.02)

        def policy():
            return tomllib.loads(snapshot.read_text())

        def pins(state, prefix):
            groups = {}
            for row in state.get("pins", []):
                if row["owner"].startswith(prefix):
                    groups.setdefault(row["owner"], []).append(row)
            return groups

        def protected(state, prefix, hashes):
            groups = pins(state, prefix)
            driver.require(len(groups) == 1, "packed publication lost its original promise")
            purpose, rows = next(iter(groups.items()))
            leases = [row for row in state.get("leases", []) if row["owner"] == purpose]
            driver.require(len(rows) == len(hashes) and {row["hash"] for row in rows} == hashes
                           and len(leases) == 1
                           and all(row["expires"] == leases[0]["expires"] for row in rows),
                           "packed publication lost exact original dictionary/container pins")
            if prefix == "publication:":
                driver.require(leases[0]["expires"] == 2**63 - 1,
                               "packed producer promise unexpectedly expires")
            else:
                driver.require(time.time() < leases[0]["expires"] <= time.time() + 31,
                               "packed publication handoff lacks bounded synchronized grace")
            return purpose

        def descriptors(expected):
            for original in originals[:2]:
                count = 0
                for path in (driver.pathlib.Path("/proc") / str(process.pid) / "fd").iterdir():
                    try:
                        value = path.stat()
                    except FileNotFoundError:
                        continue
                    count += (value.st_dev, value.st_ino) == original.key[:2]
                driver.require(count == expected,
                               "independent observer found changed original dictionary descriptors")

        try:
            lines.until("READY inline packed dictionaries retain original funded pair", timeout=30)
            driver.require(lines.bytes.decode().splitlines().count(
                "ACK actual empty recovery Resume; no Ready") == 1,
                "packed publication lacks genuine empty recovery and Resume")
            print(driver.process_status(process, 840), flush=True)
            paths = sorted((root / "objects/pack").glob("*/*"))
            driver.require(len(paths) == 2, "packed publication lacks original dictionary pair")
            for path in paths:
                originals.append(Original(driver, case, path, 840))
            pair, index, entries = records(driver, root, 122, 2)
            terminal = b"producer packed terminal vocabulary " * 16
            middle = b"producer packed terminal vocabulary intermediate " * 64
            content = b"producer packed terminal vocabulary intermediate content " * 128
            by_length = {length: (digest, codec, body)
                         for digest, (length, codec, body) in entries.items()}
            driver.require(set(by_length) == {len(terminal), len(middle)},
                           "packed publication dictionary record lengths differ")
            terminal_id, terminal_codec, terminal_body = by_length[len(terminal)]
            middle_id, middle_codec, middle_body = by_length[len(middle)]
            driver.require(terminal_codec == 0 and terminal_body == b"\0" + terminal
                           and middle_codec == 2 and middle_body[1:33].hex() == terminal_id,
                           "packed publication observer found another original dictionary graph")
            state = policy()
            groups = pins(state, "admission:")
            driver.require(len(groups) == 1, "packed publication original admission absent")
            source_pins = {row["hash"] for row in next(iter(groups.values()))}
            containers = source_pins - set(entries)
            driver.require(len(source_pins) == 3 and len(containers) == 1
                           and set(entries) <= source_pins,
                           "original dictionary producer omits its container")
            source_hold = 262144 + len(pair) + len(index)
            driver.require(sorted(row["bytes"] for row in state["reservations"])
                           == [262144, source_hold] and not state.get("residences")
                           and not files(root / "chunks") and not files(root / "sealed"),
                           "packed publication original namespace or funding differs")
            before = files(root / "objects/pack")

            if cancelled:
                os.kill(publisher.pid, signal.SIGSTOP)
                stopped = True
                wait_for(lambda: "\nState:\tT" in (
                    driver.pathlib.Path("/proc") / str(publisher.pid) / "status").read_text(),
                    "actual partition publisher did not stop")
            control("publish-packed")
            if cancelled:
                lines.until("QUEUED inline packed dictionary publication", timeout=30)
                wait_for(lambda: len(pins(policy(), "publication:")) == 1,
                         "stopped packed publication did not synchronize funding")
                state = policy()
                rows = next(iter(pins(state, "publication:").values()))
                driver.require(len(rows) == 4 and source_pins < {row["hash"] for row in rows},
                               "pending physical publication lacks original complete dictionary closure")
                closure = {row["hash"] for row in rows}
                protected(state, "publication:", closure)
                holds = [262144, source_hold, 262144 + 2 * len(content)]
                driver.require(sorted(row["bytes"] for row in state["reservations"]) == sorted(holds)
                               and quota(driver, case) + sum(holds) <= 6 * 1024 * 1024
                               and not state.get("residences") and not files(root / "sealed"),
                               "stopped packed publication lost funded overlap or published early")
                descriptors(2)
                control("cancel-packed")
                lines.until("CANCELLED inline packed dictionary waiter; physical custody retained", timeout=10)
                driver.require(policy() == state,
                               "dropping packed waiter changed synchronized physical promises")
                os.kill(publisher.pid, signal.SIGCONT)
                stopped = False
                wait_for(lambda: len(policy().get("residences", [])) == 1
                         and len(files(root / "sealed")) == 1
                         and sorted(row["bytes"] for row in policy()["reservations"])
                         == sorted([262144, source_hold, 262144]),
                         "abandoned physical packed publication did not finish")
                control("resumed-packed")

            lines.until("READY inline packed publication retains original descriptors and four pins", timeout=30)
            state = policy()
            sealed = list((root / "sealed").glob("*/*"))
            driver.require(len(sealed) == 1 and sealed[0].read_bytes() == content
                           and sealed[0].stat().st_mode & 0o7777 == 0o400,
                           "packed publication did not create the actual sealed plaintext inode")
            originals.append(Original(driver, case, sealed[0], 841))
            driver.require(len({original.key[:2] for original in originals}) == 3,
                           "packed publication aliases original dictionary inodes")
            root_id = sealed[0].name
            closure = source_pins | {root_id}
            protected(state, "publication:", closure)
            driver.require(len(closure) == 4 and not pins(state, "admission:")
                           and sorted(row["bytes"] for row in state["reservations"]) == [262144] * 2
                           and state["residences"] == [{"chunk": root_id, "object": root_id,
                                                       "offset": 0, "length": len(content)}],
                           "packed publication source handoff changed settled native ownership")
            descriptors(2)
            control("handoff-packed-publication")
            lines.until("READY inline packed publication consumer and original custody verified", timeout=30)
            state = policy()
            protected(state, "publication:" if cancelled else "publication-grace:", closure)
            driver.require(cancelled or not pins(state, "publication:"),
                           "successful handoff retained obsolete producer promise")
            holds = [262144] * (2 if cancelled else 1)
            driver.require(sorted(row["bytes"] for row in state["reservations"]) == holds
                           and quota(driver, case) + sum(holds) <= 6 * 1024 * 1024
                           and files(root / "objects/pack") == before
                           and not files(root / "chunks") and not files(root / "pending-delete"),
                           "packed handoff lost funding, original pair or extraction freedom")
            descriptors(2 if cancelled else 1)
            for original in originals:
                original.check(1)
            control("packed-publication-observed")
            remaining, error = process.communicate(timeout=10)
            driver.require(process.returncode == 0 and not error and remaining.decode().splitlines() == [
                "PASS actual inline publication retains original packed dictionary closure through cancellation or synchronized cache handoff; no Ready"
            ], "packed publication native actor did not complete")
            print("PASS independent packed publication observer verifies original dictionary descriptors, exact closure, physical completion and "
                  + ("abandoned-waiter custody" if cancelled else "synchronized cache grace"), flush=True)
        except BaseException:
            print(lines.bytes[lines.printed:].decode(), end="", flush=True)
            if process.poll() is None:
                process.kill()
            remaining, error = process.communicate(timeout=5)
            print(remaining.decode(), end="", flush=True)
            if error:
                print(error.decode(), end="", flush=True)
            raise
        finally:
            if stopped:
                os.kill(publisher.pid, signal.SIGCONT)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for original in originals:
                original.close()
