"""Observes original cross-pack dictionary ranges, funding and cache handoff."""

import struct
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
