"""Observes real encoded cache handoff, grace and original source retirement."""

import re
import struct
import time
import tomllib

from source_cleanup_vm import files, quota


def run_data_pack(driver, uuid):
    """Observes funded producer admission and same-inode handoff independently."""
    from encoded_eviction_vm import Original

    case = "admission-data-pack"
    root = driver.root(case)
    snapshot = root / "state/cache/records.toml"
    process = driver.controlled_actor(case, "admit-data-pack", uuid)
    lines = driver.Lines(process)
    originals = []

    def control(value):
        process.stdin.write((value + "\n").encode())
        process.stdin.flush()

    try:
        lines.until("READY actual producer data pair verified with original funding; no standalone copies", timeout=30)
        driver.require(lines.bytes.decode().splitlines().count(
            "ACK actual empty recovery Resume; no Ready") == 1,
            "producer data pair lacks actual empty recovery and Resume")
        print(driver.process_status(process, 840), flush=True)
        paths = sorted((root / "objects/pack").glob("*/*"))
        driver.require(len(paths) == 2 and {path.suffix for path in paths} == {".pack", ".idx"}
                       and all(path.stem == "78" * 16 and path.parent.name == "78" for path in paths),
                       "producer admission did not publish exactly one complete pair")
        for path in paths:
            originals.append(Original(driver, case, path, 840))
        pair = next(path for path in paths if path.suffix == ".pack").read_bytes()
        detached = next(path for path in paths if path.suffix == ".idx").read_bytes()
        driver.require(len(pair) >= 24 + 12 + 3 * 56 + 16
                       and pair[:4] == b"TRPK" and pair[4:8] == bytes([1, 0, 0, 0])
                       and pair[8:24] == bytes([120]) * 16 and pair[-4:] == b"TRPE",
                       "producer observer found another data-pack header")
        offset = struct.unpack_from("<Q", pair, len(pair) - 16)[0]
        driver.require(pair[offset:offset + 4] == b"TRIX"
                       and struct.unpack_from("<Q", pair, offset + 4)[0] == 3
                       and offset + 12 + 3 * 56 == len(pair) - 16
                       and detached == pair[:24] + pair[offset:-16],
                       "producer observer lost exact original detached index binding")
        records = {}
        for position in range(3):
            record = pair[offset + 12 + position * 56:offset + 12 + (position + 1) * 56]
            start, encoded, length, codec, kind = struct.unpack_from("<QIIBB", record, 32)
            driver.require(24 <= start < start + encoded <= offset and kind == 0
                           and codec in (0, 2) and record[50:] == bytes(6),
                           "producer observer found an invalid original chunk record")
            body = pair[start:start + encoded]
            driver.require(body[0] == codec and record[:32].hex() not in records,
                           "producer chunk codec or identity is ambiguous")
            records[record[:32].hex()] = (length, codec, body)
        terminal = b"producer packed terminal vocabulary " * 16
        middle = b"producer packed terminal vocabulary intermediate " * 64
        content = b"producer packed terminal vocabulary intermediate content " * 128
        by_length = {length: (digest, codec, body) for digest, (length, codec, body) in records.items()}
        driver.require(set(by_length) == {len(terminal), len(middle), len(content)},
                       "producer records do not contain the complete expected nested chain")
        terminal_id, terminal_codec, terminal_body = by_length[len(terminal)]
        middle_id, middle_codec, middle_body = by_length[len(middle)]
        _, content_codec, content_body = by_length[len(content)]
        driver.require(terminal_codec == 0 and terminal_body == b"\0" + terminal
                       and middle_codec == content_codec == 2
                       and middle_body[1:33].hex() == terminal_id
                       and content_body[1:33].hex() == middle_id,
                       "producer observer found a different original dictionary graph")
        before = files(root / "objects/pack")
        policy = tomllib.loads(snapshot.read_text())
        holds = policy["reservations"]
        driver.require(len(holds) == 2
                       and sorted(row["bytes"] for row in holds)
                       == [262144, 262144 + len(pair) + len(detached)]
                       and len(policy["pins"]) == 4
                       and {row["hash"] for row in policy["pins"]} >= set(records)
                       and all(row["owner"].startswith("admission:") for row in policy["pins"])
                       and len(policy["leases"]) == 1
                       and not files(root / "chunks") and not files(root / "pending-delete"),
                       "producer pair lacks distinct original funding and complete pin closure")
        driver.require(quota(driver, case) + sum(row["bytes"] for row in holds) <= 6 * 1024 * 1024,
                       "actual producer charge plus future funding exceeds capacity")
        control("handoff-data-pack")
        lines.until("READY actual producer data pair serves original nested envelopes after cache handoff", timeout=30)
        policy = tomllib.loads(snapshot.read_text())
        driver.require(len(policy["reservations"]) == 1 and policy["reservations"][0]["bytes"] == 262144
                       and not any(row["owner"].startswith("admission:") for row in policy["pins"])
                       and any(row["owner"].startswith("admission-grace:") for row in policy["pins"])
                       and files(root / "objects/pack") == before
                       and not files(root / "chunks") and not files(root / "pending-delete"),
                       "producer handoff changed original pair or retained producer funding/copies")
        for original in originals:
            original.check(1)
        control("data-pack-observed")
        remaining, error = process.communicate(timeout=10)
        driver.require(process.returncode == 0 and not error and remaining.decode().splitlines() == [
            "PASS actual producer data pair rejects invalid content before funding, retains both original members and serves nested chunks without extraction; no Ready"
        ], "producer data actor did not complete its actual native reads")
        print("PASS independent observer verifies producer data-pair funding, nested dictionary records and same-inode cache handoff", flush=True)
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


def run_external_data_pack(driver, uuid):
    """Binds a packed consumer to four original inodes and two dependency edges."""
    from encoded_eviction_vm import Original

    case = "admission-external-data-pack"
    root = driver.root(case)
    snapshot = root / "state/cache/records.toml"
    process = driver.controlled_actor(case, "admit-external-data-pack", uuid)
    lines = driver.Lines(process)
    originals = []

    def control(value):
        process.stdin.write((value + "\n").encode())
        process.stdin.flush()

    try:
        lines.until("READY external data pair retains genuine producer-held nested dictionaries", timeout=30)
        driver.require(lines.bytes.decode().splitlines().count(
            "ACK actual empty recovery Resume; no Ready") == 1,
            "external pack lacks genuine empty recovery and Resume")
        print(driver.process_status(process, 840), flush=True)
        chunk_paths = sorted((root / "chunks").glob("*/*"))
        pair_paths = sorted((root / "objects/pack").glob("*/*"))
        driver.require(len(chunk_paths) == 2 and {path.suffix for path in chunk_paths} == {".0", ".2"}
                       and len(pair_paths) == 2 and {path.suffix for path in pair_paths} == {".pack", ".idx"}
                       and all(path.stem == "79" * 16 and path.parent.name == "79" for path in pair_paths),
                       "external pack did not retain exactly two original dictionary files and its pair")
        for path in chunk_paths + pair_paths:
            originals.append(Original(driver, case, path, 840))
        terminal_path = next(path for path in chunk_paths if path.suffix == ".0")
        middle_path = next(path for path in chunk_paths if path.suffix == ".2")
        terminal = terminal_path.read_bytes()
        middle = middle_path.read_bytes()
        pair = next(path for path in pair_paths if path.suffix == ".pack").read_bytes()
        detached = next(path for path in pair_paths if path.suffix == ".idx").read_bytes()
        driver.require(terminal == b"\0" + b"producer packed terminal vocabulary " * 16
                       and middle[0] == 2 and middle[1:33].hex() == terminal_path.stem
                       and pair[:8] == b"TRPK\x01\0\0\0" and pair[8:24] == bytes([121]) * 16
                       and pair[-4:] == b"TRPE",
                       "external observer found a different standalone graph or data header")
        offset = struct.unpack_from("<Q", pair, len(pair) - 16)[0]
        driver.require(pair[offset:offset + 4] == b"TRIX"
                       and struct.unpack_from("<Q", pair, offset + 4)[0] == 1
                       and offset + 12 + 56 == len(pair) - 16
                       and detached == pair[:24] + pair[offset:-16],
                       "external pack lost its exact one-record detached index")
        record = pair[offset + 12:offset + 12 + 56]
        start, size, length, codec, kind = struct.unpack_from("<QIIBB", record, 32)
        driver.require(24 <= start < start + size <= offset and codec == 2 and kind == 0
                       and record[50:] == bytes(6)
                       and length == len(b"producer packed terminal vocabulary intermediate content " * 128)
                       and pair[start] == 2 and pair[start + 1:start + 33].hex() == middle_path.stem,
                       "packed root does not depend on the actual original middle dictionary")
        before_chunks = files(root / "chunks")
        before_pair = files(root / "objects/pack")
        policy = tomllib.loads(snapshot.read_text())
        expected_holds = [262144, 262144 + len(terminal), 262144 + len(middle),
                          262144 + len(pair) + len(detached)]
        driver.require(sorted(row["bytes"] for row in policy["reservations"]) == sorted(expected_holds)
                       and len(policy["pins"]) == 6 and len(policy["leases"]) == 3
                       and all(row["owner"].startswith("admission:") for row in policy["pins"])
                       and not files(root / "pending-delete"),
                       "external pair lacks actual producer funding and dictionary protection")
        driver.require(quota(driver, case) + sum(expected_holds) <= 6 * 1024 * 1024,
                       "external pack exceeds original physical capacity")

        control("handoff-external-pack")
        lines.until("READY external data pair reads original dictionaries before and after their cache handoff", timeout=30)

        policy = tomllib.loads(snapshot.read_text())
        dependencies = [row for row in policy["pins"] if row["owner"].startswith("cache-dependency:")]
        driver.require(len(policy["reservations"]) == 1 and policy["reservations"][0]["bytes"] == 262144
                       and len(dependencies) == 2
                       and {row["hash"] for row in dependencies} == {terminal_path.stem, middle_path.stem}
                       and not any(row["owner"].startswith("admission:") for row in policy["pins"])
                       and files(root / "chunks") == before_chunks
                       and files(root / "objects/pack") == before_pair
                       and not files(root / "pending-delete"),
                       "external dictionary handoff changed original inodes or lost dependency protection")
        for original in originals:
            original.check(1)
        control("external-pack-observed")
        remaining, error = process.communicate(timeout=10)
        driver.require(process.returncode == 0 and not error and remaining.decode().splitlines() == [
            "PASS actual external data pack retains nested standalone dictionary custody through producer and cache handoff without extraction; no Ready"
        ], "external dictionary native actor did not complete both consumer reads")
        print("PASS independent observer verifies four original external-pack inodes, nested dictionary edges and durable dependency handoff", flush=True)
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


def run(driver, uuid):
    """Checks actual resources independently of reports from the native actor."""
    case = "admission-cache"
    process = driver.controlled_actor(case, "cache-admission-handoff", uuid)
    lines = driver.Lines(process)
    root = driver.root(case)
    snapshot = root / "state/cache/records.toml"

    def control(value):
        process.stdin.write((value + "\n").encode())
        process.stdin.flush()

    def state():
        return tomllib.loads(snapshot.read_text())

    def rows(policy, group, prefix):
        return [row for row in policy.get(group, []) if row["owner"].startswith(prefix)]

    def cached(policy, grace, dependency, holds=1):
        driver.require(len(policy["reservations"]) == holds
                       and sum(row["bytes"] for row in policy["reservations"]) == holds * 262144
                       and not rows(policy, "pins", "admission:")
                       and not rows(policy, "leases", "admission:")
                       and len(rows(policy, "leases", "admission-grace:")) == grace
                       and len(rows(policy, "leases", "cache-dependency:")) == dependency
                       and len(rows(policy, "pins", "cache-dependency:")) == dependency,
                       "encoded handoff did not preserve exact original funding/dependencies")

    try:
        lines.until("READY accepted encoded handoff waiter cancelled with physical owner stalled",
                    timeout=30)
        driver.require(lines.bytes.decode().splitlines().count(
            "PASS full encoded handoff queue returns original admission without policy mutation") == 1,
            "encoded queue refusal did not preserve the original native receipt")
        print(driver.process_status(process, 840), flush=True)
        stalled = snapshot.read_bytes()
        chunks = files(root / "chunks")
        driver.require(len(chunks) == 3 and len(state()["reservations"]) == 2,
                       "cancelled encoded handoff lacks its original funded source")
        time.sleep(0.1)
        driver.require(process.poll() is None and snapshot.read_bytes() == stalled
                       and files(root / "chunks") == chunks,
                       "cancelled accepted waiter released custody while physical owner stalled")
        control("release-handoff")
        lines.until("READY genuine encoded chunks and metadata pair cached with original inodes retained",
                    timeout=30)
        canonical = files(root / "chunks")
        metadata = files(root / "objects")
        policy = state()
        cached(policy, 4, 1)
        driver.require(canonical == chunks and len(metadata) == 2
                       and not files(root / "pending-delete") and not files(root / "sealed"),
                       "encoded handoff replaced canonical inodes or lost the actual metadata pair")
        matches = re.findall(
            r"^ADMISSION_CACHE_GRACE expires=(\d+) charged_reserved_bytes=(\d+) future_hold_bytes=(\d+)$",
            lines.bytes.decode(), re.M)
        driver.require(len(matches) == 1, "missing unique original encoded handoff measurement")
        expires, charged, future = map(int, matches[0])
        actual_expiry = max(row["expires"] for row in rows(policy, "leases", "admission-grace:"))
        driver.require(expires == actual_expiry and future == 262144 and quota(driver, case) == charged,
                       "encoded report differs from actual synchronized deadline or helper quota")
        dictionary_hash = rows(policy, "pins", "cache-dependency:")[0]["hash"]
        dictionary_paths = [path for path in canonical if path.endswith(dictionary_hash + ".0")]
        driver.require(len(dictionary_paths) == 1,
                       "encoded dependency lacks its actual original dictionary inode")
        dictionary = {path: canonical[path] for path in dictionary_paths}
        sources = {path: value for path, value in canonical.items() if path not in dictionary}
        wait = expires - time.time() + 3
        driver.require(wait <= 34, "encoded release grace exceeds the configured native bound")
        if wait > 0:
            time.sleep(wait)
        expired = state()
        cached(expired, 0, 1)
        driver.require(process.poll() is None and files(root / "chunks") == canonical
                       and files(root / "objects") == metadata,
                       "real grace expiration lost encoded backing or dictionary protection")
        print("PASS independent observer verifies original encoded inodes, exact future funding and actual dictionary protection after durable grace",
              flush=True)
        control("after-grace")
        lines.until("READY genuine cached admissions transferred into verified sealed manifest", timeout=30)
        published = state()
        metadata_leases = rows(published, "leases", "metadata:")
        metadata_tokens = {row["owner"].removeprefix("metadata:") for row in metadata_leases}
        metadata_holds = [row for row in published["reservations"] if row["id"] in metadata_tokens]
        metadata_pins = rows(published, "pins", "metadata:")
        driver.require(len(metadata_leases) == len(metadata_holds) == 1
                       and len(metadata_pins) == 2 and metadata_holds[0]["bytes"] == 262144,
                       "published manifest lacks original durable reconstruction metadata custody")
        retained_holds = expired["reservations"] + metadata_holds
        pending = files(root / "pending-delete")
        sealed = files(root / "sealed")
        driver.require(len(sources) == len(pending) == 2 and len(sealed) == 1
                       and files(root / "chunks") == dictionary
                       and files(root / "objects") == metadata
                       and sorted(pending.values()) == sorted(sources.values()),
                       "publication did not retire the exact original cached source inodes")
        leases = [tomllib.loads(path.read_text()) for path in
                  (root / "state/publication").glob("retirement-*.toml")]
        deadlines = []
        for device, inode, _digest in sources.values():
            matching = [lease["deadline_unix_ms"] for lease in leases
                        if lease["device"] == device and lease["inode"] == inode
                        and lease["domain"] == driver.domain(case)]
            driver.require(len(matching) == 1,
                           "cached source lacks its original durable publisher retirement deadline")
            deadlines.extend(matching)
        wait = max(deadlines) / 1000 - time.time() + 3
        driver.require(wait <= 34, "cached source retirement exceeds configured native bound")
        if wait > 0:
            time.sleep(wait)
        driver.require(process.poll() is None and files(root / "pending-delete") == pending,
                       "cached source lost original pending custody before acknowledgement")
        control("finish-sources")
        lines.until("READY original cache owner retains dictionary and reconstruction pair after acknowledged source retirement",
                    timeout=30)
        final = state()
        cached(final, 0, 0, holds=2)
        measurements = re.findall(
            r"^ADMISSION_CACHE_FINAL charged_reserved_bytes=(\d+) future_hold_bytes=(\d+)$",
            lines.bytes.decode(), re.M)
        driver.require(len(measurements) == 1, "missing actual final encoded source accounting")
        final_charged, final_future = map(int, measurements[0])
        driver.require(process.poll() is None and not files(root / "pending-delete")
                       and files(root / "chunks") == dictionary
                       and files(root / "sealed") == sealed and files(root / "objects") == metadata
                       and rows(final, "pins", "metadata:") == metadata_pins
                       and rows(final, "leases", "metadata:") == metadata_leases
                       and sorted(final["reservations"], key=lambda row: row["id"])
                       == sorted(retained_holds, key=lambda row: row["id"])
                       and final_future == sum(row["bytes"] for row in retained_holds)
                       and quota(driver, case) == final_charged,
                       "acknowledged cached source cleanup lost reconstruction resources or exact quota")
        print("PASS independent observer verifies original cached source retirement and dependency release while reconstruction metadata and native owner remain live",
              flush=True)
        control("finish")
        lines.until("PASS genuine encoded cache handoff preserves queue retry, cancelled waiter custody, dictionary dependencies and native pair through grace and actual source retirement; no Ready",
                    timeout=15)
        output, error = process.communicate(timeout=10)
        driver.require(process.returncode == 0 and not output and not error,
                       "encoded cache handoff actor did not exit successfully")
    except BaseException:
        # Preserve the actual native refusal even if the actor exits before the
        # next handshake. Diagnostics never retry or qualify a failed operation.
        try:
            print(lines.bytes[lines.printed:].decode(), end="", flush=True)
            if process.poll() is None:
                process.kill()
            remaining, _ = process.communicate(timeout=5)
            print(remaining.decode(), end="", flush=True)
        except Exception as error:
            print("ADMISSION_CACHE_FAILURE_DIAGNOSTICS unavailable: " + str(error), flush=True)
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def run_dictionary_custody(driver, uuid):
    """Checks original dictionary and dependent inodes through release grace."""
    case = "dictionary-custody"
    process = driver.controlled_actor(case, "dictionary-custody", uuid)
    lines = driver.Lines(process)
    root = driver.root(case)
    snapshot = root / "state/cache/records.toml"

    def control(value):
        process.stdin.write((value + "\n").encode())
        process.stdin.flush()

    def state():
        return tomllib.loads(snapshot.read_text())

    def owned(policy, group, prefix):
        return [row for row in policy.get(group, []) if row["owner"].startswith(prefix)]

    try:
        lines.until("READY genuine dictionary remains protected by its actual admitted dependent after producer handoff",
                    timeout=30)
        policy = state()
        canonical = files(root / "chunks")
        measurements = re.findall(
            r"^DICTIONARY_CUSTODY_GRACE expires=(\d+) hash=([0-9a-f]{64}) dependent_hash=([0-9a-f]{64}) charged_reserved_bytes=(\d+) future_hold_bytes=(\d+)$",
            lines.bytes.decode(), re.M)
        driver.require(len(measurements) == 1, "missing unique actual dictionary custody report")
        expiry, digest, dependent_digest, charged, future = measurements[0]
        expiry, charged, future = int(expiry), int(charged), int(future)
        graces = owned(policy, "leases", "admission-grace:")
        dependency_pins = owned(policy, "pins", "cache-dependency:")
        dependency_leases = owned(policy, "leases", "cache-dependency:")
        holds = policy["reservations"]
        consumers = owned(policy, "leases", "consumer-grace:")
        consumer_pins = owned(policy, "pins", "consumer-grace:")
        reports = re.findall(
            r"^ENCODED_CONSUMER_GRACE owner=(consumer-grace:[0-9a-f]{32}) expires=(\d+) backing_inode_bytes=(\d+) charged_reserved_bytes=(\d+) future_hold_bytes=(\d+)$",
            lines.bytes.decode(), re.M)
        driver.require(len(reports) == len(consumers) == 1 and len(consumer_pins) == 2,
                       "encoded consumer lacks original durable release records")
        consumer_owner, consumer_end, allocated, consumer_charge, consumer_future = reports[0]
        actual_allocation = sum(path.stat().st_blocks * 512 for path in (root / "chunks").rglob("*") if path.is_file())
        driver.require(consumers[0]["owner"] == consumer_owner
                       and consumers[0]["expires"] == int(consumer_end)
                       and all(row["owner"] == consumer_owner and row["expires"] == int(consumer_end) for row in consumer_pins)
                       and {row["hash"] for row in consumer_pins} == {digest, dependent_digest}
                       and int(allocated) == actual_allocation
                       and int(consumer_charge) == charged and int(consumer_future) == future
                       and lines.bytes.decode().splitlines().count(
                           "PASS genuine encoded consumer reads and renews original body and dictionary concurrently under stalled policy, then revokes with distinct durable release protection") == 1,
                       "encoded consumer lost independent body/dictionary protection or actual allocation")
        retained_holds = [row for row in holds if row["id"] != consumer_owner.split(":", 1)[1]]
        dependent_path = next(path for path in (root / "chunks").rglob("*") if path.name == dependent_digest + ".2")
        initial_metadata = dependent_path.stat()
        original_stamp = (initial_metadata.st_ctime_ns, initial_metadata.st_mtime_ns)
        driver.require(len(canonical) == 2 and digest != dependent_digest
                       and {path.rsplit("/", 1)[-1] for path in canonical}
                       == {digest + ".0", dependent_digest + ".2"}
                       and len({value[:2] for value in canonical.values()}) == 2,
                       "dictionary lacks distinct original canonical codec inodes")
        driver.require(len(holds) == 2 and all(row["bytes"] == 262144 for row in holds)
                       and future == 524288 and len(retained_holds) == 1
                       and len(graces) == 2 and max(row["expires"] for row in graces + consumers) == expiry
                       and len(dependency_pins) == len(dependency_leases) == 1
                       and dependency_pins[0]["hash"] == digest
                       and dependency_pins[0]["owner"] == dependency_leases[0]["owner"]
                       and dependency_leases[0]["expires"] == (1 << 63) - 1
                       and not owned(policy, "pins", "admission:")
                       and not owned(policy, "leases", "admission:")
                       and not files(root / "sealed") and not files(root / "pending-delete")
                       and not files(root / "objects") and quota(driver, case) == charged,
                       "dictionary retirement refusal lost exact native backing, dependency or funding")
        wait = expiry - time.time() + 3
        driver.require(wait <= 34, "dictionary release grace exceeds the configured native bound")
        if wait > 0:
            time.sleep(wait)
        expired = state()
        driver.require(process.poll() is None and files(root / "chunks") == canonical
                       and expired["reservations"] == retained_holds
                       and not owned(expired, "leases", "consumer")
                       and not owned(expired, "pins", "consumer")
                       and not owned(expired, "leases", "admission-grace:")
                       and owned(expired, "pins", "cache-dependency:") == dependency_pins
                       and owned(expired, "leases", "cache-dependency:") == dependency_leases
                       and not files(root / "sealed") and not files(root / "pending-delete"),
                       "actual grace expiration lost the dictionary dependency")
        print("PASS independent observer verifies actual encoded consumer body/dictionary release, distinct backing allocation and original inode custody through real grace", flush=True)
        print("PASS independent observer verifies original distinct dictionary/dependent inodes and actual dependency protection through grace and retirement refusal",
              flush=True)
        control("after-grace")
        lines.until("READY actual dictionary remains protected after producer grace",
                    timeout=15)
        before_rewrite = snapshot.read_bytes()
        control("finish")
        lines.until("PASS actual same-bytes rewrite retains original inode and plaintext but refuses a fresh encoded grant at the original admission stamp without policy mutation",
                    timeout=15)
        control("quarantine")
        lines.until("READY rewritten encoded original quarantined with dictionary dependency and funding retained", timeout=15)
        entries = list((root / "quarantine").iterdir())
        prefix = "encoded." + dependent_path.name + "."
        driver.require(len(entries) == 1 and entries[0].name.startswith(prefix)
                       and re.fullmatch("[0-9a-f]{64}", entries[0].name[len(prefix):]),
                       "rewritten source lacks exact original encoded quarantine name")
        changed = entries[0].stat()
        remaining = {name: value for name, value in canonical.items()
                     if not name.endswith(dependent_digest + ".2")}
        original_body = next(value for name, value in canonical.items()
                             if name.endswith(dependent_digest + ".2"))
        moved = files(root / "quarantine")
        driver.require(files(root / "chunks") == remaining and not dependent_path.exists()
                       and list(moved.values()) == [original_body]
                       and changed.st_nlink == 1 and changed.st_uid == 840
                       and changed.st_mode & 0o7777 == 0o640
                       and changed.st_blocks == initial_metadata.st_blocks
                       and (changed.st_ctime_ns, changed.st_mtime_ns) != original_stamp
                       and snapshot.read_bytes() == before_rewrite,
                       "same-bytes refusal lost original encoded inode, bytes, allocation, dictionary or policy")
        print("PASS independent observer verifies unchanged original encoded bytes/inodes, changed timestamps and zero policy effects for the refused fresh grant", flush=True)
        print("PASS independent observer verifies rewritten encoded original quarantined with dictionary and dependency funding retained", flush=True)
        control("quarantine-checked")
        lines.until("PASS actual original dictionary and admitted dependent retain dependency protection and refuse dictionary retirement through actual grace; no Ready",
                    timeout=15)
        output, error = process.communicate(timeout=10)
        driver.require(process.returncode == 0 and not output and not error,
                       "dictionary custody actor did not exit successfully")
    except BaseException:
        try:
            print(lines.bytes[lines.printed:].decode(), end="", flush=True)
            if process.poll() is None:
                process.kill()
            remaining, _ = process.communicate(timeout=5)
            print(remaining.decode(), end="", flush=True)
        except Exception as error:
            print("DICTIONARY_CUSTODY_FAILURE_DIAGNOSTICS unavailable: " + str(error), flush=True)
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
