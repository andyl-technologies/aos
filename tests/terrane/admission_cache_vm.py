"""Observes real encoded cache handoff, grace and original source retirement."""

import re
import time
import tomllib

from source_cleanup_vm import files, quota


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
        driver.require(len(canonical) == 2 and digest != dependent_digest
                       and {path.rsplit("/", 1)[-1] for path in canonical}
                       == {digest + ".0", dependent_digest + ".2"}
                       and len({value[:2] for value in canonical.values()}) == 2,
                       "dictionary lacks distinct original canonical codec inodes")
        driver.require(len(holds) == 1 and holds[0]["bytes"] == future == 262144
                       and len(graces) == 2 and max(row["expires"] for row in graces) == expiry
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
                       and expired["reservations"] == holds
                       and not owned(expired, "leases", "admission-grace:")
                       and owned(expired, "pins", "cache-dependency:") == dependency_pins
                       and owned(expired, "leases", "cache-dependency:") == dependency_leases
                       and not files(root / "sealed") and not files(root / "pending-delete"),
                       "actual grace expiration lost the dictionary dependency")
        print("PASS independent observer verifies original distinct dictionary/dependent inodes and actual dependency protection through grace and retirement refusal",
              flush=True)
        control("after-grace")
        lines.until("READY actual dictionary remains protected after producer grace",
                    timeout=15)
        control("finish")
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
