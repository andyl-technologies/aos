"""Observes original mixed FIFO allocations and real open-inode quota charge."""

import fcntl
import hashlib
import os
import re
import stat
import struct
import time
import tomllib

from source_cleanup_vm import files, quota


class Original:
    """Retains a real read-only observer descriptor without creating authority."""

    def __init__(self, driver, case, path, uid):
        self.driver = driver
        self.path = path
        self.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.bind(case, uid)
        except BaseException:
            self.close()
            raise

    def bind(self, case, uid):
        """Captures only actual native facts after opening the original inode."""
        driver = self.driver
        value = os.fstat(self.fd)
        driver.require(stat.S_ISREG(value.st_mode) and value.st_uid == uid
                       and value.st_gid == (841 if uid == 841 else 845)
                       and value.st_dev == driver.root(case).stat().st_dev
                       and 0 < value.st_size <= 2 * 1024 * 1024 and value.st_nlink == 1,
                       "encoded observer did not open the actual role-owned original")
        project = struct.unpack("=5I8s", fcntl.ioctl(self.fd, 0x801C581F, bytes(28)))[3]
        driver.require(project == driver.project(case), "encoded original changed charge owner")
        self.binding = (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
                        value.st_mode, value.st_size, value.st_blocks, value.st_mtime_ns, project)
        contents = os.pread(self.fd, value.st_size, 0)
        driver.require(len(contents) == value.st_size, "encoded observer read incomplete original bytes")
        self.digest = hashlib.sha256(contents).hexdigest()
        self.key = (value.st_dev, value.st_ino, self.digest)
        self.allocated = value.st_blocks * 512
        driver.require(self.allocated > 0, "encoded original has no measured native allocation")

    def check(self, links):
        """Checks unchanged original bytes and ownership while allowing rename ctime."""
        value = os.fstat(self.fd)
        project = struct.unpack("=5I8s", fcntl.ioctl(self.fd, 0x801C581F, bytes(28)))[3]
        binding = (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
                   value.st_mode, value.st_size, value.st_blocks, value.st_mtime_ns, project)
        self.driver.require(binding == self.binding and value.st_nlink == links
                            and hashlib.sha256(os.pread(self.fd, value.st_size, 0)).hexdigest() == self.digest,
                            "encoded retirement changed original inode, bytes or project")

    def close(self):
        """Closes the actual observer descriptor rather than inferring reclamation."""
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def run(driver, uuid):
    """Checks real FIFO, restoration, dependencies, paired removal and final closure."""
    case = "encoded-eviction"
    root = driver.root(case)
    snapshot = root / "state/cache/records.toml"
    process = driver.controlled_actor(case, "encoded-eviction", uuid)
    lines = driver.Lines(process)
    originals = {}

    def control(value):
        process.stdin.write((value + "\n").encode())
        process.stdin.flush()

    def state():
        return tomllib.loads(snapshot.read_text())

    def owned(policy, group, prefix):
        return [row for row in policy.get(group, []) if row["owner"].startswith(prefix)]

    def one(pattern, message):
        matches = re.findall(pattern, lines.bytes.decode(), re.M)
        driver.require(len(matches) == 1, message)
        return matches[0]

    def scene(canonical, pending):
        for label, original in originals.items():
            if original.fd is not None:
                original.check(1 if label in canonical or label in pending else 0)
        for directory in ["chunks", "sealed", "objects"]:
            expected = {str(originals[label].path): originals[label].key for label in canonical
                        if originals[label].path.is_relative_to(root / directory)}
            driver.require(files(root / directory) == expected,
                           "encoded FIFO changed canonical allocation names or original inodes")
        driver.require(sorted(files(root / "pending-delete").values())
                       == sorted(originals[label].key for label in pending),
                       "encoded FIFO did not retain exactly the original pending allocation members")

    def wait_grace(expiry):
        wait = int(expiry) - time.time() + 3
        driver.require(wait <= 34, "encoded consumer grace exceeds its actual configured bound")
        if wait > 0:
            time.sleep(wait)

    def wait_removed(canonical, labels):
        # Start after the actual acknowledgment and preserve an early refusal
        # observation. The real publisher still enforces its own durable clock.
        scene(canonical, labels)
        time.sleep(1)
        scene(canonical, labels)
        time.sleep(31)
        deadline = time.monotonic() + 5
        while files(root / "pending-delete"):
            driver.require(process.poll() is None and time.monotonic() < deadline,
                           "actual due encoded retirement did not finish")
            time.sleep(0.05)
        scene(canonical, set())

    def measurement(kind):
        charged, future = map(int, one(
            rf"^ENCODED_EVICTION_MEASUREMENT kind={kind} charged=(\d+) future=(\d+)$",
            "missing unique original encoded quota measurement"))
        driver.require(quota(driver, case) == charged
                       and sum(row["bytes"] for row in state()["reservations"]) == future,
                       "encoded report differs from actual helper quota or durable funding")
        return charged, future

    def close_group(kind, labels, next_control, next_marker):
        before, future = measurement(kind + "-held")
        policy = state()
        allocated = sum(originals[label].allocated for label in labels)
        for label in labels:
            originals[label].check(0)
            originals[label].close()
        control(next_control)
        lines.until(next_marker, timeout=30)
        after, remaining = measurement(kind + "-closed")
        driver.require(after <= before - allocated and remaining == future
                       and state()["reservations"] == policy["reservations"],
                       "encoded quota was not released only after the last original descriptions closed")
        print(f"PASS independent encoded {kind} observer verifies original inode closure and measured charge release; funding unchanged",
              flush=True)

    def admission_pressure():
        """Checks actual automatic admission pressure on the same Running owner."""
        lines.until("READY original admission pressure allocations and independent consumers retained", timeout=30)
        expiry, incoming, incoming_hold = one(
            r"^ADMISSION_PRESSURE_INIT expires=(\d+) incoming=([0-9a-f]{64}) hold=(\d+)$",
            "missing unique actual incoming pressure inventory")
        members = re.findall(r"^ADMISSION_PRESSURE_MEMBER index=(\d+) hash=([0-9a-f]{64})$",
                             lines.bytes.decode(), re.M)
        driver.require([int(index) for index, _hash in members] == list(range(19))
                       and len({digest for _index, digest in members}) == 19
                       and int(incoming_hold) == 262144 + 16384,
                       "automatic pressure lacks original bounded admission inventory")
        labels = []
        for index, digest in members:
            label = "pressure:" + index
            originals[label] = Original(driver, case, root / "chunks" / digest[:2] / (digest + ".0"), 840)
            driver.require(originals[label].binding[5] == 262144
                           and originals[label].allocated == 262144
                           and os.pread(originals[label].fd, 1, 0) == b"\x00",
                           "pressure input does not occupy actual original raw blocks")
            labels.append(label)
        driver.require(len({originals[label].key[:2] for label in labels}) == 19,
                       "pressure members alias original allocation units")
        incoming_path = root / "chunks" / incoming[:2] / (incoming + ".0")
        canonical = set(labels)
        scene(canonical, set())
        policy = state()
        consumers = owned(policy, "leases", "consumer:")
        consumer_pins = owned(policy, "pins", "consumer:")
        holds = policy["reservations"]
        driver.require(len(consumers) == len(consumer_pins) == 3 and len(holds) == 4
                       and all(row["bytes"] == 262144 for row in holds)
                       and {pin["hash"] for pin in consumer_pins} == {digest for _index, digest in members[-3:]}
                       and not incoming_path.exists(),
                       "automatic pressure lacks actual independently funded protected consumers")
        grace = owned(policy, "leases", "admission-grace:")
        driver.require(grace and max(row["expires"] for row in grace) == int(expiry),
                       "pressure deadline differs from original durable producer grace")

        def pressure_measurement(kind):
            charged, future = map(int, one(
                rf"^ADMISSION_PRESSURE_MEASUREMENT kind={kind} charged=(\d+) future=(\d+)$",
                "missing actual automatic admission pressure measurement"))
            driver.require(quota(driver, case) == charged
                           and sum(row["bytes"] for row in state()["reservations"]) == future,
                           "automatic admission measurement differs from native quota or real funding")
            return charged, future

        wait_grace(expiry)
        original_policy = snapshot.read_bytes()
        control("pressure-invalid")
        lines.until("READY invalid incoming chunk refused before automatic eviction or funding", timeout=30)
        before, future = pressure_measurement("before")
        driver.require(before + future + int(incoming_hold) > 6 * 1024 * 1024
                       and snapshot.read_bytes() == original_policy,
                       "invalid input did not exercise real pressure without policy effects")
        scene(canonical, set())
        control("pressure-admit")
        lines.until("READY verified incoming admission retires original FIFO units but refuses pending quota charge", timeout=30)
        pending_files = files(root / "pending-delete")
        pending = {label for label in labels if originals[label].key in pending_files.values()}
        count = int(one(r"^ADMISSION_PRESSURE_PENDING members=(\d+)$",
                        "missing actual admission-selected victim count"))
        driver.require(0 < count < 16 and pending == set(labels[:count])
                       and len(pending_files) == count and not incoming_path.exists()
                       and state()["reservations"] == holds
                       and owned(state(), "leases", "consumer:") == consumers
                       and owned(state(), "pins", "consumer:") == consumer_pins,
                       "automatic admission did not retire the original eligible FIFO prefix or retained failed funding")
        canonical -= pending
        scene(canonical, pending)
        charged, remaining = pressure_measurement("pending")
        driver.require(charged >= sum(originals[label].allocated for label in labels)
                       and remaining == future,
                       "pending automatic victims were falsely credited as released quota")
        print("PASS independent observer verifies corrupt input has no eviction effects and verified admission alone retires original eligible FIFO units while preserving real charge and three consumers", flush=True)

        wait_removed(canonical, pending)
        control("pressure-drop")
        lines.until("READY automatic pressure victims close while independent observers retain charge", timeout=30)
        held, remaining = pressure_measurement("held")
        allocated = sum(originals[label].allocated for label in pending)
        for label in pending:
            originals[label].check(0)
            originals[label].close()
        control("pressure-observers")
        lines.until("READY original pressure observer closure releases measured quota without changing funding", timeout=30)
        closed, final_future = pressure_measurement("closed")
        driver.require(closed <= held - allocated and remaining == final_future == future
                       and state()["reservations"] == holds,
                       "automatic pressure released quota before actual final closure or changed original funding")
        control("pressure-retry")
        lines.until("READY same incoming admission succeeds after actual last-description quota release", timeout=30)
        originals["pressure:incoming"] = Original(driver, case, incoming_path, 840)
        driver.require(originals["pressure:incoming"].binding[5] == 16384
                       and os.pread(originals["pressure:incoming"].fd, 16384, 0) == b"\x00" + bytes([221]) * 16383,
                       "successful retry did not admit the exact original verified incoming bytes")
        canonical.add("pressure:incoming")
        scene(canonical, set())
        _charged, final_future = pressure_measurement("admitted")
        driver.require(final_future == future and state()["reservations"] == holds
                       and owned(state(), "leases", "consumer:") == consumers
                       and owned(state(), "pins", "consumer:") == consumer_pins,
                       "successful automatic retry lost original consumer promises or leaked producer funding")
        print("PASS independent observer verifies actual last-description quota release permits the same incoming admission to reserve and complete while original consumer funding survives", flush=True)
        control("pressure-done")
        lines.until("PASS genuine verified admission requests bounded native eviction, retains pending charge and live consumers, then retries after original descriptor closure; no Ready", timeout=30)

    try:
        lines.until("READY mixed encoded allocations retain original producer grace", timeout=30)
        print(driver.process_status(process, 840), flush=True)
        expires, raw, sealed, pack, dictionary, dependent = one(
            r"^ENCODED_EVICTION_INIT expires=(\d+) raw=([0-9a-f]{64}) sealed=([0-9a-f]{64}) pack=([0-9a-f]{32}) dictionary=([0-9a-f]{64}) dependent=([0-9a-f]{64})$",
            "missing actual mixed encoded allocation identity inventory")
        paths = {
            "raw": (root / "chunks" / raw[:2] / (raw + ".0"), 840),
            "sealed": (root / "sealed" / sealed, 841),
            "index": (root / "objects/pack" / pack[:2] / (pack + ".idx"), 840),
            "pack": (root / "objects/pack" / pack[:2] / (pack + ".pack"), 840),
            "dictionary": (root / "chunks" / dictionary[:2] / (dictionary + ".0"), 840),
            "dependent": (root / "chunks" / dependent[:2] / (dependent + ".2"), 840),
        }
        for label, (path, uid) in paths.items():
            originals[label] = Original(driver, case, path, uid)
        driver.require(len({original.key[:2] for original in originals.values()}) == 6
                       and len(state()["reservations"]) == 1
                       and state()["reservations"][0]["bytes"] == 262144,
                       "mixed fixture aliases originals or lost its exact bootstrap funding")
        canonical = set(originals)
        scene(canonical, set())
        policy = state()
        actual_grace = [row["expires"] for row in policy["leases"] if row["expires"] < 2**63 - 1]
        driver.require(actual_grace and max(actual_grace) == int(expires),
                       "encoded handoff deadline differs from actual durable promises")
        dependency_pins = owned(policy, "pins", "cache-dependency:")
        dependency_leases = owned(policy, "leases", "cache-dependency:")
        driver.require(len(dependency_pins) == len(dependency_leases) == 1
                       and dependency_pins[0]["hash"] == dictionary,
                       "mixed cache lacks its actual distinct dictionary dependency")
        wait_grace(expires)
        control("first")
        lines.until("READY original raw allocation retires before the later sealed allocation", timeout=30)
        canonical.remove("raw")
        scene(canonical, {"raw"})
        control("repin")
        lines.until("READY original encoded allocation restores before a fresh policy-held consumer read", timeout=30)
        unread = one(r"^ENCODED_EVICTION_UNREAD hash=([0-9a-f]{64})$", "missing actual unread companion identity")
        originals["unread"] = Original(driver, case, root / "chunks" / unread[:2] / (unread + ".1"), 840)
        driver.require(originals["unread"].allocated > 65536
                       and os.pread(originals["unread"].fd, 1, 0) == b"\x01",
                       "unread companion does not exercise actual compressed probation allocation")
        canonical.add("raw")
        canonical.add("unread")
        scene(canonical, set())
        driver.require(len(owned(state(), "leases", "consumer:")) == 3,
                       "restored encoded reads or unread companion lack independent consumer promises")
        print("PASS independent observer verifies original mixed FIFO order and same-inode encoded restoration before consumer grants", flush=True)
        control("second")
        lines.until("READY next sealed allocation retires in original mixed FIFO order", timeout=30)
        canonical.remove("sealed")
        scene(canonical, {"sealed"})
        control("pair")
        lines.until("READY complete original pack and index retire as one allocation", timeout=30)
        canonical -= {"pack", "index"}
        scene(canonical, {"sealed", "pack", "index"})
        policy = snapshot.read_bytes()
        control("duplicate-pair")
        lines.until("READY duplicate pack admission restores both originals and refuses before new funding", timeout=30)
        canonical |= {"pack", "index"}
        scene(canonical, {"sealed"})
        driver.require(snapshot.read_bytes() == policy, "duplicate pack restoration changed durable policy")
        control("retire-pair-duplicate")
        lines.until("READY restored original pack unit retires under a fresh actual acknowledgment", timeout=30)
        canonical -= {"pack", "index"}
        wait_removed(canonical, {"sealed", "pack", "index"})
        control("drop-pair")
        lines.until("READY removed pack and sealed descriptions close while independent observers retain charge", timeout=30)
        close_group("pair", {"sealed", "pack", "index"}, "after-pair-observers",
                    "READY independent encoded consumers survive actual pack and sealed removal")
        scene(canonical, set())

        control("release-raw")
        lines.until("READY actual raw consumer grace protects original encoded allocation", timeout=30)
        expiry = one(r"^ENCODED_EVICTION_GRACE kind=raw expires=(\d+)$", "missing original raw consumer grace")
        wait_grace(expiry)
        control("retire-raw")
        lines.until("READY restored original raw allocation retires only after actual consumer grace", timeout=30)
        canonical.remove("raw")
        scene(canonical, {"raw"})
        policy = snapshot.read_bytes()
        control("duplicate-raw")
        lines.until("READY duplicate chunk admission restores original backing and refuses before new funding", timeout=30)
        canonical.add("raw")
        scene(canonical, set())
        driver.require(snapshot.read_bytes() == policy, "duplicate raw restoration changed durable policy")
        control("retire-raw-duplicate")
        lines.until("READY restored duplicate raw allocation retires under a fresh actual acknowledgment", timeout=30)
        canonical.remove("raw")
        wait_removed(canonical, {"raw"})
        control("drop-raw")
        lines.until("READY removed raw description closes while independent observer retains charge", timeout=30)
        close_group("raw", {"raw"}, "after-raw-observer",
                    "READY removed raw allocation cannot issue a fresh consumer grant")
        scene(canonical, set())
        driver.require(owned(state(), "pins", "cache-dependency:") == dependency_pins
                       and owned(state(), "leases", "cache-dependency:") == dependency_leases,
                       "unrelated encoded retirement changed the original dictionary promise")

        control("release-dependent")
        lines.until("READY actual dependent consumer grace protects original encoded allocation", timeout=30)
        expiry = one(r"^ENCODED_EVICTION_GRACE kind=dependent expires=(\d+)$", "missing actual dependent consumer grace")
        wait_grace(expiry)
        control("retire-dependent")
        lines.until("READY original dictionary remains protected throughout dependent retirement", timeout=30)
        canonical.remove("dependent")
        scene(canonical, {"dependent"})
        driver.require(owned(state(), "pins", "cache-dependency:") == dependency_pins
                       and owned(state(), "leases", "cache-dependency:") == dependency_leases,
                       "pending dependent released its dictionary promise before acknowledgment")
        wait_removed(canonical, {"dependent"})
        driver.require(not owned(state(), "pins", "cache-dependency:")
                       and not owned(state(), "leases", "cache-dependency:"),
                       "acknowledged dependent removal retained an obsolete dictionary promise")
        control("drop-dependent")
        lines.until("READY removed dependent description closes after its actual dictionary promise releases", timeout=30)
        close_group("dependent", {"dependent"}, "after-dependent-observer",
                    "ENCODED_EVICTION_MEASUREMENT kind=dependent-closed")
        control("release-unread")
        lines.until("READY actual unread consumer grace protects original encoded allocation", timeout=30)
        expiry = one(r"^ENCODED_EVICTION_GRACE kind=unread expires=(\d+)$", "missing unread companion grace")
        wait_grace(expiry)
        control("retire-unread")
        lines.until("READY unread Zstd companion retires before the older dictionary actually consumed by verified reads", timeout=30)
        canonical.remove("unread")
        wait_removed(canonical, {"unread"})
        control("drop-unread")
        lines.until("READY removed unread companion description closes while its independent observer retains charge", timeout=30)
        close_group("unread", {"unread"}, "after-unread-observer",
                    "READY promoted original dictionary remains canonical after unread companion closure")
        scene(canonical, set())
        print("PASS independent observer verifies dictionary read promotion ahead of a newer unread Zstd allocation and actual last-description charge release", flush=True)
        control("retire-dictionary")
        lines.until("READY original dictionary retires only after acknowledged dependent removal", timeout=30)
        canonical.remove("dictionary")
        wait_removed(canonical, {"dictionary"})
        control("drop-dictionary")
        lines.until("READY removed dictionary description closes while independent observer retains charge", timeout=30)
        close_group("dictionary", {"dictionary"}, "finish",
                    "READY all original encoded allocations removed with the Running owner retained")
        scene(set(), set())
        final = state()
        driver.require(process.poll() is None and len(final["reservations"]) == 1 and final["reservations"][0]["bytes"] == 262144
                       and not final.get("pins", []) and not final.get("leases", []),
                       "final native encoded removal lost bootstrap funding or retained obsolete promises")
        control("done")
        lines.until("PASS actual mixed FIFO encoded restoration, consumer and dictionary protection, complete pack unit removal and original descriptor closure; no Ready", timeout=30)
        admission_pressure()
        output, error = process.communicate(timeout=10)
        driver.require(process.returncode == 0 and not output and not error,
                       "encoded FIFO actor did not exit successfully")
        print("PASS independent native observer verifies original encoded FIFO, restored grants, paired removal, dictionary lifetime and last-description quota release", flush=True)
    except BaseException:
        try:
            print(lines.bytes[lines.printed:].decode(), end="", flush=True)
            if process.poll() is None:
                process.kill()
            output, _ = process.communicate(timeout=5)
            print(output.decode(), end="", flush=True)
        except Exception as error:
            print("ENCODED_EVICTION_FAILURE_DIAGNOSTICS unavailable: " + str(error), flush=True)
        raise
    finally:
        for original in originals.values():
            original.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
