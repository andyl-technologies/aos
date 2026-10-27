"""Observes actual source cleanup and open-inode quota in the isolated guest."""

import hashlib
import json
import os
import pathlib
import re
import signal
import subprocess
import time
import tomllib


def files(directory):
    """Retains actual native names, inodes and bytes without granting authority."""
    return {str(path): (path.stat().st_dev, path.stat().st_ino,
                        hashlib.sha256(path.read_bytes()).hexdigest())
            for path in directory.rglob("*") if path.is_file()}


def quota(driver, case):
    """Queries the real privileged helper through its ordinary authenticated CLI."""
    result = subprocess.run([
        str(driver.IMAGE / "bin/aos-terrane-host"), "query", "--config",
        str(driver.ADMIN / "host.toml"), "--owner", driver.owner(case),
        "--domain", driver.domain(case),
    ], check=True, text=True, capture_output=True, timeout=10)
    match = re.fullmatch(r"project=(\d+) hard_limit_bytes=(\d+) charged_reserved_bytes=(\d+) roots=(\d+)\n",
                         result.stdout)
    driver.require(match is not None, "missing actual source cleanup quota response")
    project, hard, charged, roots = map(int, match.groups())
    driver.require(project == driver.project(case) and hard == driver.HARD and roots == 8,
                   "source cleanup quota reply has another native binding")
    return charged


def run(driver, publisher, uuid):
    """Runs real grace refusal, foreign refusal and stopped-publisher cancellation."""
    early = "source-cleanup-early"
    output = driver.actor(early, "source-cleanup-early", uuid)
    driver.require(output.splitlines() == [
        "PASS actual early source cleanup refused with original pending inode and funding retained; unavailable requires recovery"
    ] and files(driver.root(early) / "pending-delete"),
        "early source cleanup lost the actual native pending source or failure witness")

    case = "source-cleanup"
    process = driver.controlled_actor(case, "source-cleanup", uuid)
    stopped = False
    lines = driver.Lines(process)
    try:
        lines.until("READY actual inline and manifest retired sources; retain original native grace")
        driver.require("PASS actual foreign physical owner refused source cleanup and remained usable"
                       in lines.bytes.decode().splitlines(), "missing actual foreign cleanup refusal")
        driver.require(lines.bytes.decode().splitlines().count(
            "PASS actual eviction census retains original inline and manifest pending sources under unsatisfied capacity pressure; durable funding unchanged"
        ) == 1, "missing actual eviction census with original pending source custody")
        print(driver.process_status(process, 840), flush=True)
        snapshot = driver.root(case) / "state/cache/records.toml"
        before = snapshot.read_bytes()
        pending = files(driver.root(case) / "pending-delete")
        sealed = files(driver.root(case) / "sealed")
        driver.require(len(pending) >= 3 and len(sealed) == 2,
                       "source cleanup lacks original pending sources and sealed outputs")
        # The actual publisher configuration fixes a 30-second grace. This
        # interval starts after both real Retire acknowledgements and never
        # changes that native deadline or retries an unavailable operation.
        time.sleep(31)
        driver.require(process.poll() is None and snapshot.read_bytes() == before
                       and files(driver.root(case) / "pending-delete") == pending,
                       "native grace discarded original source names or funding")
        publisher.send_signal(signal.SIGSTOP)
        stopped = True
        deadline = time.monotonic() + 2
        while True:
            status = (pathlib.Path("/proc") / str(publisher.pid) / "status").read_text()
            driver.require(publisher.poll() is None, "publisher exited before cleanup cancellation")
            if any(line.startswith("State:\tT") or line.startswith("State:\tt") for line in status.splitlines()):
                break
            driver.require(time.monotonic() < deadline, "cleanup publisher stop not acknowledged")
            time.sleep(0.005)
        process.stdin.write(b"start\n")
        process.stdin.flush()
        lines.until("CANCELLED accepted source cleanup waiter; physical owner retained", timeout=2)
        driver.require(snapshot.read_bytes() == before
                       and files(driver.root(case) / "pending-delete") == pending,
                       "stopped publisher supplied cleanup or lost synchronized funding")
        publisher.send_signal(signal.SIGCONT)
        stopped = False
        process.stdin.write(b"complete\n")
        process.stdin.flush()
        lines.until("READY actual cleanup accounting retains open source descriptions", timeout=45)
        measurement = [line for line in lines.bytes.decode().splitlines()
                       if line.startswith("SOURCE_CLEANUP_MEASUREMENT ")]
        driver.require(len(measurement) == 1, "missing unique actual cleanup measurement")
        match = re.fullmatch(
            r"SOURCE_CLEANUP_MEASUREMENT charged_reserved_bytes=(\d+) future_hold_bytes=(\d+) retained_source_bytes=(\d+) sealed_bytes=(\d+)",
            measurement[0])
        driver.require(match is not None, "invalid original cleanup accounting witness")
        charged, future, retained, sealed_bytes = map(int, match.groups())
        state = tomllib.loads(snapshot.read_text())
        actual = quota(driver, case)
        driver.require(actual == charged and retained > 0 and sealed_bytes > 0
                       and charged >= retained + sealed_bytes
                       and future == sum(row["bytes"] for row in state["reservations"])
                       and snapshot.read_bytes() == before
                       and files(driver.root(case) / "sealed") == sealed
                       and not files(driver.root(case) / "pending-delete"),
                       "cleanup lost original custody or inferred freed open-inode charge")
        print("PASS independent helper observes actual unlinked source allocation while original descriptions remain open",
              flush=True)
        process.stdin.write(b"close-sources\n")
        process.stdin.flush()
        lines.until("CLOSED actual original source observations; Running owner retained", timeout=15)
        driver.run(["sync", "-f", driver.root(case)])
        process.stdin.write(b"measure\n")
        process.stdin.flush()
        lines.until("READY actual source reclamation with original Running owner retained", timeout=45)
        closure = "PASS closed resident view refuses reads while independent sources and consumer leases remain readable under stalled policy; durable protection unchanged"
        observed = lines.bytes.decode().splitlines()
        driver.require(observed.count(closure) == 1,
                       "missing actual producer read-view closure with independent live consumer")
        revocation = "PASS actual publication revokes original producer views and refuses reacquisition while independent consumer reads remain live; durable protection unchanged"
        capacity = "PASS actual producer-view capacity refuses overflow and reclaims closed slots without policy mutation"
        driver.require(observed.count(capacity) == observed.count(revocation) == 1
                       and observed.index(closure) < observed.index(capacity) < observed.index(revocation),
                       "missing original producer revocation or independent live consumer")
        closed_measurement = [line for line in lines.bytes.decode().splitlines()
                              if line.startswith("SOURCE_CLEANUP_CLOSED ")]
        driver.require(len(closed_measurement) == 1, "missing actual live-owner reclamation measurement")
        closed_match = re.fullmatch(r"SOURCE_CLEANUP_CLOSED charged_reserved_bytes=(\d+) future_hold_bytes=(\d+)",
                                    closed_measurement[0])
        driver.require(closed_match is not None, "invalid actual live-owner reclamation measurement")
        closed, closed_future = map(int, closed_match.groups())
        driver.require(process.poll() is None and quota(driver, case) == closed
                       and closed <= charged - retained and closed_future == future
                       and snapshot.read_bytes() == before
                       and files(driver.root(case) / "sealed") == sealed
                       and not files(driver.root(case) / "pending-delete"),
                       "source allocation survived original closure or Running custody changed")
        print("PASS independent helper observes actual source reclamation while the original Running owner and consumers remain alive",
              flush=True)
        process.stdin.write(b"release\n")
        process.stdin.flush()
        completion = "PASS actual inline and repeated-manifest source cleanup retained pins, live reads and holds after cancellation; original source descriptors closed with Running custody retained; no Ready"
        lines.until(completion, timeout=15)
        driver.run(["sync", "-f", driver.root(case)])
        after = quota(driver, case)
        driver.require(process.poll() is None and after <= closed and snapshot.read_bytes() == before
                       and files(driver.root(case) / "sealed") == sealed,
                       "actual source descriptors did not close or immutable output changed")
        print("PASS independent helper observes actual source reclamation only after original descriptions close",
              flush=True)
        process.stdin.write(b"handoff\n")
        process.stdin.flush()
        lines.until("READY actual cache handoff retains independent consumers and reconstruction metadata", timeout=45)
        retry = "PASS full cache handoff queue returns the original publication for retry without policy mutation"
        driver.require(lines.bytes.decode().splitlines().count(retry) == 1,
                       "missing original receipt retry after real bounded queue refusal")
        grace = re.findall(r"^CACHE_HANDOFF_GRACE expires=(\d+) released_future_hold_bytes=(\d+)$",
                           lines.bytes.decode(), re.M)
        driver.require(len(grace) == 1, "missing actual cache handoff deadline")
        grace_end, released_future = map(int, grace[0])
        driver.require(released_future > 0 and released_future < future,
                       "cache handoff has no actual released producer/source holds")
        # The actual worker performs its ordinary periodic sweep while the
        # actor retains both old and fresh consumer leases. No clock advances
        # or policy edits substitute for the durable grace deadline.
        wait = grace_end - time.time() + 3
        # NativeOwnerConfig fixes release grace at 30 seconds. Wait for that
        # real durable deadline plus the existing three-second sweep allowance.
        driver.require(wait <= 34, "cache handoff grace exceeds the native fixture bound")
        if wait > 0:
            time.sleep(wait)
        expired = tomllib.loads(snapshot.read_text())
        driver.require(not any(row["owner"].startswith("publication-grace:")
                               for name in ["pins", "leases"] for row in expired.get(name, [])),
                       "periodic native sweep retained expired producer grace")
        process.stdin.write(b"after-grace\n")
        process.stdin.flush()
        lines.until("READY actual cache handoff grace expired with original owner and consumers retained", timeout=30)
        handoff = re.findall(r"^CACHE_HANDOFF_MEASUREMENT charged_reserved_bytes=(\d+) future_hold_bytes=(\d+)$",
                            lines.bytes.decode(), re.M)
        driver.require(len(handoff) == 1, "missing actual cached consumer accounting")
        cached_charge, cached_future = map(int, handoff[0])
        final_policy = tomllib.loads(snapshot.read_text())
        driver.require(process.poll() is None and quota(driver, case) == cached_charge
                       and cached_future == sum(row["bytes"] for row in final_policy["reservations"])
                       and files(driver.root(case) / "sealed") == sealed
                       and not files(driver.root(case) / "pending-delete")
                       and not any(row["owner"].startswith("publication:")
                                   for name in ["pins", "leases"] for row in final_policy.get(name, [])),
                       "cache handoff lost native ownership or misreported policy holds as physical usage")
        print("PASS independent helper verifies actual cache handoff, expired producer grace and retained live consumers", flush=True)
        process.stdin.write(b"finish\n")
        process.stdin.flush()
        lines.until("PASS actual cache handoff releases producer and closed-source funding, retains reconstruction metadata, and grants fresh consumer reads after durable grace; no Ready", timeout=15)
        run_eviction(driver, case, process, lines, snapshot)
    except BaseException:
        # Lines.until may observe process exit before draining the last pipe
        # bytes. Keep the original native refusal and bounded actual state;
        # neither diagnostics nor timeouts turn a failed witness into success.
        try:
            print(lines.bytes[lines.printed:].decode(), end="", flush=True)
            if process.poll() is None:
                process.kill()
            remaining, _ = process.communicate(timeout=5)
            print(remaining.decode(), end="", flush=True)
            print("SOURCE_CLEANUP_FAILURE_STATE " + json.dumps({
                "policy": tomllib.loads((driver.root(case) / "state/cache/records.toml").read_text()),
                "pending": files(driver.root(case) / "pending-delete"),
                "sealed": files(driver.root(case) / "sealed"),
            }, sort_keys=True), flush=True)
        except Exception as diagnostic_error:
            print("SOURCE_CLEANUP_FAILURE_STATE unavailable: " + str(diagnostic_error), flush=True)
        raise
    finally:
        if stopped and publisher.poll() is None:
            publisher.send_signal(signal.SIGCONT)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def run_eviction(driver, case, process, lines, snapshot):
    """Observes actual original-body retirement while its real owner stays alive."""
    def control(command):
        process.stdin.write((command + "\n").encode())
        process.stdin.flush()

    def pending_measurement(phase):
        values = re.findall(r"^CACHE_EVICTION_PENDING phase=" + phase
                            + r" charged_reserved_bytes=(\d+) future_hold_bytes=(\d+)$",
                            lines.bytes.decode(), re.M)
        driver.require(len(values) == 1, "missing unique actual pending cache measurement")
        charge, future = map(int, values[0])
        state = tomllib.loads(snapshot.read_text())
        driver.require(quota(driver, case) == charge
                       and future == sum(row["bytes"] for row in state["reservations"]),
                       "pending cache report differs from real helper or durable holds")

    def retirement_wait(original):
        leases = [tomllib.loads(path.read_text()) for path in
                  (driver.root(case) / "state/publication").glob("retirement-*.toml")]
        deadlines = [lease["deadline_unix_ms"] for lease in leases
                     if lease["device"] == original.st_dev and lease["inode"] == original.st_ino
                     and lease["domain"] == driver.domain(case)]
        driver.require(len(deadlines) == 1, "inline retirement lacks its original native deadline")
        wait = deadlines[0] / 1000 - time.time() + 3
        driver.require(wait <= 34, "inline native retirement exceeds configured publisher bound")
        if wait > 0:
            time.sleep(wait)

    control("evict")
    lines.until("READY native eviction controls retain extended independent consumers", timeout=15)
    targets = re.findall(r"^CACHE_EVICTION_TARGET hash=([0-9a-f]{64})$", lines.bytes.decode(), re.M)
    driver.require(len(targets) == 1, "missing actual inline eviction identity")
    digest = targets[0]
    root = driver.root(case)
    canonical = root / "sealed" / digest[:2] / digest
    pending = root / "pending-delete" / digest
    all_sealed = files(root / "sealed")
    metadata = files(root / "objects")
    original_policy = snapshot.read_bytes()
    with canonical.open("rb") as observer:
        original = canonical.stat()
        allocated = original.st_blocks * 512
        original_bytes = observer.read()
        driver.require(allocated > 0 and original_bytes,
                       "eviction observer lacks actual original allocation")
        control("retire")
        lines.until("READY actual cached inline pending retirement with charge retained", timeout=15)
        renamed = pending.stat()
        driver.require(not canonical.exists()
                       and (renamed.st_dev, renamed.st_ino) == (original.st_dev, original.st_ino)
                       and renamed.st_nlink == 1 and pending.read_bytes() == original_bytes
                       and snapshot.read_bytes() == original_policy,
                       "cache retirement lost original inode or changed durable funding")
        pending_measurement("initial")

        control("repin")
        lines.until("READY inline pin accepted before deadline while original physical owner is stalled", timeout=15)
        retirement_wait(original)
        driver.require(not canonical.exists() and pending.stat().st_ino == original.st_ino
                       and snapshot.read_bytes() == original_policy,
                       "queued inline pin was acknowledged or lost original pending custody while stalled")
        control("release-stall")
        lines.until("READY actual inline consumer pin restores canonical backing and reads with policy held", timeout=15)
        restored = canonical.stat()
        driver.require(not pending.exists()
                       and (restored.st_dev, restored.st_ino) == (original.st_dev, original.st_ino)
                       and files(root / "sealed") == all_sealed,
                       "new pin did not restore the exact original canonical body")

        before_expiring = tomllib.loads(snapshot.read_text())
        control("expiring-pin")
        lines.until("READY independent finite consumer retains original restored inline backing", timeout=15)
        grants = re.findall(r"^CACHE_EVICTION_EXPIRING owner=(consumer:[0-9a-f]{32}) expires=(\d+)$",
                            lines.bytes.decode(), re.M)
        driver.require(len(grants) == 1, "missing unique finite inline consumer grant")
        expired_owner, finite_expiry = grants[0][0], int(grants[0][1])
        expired_token = expired_owner.removeprefix("consumer:")
        expected_expiring = dict(before_expiring)
        expected_expiring["pins"] = before_expiring["pins"] + [
            {"owner": expired_owner, "hash": digest, "expires": finite_expiry}]
        expected_expiring["leases"] = before_expiring["leases"] + [
            {"owner": expired_owner, "expires": finite_expiry}]
        expected_expiring["reservations"] = before_expiring["reservations"] + [
            {"id": expired_token, "owner": driver.owner(case), "bytes": 262144}]
        driver.require(tomllib.loads(snapshot.read_text()) == expected_expiring
                       and canonical.stat().st_ino == original.st_ino
                       and files(root / "sealed") == all_sealed and not pending.exists(),
                       "finite consumer lost its exact grant, funding or original inline inode")
        wait = finite_expiry - time.time() + 1
        driver.require(0 < wait <= 12, "finite inline consumer exceeds its original deadline")
        time.sleep(wait)
        control("expired-pin")
        lines.until("READY expired inline consumer refuses reads and renewal without changing durable policy", timeout=15)
        driver.require(tomllib.loads(snapshot.read_text()) == expected_expiring,
                       "finite consumer expiry removed protection before original grace")

        control("release-pin")
        lines.until("READY released inline pin prevents eviction through its durable grace", timeout=15)
        grace = re.findall(r"^CACHE_EVICTION_PIN_GRACE expires=(\d+)$", lines.bytes.decode(), re.M)
        driver.require(len(grace) == 1 and canonical.exists() and not pending.exists(),
                       "released inline pin lost its actual canonical grace protection")
        expiry = int(grace[0])
        state = tomllib.loads(snapshot.read_text())
        driver.require(any(row["hash"] == digest and row["expires"] == expiry
                           and row["owner"].startswith("consumer-grace:") for row in state["pins"]),
                       "inline release did not persist its original grace pin")
        wait = expiry - time.time() + 3
        driver.require(wait <= 34, "inline release grace exceeds configured native bound")
        if wait > 0:
            time.sleep(wait)
        state = tomllib.loads(snapshot.read_text())
        driver.require(not any(row["hash"] == digest for row in state["pins"]),
                       "periodic sweep retained expired inline grace protection")
        driver.require(not any(row["owner"] == expired_owner for row in state["leases"])
                       and not any(row["id"] == expired_token for row in state["reservations"]),
                       "periodic expiry retained the finite consumer lease or future hold")
        print("PASS independent observer verifies automatic finite consumer expiry before original inline retirement; no explicit release or sweep for that consumer",
              flush=True)

        control("retire-after-grace")
        lines.until("READY actual cached inline pending final removal after release grace", timeout=15)
        pending_measurement("final")
        driver.require(not canonical.exists() and pending.stat().st_ino == original.st_ino,
                       "post-grace retirement did not retain its original pending inode")
        prior_residences = tomllib.loads(snapshot.read_text())["residences"]
        control("duplicate")
        lines.until("READY duplicate publication restores original pending inode without replacement", timeout=15)
        duplicates = re.findall(r"^CACHE_EVICTION_DUPLICATE inode=(\d+) grace_expires=(\d+)$", lines.bytes.decode(), re.M)
        driver.require(len(duplicates) == 1 and int(duplicates[0][0]) == original.st_ino
                       and canonical.stat().st_ino == original.st_ino and not pending.exists()
                       and files(root / "sealed") == all_sealed
                       and tomllib.loads(snapshot.read_text())["residences"] == prior_residences,
                       "duplicate publication created another inode or moved original residences")
        duplicate_expiry = int(duplicates[0][1])
        wait = duplicate_expiry - time.time() + 3
        driver.require(wait <= 34, "duplicate producer grace exceeds configured native bound")
        if wait > 0:
            time.sleep(wait)
        driver.require(not any(row["hash"] == digest for row in tomllib.loads(snapshot.read_text())["pins"]),
                       "duplicate publication retained expired producer protection")
        control("retire-duplicate-after-grace")
        lines.until("READY actual duplicate publication aliases share one final native retirement", timeout=15)
        pending_measurement("duplicate-final")
        driver.require(not canonical.exists() and pending.stat().st_ino == original.st_ino,
                       "duplicate aliases did not retire their single original inode")
        retirement_wait(original)
        driver.require(not canonical.exists() and not pending.exists()
                       and not any(row["chunk"] == digest for row in tomllib.loads(snapshot.read_text())["residences"]),
                       "idle owner failed actual final namespace and residence removal")
        control("after-delete")
        lines.until("READY actual cached inline final removal reconciled with original owner retained", timeout=15)
        driver.run(["sync", "-f", root])
        held = quota(driver, case)
        stable_policy = snapshot.read_bytes()
        observer.seek(0)
        retained = os.fstat(observer.fileno())
        driver.require(process.poll() is None and original_bytes == observer.read()
                       and retained.st_nlink == 0
                       and (retained.st_dev, retained.st_ino) == (original.st_dev, original.st_ino),
                       "final cache retirement lost its independent open-inode observer")

    # Only this final independent observer closes here. The physical owner and
    # both unrelated consumer grants remain live throughout the real query.
    driver.run(["sync", "-f", root])
    after = quota(driver, case)
    driver.require(after <= held - allocated and snapshot.read_bytes() == stable_policy,
                   "cached body charge survived original physical closure or policy changed")
    remaining = dict(all_sealed)
    remaining.pop(str(canonical))
    driver.require(files(root / "sealed") == remaining and files(root / "objects") == metadata,
                   "inline retirement changed unrelated backing or reconstruction metadata")
    print("PASS independent helper observes actual cached-body charge release only after the last original descriptor closes", flush=True)
    control("measure-after-observer")
    lines.until("READY independent consumers survive actual final cache retirement and descriptor closure", timeout=15)
    values = re.findall(r"^CACHE_EVICTION_FINAL charged_reserved_bytes=(\d+) future_hold_bytes=(\d+)$", lines.bytes.decode(), re.M)
    driver.require(len(values) == 1, "missing final native cache measurement")
    charge, future = map(int, values[0])
    driver.require(charge == quota(driver, case) and future == sum(row["bytes"] for row in tomllib.loads(snapshot.read_text())["reservations"]),
                   "final native cache accounting differs from real project usage")
    output, _ = process.communicate(b"done\n", timeout=15)
    print(output.decode(), end="", flush=True)
    driver.require(process.returncode == 0 and output.decode().splitlines() == [
        "PASS automatic consumer expiry permits original inline eviction and measured reclamation while the expired handle remains retained",
        "PASS actual S3 FIFO inline retirement restores for a new pin, preserves release grace, and finally removes original backing before measured quota release; independent consumers remain live; no Ready"
    ], "native cache eviction did not complete with original live custody")
