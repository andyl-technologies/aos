"""Observes actual source cleanup and open-inode quota in the isolated guest."""

import hashlib
import json
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
        driver.require(wait <= 10, "cache handoff grace exceeds the native fixture bound")
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
        output, _ = process.communicate(b"finish\n", timeout=15)
        print(output.decode(), end="", flush=True)
        driver.require(process.returncode == 0 and output.decode().splitlines() == [
            "PASS actual cache handoff releases producer and closed-source funding, retains reconstruction metadata, and grants fresh consumer reads after durable grace; no Ready"
        ], "cache handoff did not reach original native completion")
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
