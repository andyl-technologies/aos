"""Observes copy-before-delete ordering and actual original inode reclamation."""

import os
import re
import time
import tomllib

from source_cleanup_vm import quota


def send(process, command):
    process.stdin.write(command.encode() + b"\n")
    process.stdin.flush()


def wait_deadline(driver, process, deadline):
    """Waits for the real durable deadline without changing native clocks."""
    driver.require(time.time() <= deadline + 10, "shared extraction missed its native grace")
    # This fixture configures 30 seconds. A permanent reconstruction pin must
    # fail promptly instead of parking the guest until its whole-test timeout.
    driver.require(deadline <= time.time() + 31,
                   "shared extraction deadline exceeds its configured release grace")
    while time.time() <= deadline + 1:
        driver.require(process.poll() is None, "shared extraction actor exited during grace")
        time.sleep(min(0.1, max(0.001, deadline + 1 - time.time())))


def row(driver, lines, prefix, pattern):
    matches = [re.fullmatch(pattern, line) for line in lines.bytes.decode().splitlines()
               if line.startswith(prefix)]
    driver.require(len(matches) == 1 and matches[0] is not None,
                   "missing unique shared extraction witness: " + prefix)
    return matches[0].groups()


def run(driver, uuid):
    """Retains original body observation and live consumers through actual eviction."""
    case = "shared-reextract"
    process = driver.controlled_actor(case, case, uuid)
    lines = driver.Lines(process)
    observer = None
    try:
        lines.until("READY shared extraction originals published; wait for source retirement grace")
        original, inode, allocated = row(driver, lines, "SHARED_EXTRACTION_ORIGINAL ",
            r"SHARED_EXTRACTION_ORIGINAL object=([0-9a-f]{64}) inode=(\d+) bytes=(\d+)")
        body = driver.root(case) / "sealed" / original[:2] / original
        driver.require(body.stat().st_ino == int(inode) and int(allocated) > 0,
                       "shared extraction original inode differs from native publication")
        observer = body.open("rb")
        plaintext = observer.read()
        time.sleep(31)
        send(process, "cleanup")
        lines.until("READY pinned shared eviction refused; original body and range retained")
        (grace,) = row(driver, lines, "SHARED_EXTRACTION_GRACE ",
                      r"SHARED_EXTRACTION_GRACE expires=(\d+)")
        policy = driver.root(case) / "state/cache/records.toml"
        before = tomllib.loads(policy.read_text())
        driver.require(any(record["object"] == original for record in before["residences"])
                       and body.read_bytes() == plaintext,
                       "pinned shared eviction changed its original backing")
        wait_deadline(driver, process, int(grace))
        send(process, "extract")
        lines.until("READY verified standalone replacement and independent consumers; original body still charged")
        chunk, same, expires = row(driver, lines, "SHARED_EXTRACTION_COPY ",
            r"SHARED_EXTRACTION_COPY chunk=([0-9a-f]{64}) object=([0-9a-f]{64}) expires=(\d+)")
        replacement = driver.root(case) / "chunks" / chunk[:2] / (chunk + ".0")
        copied = replacement.read_bytes()
        after = tomllib.loads(policy.read_text())
        driver.require(same == original and copied[:1] == b"\0"
                       and copied[1:] == plaintext[:len(copied) - 1]
                       and body.stat().st_ino == int(inode) and body.read_bytes() == plaintext
                       and not any(record["chunk"] == chunk for record in after["residences"])
                       and any(record["object"] == original for record in after["residences"]),
                       "shared extraction failed real copy-before-delete custody")
        wait_deadline(driver, process, int(expires))
        send(process, "retire")
        lines.until("READY original shared body pending deletion; replacement and independent consumer retained")
        pending = [path for path in (driver.root(case) / "pending-delete").iterdir()
                   if path.is_file() and path.stat().st_ino == int(inode)]
        driver.require(len(pending) == 1 and not body.exists() and observer.read(1) == b"",
                       "shared extraction lacks exactly its original pending inode")
        time.sleep(31)
        send(process, "deleted")
        lines.until("READY original shared body removed; real consumers remain readable with policy held")
        driver.run(["sync", "-f", driver.root(case)])
        held = quota(driver, case)
        observer.seek(0)
        driver.require(observer.read() == plaintext and not pending[0].exists()
                       and os.fstat(observer.fileno()).st_nlink == 0,
                       "final shared deletion lost original unlinked observation")
        observer.close()
        observer = None
        driver.run(["sync", "-f", driver.root(case)])
        closed = quota(driver, case)
        driver.require(process.poll() is None and closed <= held - int(allocated)
                       and replacement.read_bytes() == copied,
                       "original shared descriptor survived final native closure")
        send(process, "finish")
        output, _ = process.communicate(timeout=15)
        full = (lines.bytes + output).decode()
        driver.require(process.returncode == 0 and full.splitlines().count(
            "PASS actual shared-chunk re-extraction preserves one residence, durable grace, independent consumers and final original descriptor closure; no Ready") == 1,
            "shared extraction actor did not finish with its original consumers")
        print(full, end="", flush=True)
        print("PASS independent quota observation releases original sealed allocation only after all original descriptions close", flush=True)
    finally:
        if observer is not None:
            observer.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
