"""Pin the actual Native environment and one ordinary index child privately.

No environment value is returned in a receipt. Capturing or launching a process
does not establish current actor/provider authority, successful SQL, or drain.
This module is a confined fleet helper, not a Hub command or effect executor.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time


MAX_ENVIRONMENT = 256 * 1024


def private_write(path, body):
    """Retain one private original exclusively and durably."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def process_identity(pid):
    """Read one actual process lifetime before and after executable hashing."""
    directory = Path("/proc") / str(pid)
    before = (directory / "stat").read_text().rpartition(") ")[2].split()[19]
    with (directory / "exe").open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    with (directory / "cmdline").open("rb") as source:
        command = source.read(65537)
    after = (directory / "stat").read_text().rpartition(") ")[2].split()[19]
    if before != after or len(command) > 65536:
        raise ValueError("index process changed or command exceeds bound")
    return {"pid": pid, "startTicks": before, "ownerUid": directory.stat().st_uid,
        "executableSha256": digest, "commandLineSha256": hashlib.sha256(command).hexdigest()}


def _check_process(pin):
    actual = process_identity(pin["pid"])
    if actual != pin or not _may_observe_owner(actual["ownerUid"]):
        raise ValueError("Native process lifetime differs")
    return actual


def _may_observe_owner(owner_uid):
    # The fixture's root observer may read the independently pinned service UID.
    # This does not change the service identity or the later child identity.
    return owner_uid == os.getuid() or os.geteuid() == 0


def capture_environment(pin, output):
    """Capture only the pinned live Native process's actual raw environment."""
    actual = process_identity(pin["pid"])
    required = {"pid", "startTicks", "ownerUid", "executableSha256"}
    if (not required.issubset(pin) or not _may_observe_owner(actual["ownerUid"])
            or any(actual[key] != pin[key] for key in required)
            or any(key in pin and pin[key] != actual[key]
                for key in ("ownerUid", "commandLineSha256"))):
        raise ValueError("Native selected process lifetime differs")
    with (Path("/proc") / str(pin["pid"]) / "environ").open("rb") as source:
        body = source.read(MAX_ENVIRONMENT + 1)
    if not body or len(body) > MAX_ENVIRONMENT or not body.endswith(b"\0"):
        raise ValueError("Native environment is missing or exceeds bound")
    _check_process(actual)
    private_write(output, body)
    return {"version": 1, "file": str(output), "sha256": hashlib.sha256(body).hexdigest(),
        "bytes": len(body), "nativeProcess": actual}


def checked_environment(capture, executable):
    """Recheck retained environment against the same still-live Native original."""
    _check_process(capture["nativeProcess"])
    descriptor = os.open(capture["file"], os.O_RDONLY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(descriptor)
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid()
                or observed.st_nlink != 1 or observed.st_mode & 0o077
                or not 0 < observed.st_size <= MAX_ENVIRONMENT):
            raise ValueError("Native environment file custody differs")
        body = os.read(descriptor, MAX_ENVIRONMENT + 1)
        after = os.fstat(descriptor)
        if (observed.st_size != len(body) or observed.st_mtime_ns != after.st_mtime_ns
                or observed.st_ctime_ns != after.st_ctime_ns
                or len(body) != capture["bytes"]
                or hashlib.sha256(body).hexdigest() != capture["sha256"]):
            raise ValueError("Native captured environment changed")
    finally:
        os.close(descriptor)
    with (Path("/proc") / str(capture["nativeProcess"]["pid"]) / "environ").open("rb") as source:
        live = source.read(MAX_ENVIRONMENT + 1)
    with Path(executable).open("rb") as source:
        actual_executable = hashlib.file_digest(source, "sha256").hexdigest()
    _check_process(capture["nativeProcess"])
    if live != body or actual_executable != capture["nativeProcess"]["executableSha256"]:
        raise ValueError("Native environment or selected index executable changed")
    environment = {}
    for item in body[:-1].split(b"\0"):
        key, separator, value = item.partition(b"=")
        if not separator or key.decode() in environment:
            raise ValueError("Native environment has duplicate or malformed entries")
        environment[key.decode()] = value.decode()
    required = {"HUB_HYBRID_WORKER_URL", "HUB_DEPLOYMENT_ID", "HUB_STORAGE_WORK_KEY_FILE"}
    if (not required.issubset(environment)
            or not (environment.get("HUB_DATABASE_URL") or environment.get("HUB_DATABASE_URL_FILE"))):
        raise ValueError("Native indexing environment lacks actual configured pins")
    return environment


def supervise_index(selection):
    """Run one selected index command and retain its genuine terminal status."""
    environment = checked_environment(selection["environment"], selection["executable"])
    root = Path(selection["root"])
    argv = [selection["executable"], "index", selection["registrySlug"], "--topology", "hybrid"]
    private_write(root / "index-arguments.private.json", json.dumps(argv).encode())
    with (root / "index.stdout.private").open("xb") as stdout:
        with (root / "index.stderr.private").open("xb") as stderr:
            child = subprocess.Popen(argv, env=environment, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr)
            try:
                pin = process_identity(child.pid)
                if (pin["executableSha256"] != selection["environment"]["nativeProcess"]["executableSha256"]
                        or pin["ownerUid"] != os.getuid()):
                    raise ValueError("Index child executable differs from Native")
                private_write(root / "index-process.json", json.dumps({"process": pin,
                    "arguments": argv, "environmentSha256": selection["environment"]["sha256"]}).encode())
                try:
                    code = child.wait(timeout=90)
                    timed_out = False
                except subprocess.TimeoutExpired:
                    # This parent owns the exact Popen child; timeout is not SQL/provider rollback.
                    child.kill()
                    code = child.wait()
                    timed_out = True
                private_write(root / "index-terminal.json", json.dumps({"version": 1,
                    "exitCode": code, "timedOut": timed_out, "process": pin,
                    "completedAtUnixMillis": str(time.time_ns() // 1_000_000)}).encode())
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
