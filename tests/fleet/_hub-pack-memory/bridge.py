"""Carry fixed source-owner controls over the existing serialized guest channel.

The Native owner publishes one request at a time. The host forwards that exact
bounded request to the Worker owner and returns its measured reply. Neither end
accepts a command, path, lease extension, replacement original or provider URL.
"""

import asyncio
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time


ACTIONS = {"state", "release_metadata", "release_pack", "retire"}
MAX_MESSAGES = 512
MAX_RESPONSE_BYTES = 32768


def encoded(value):
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode()


def private_directory(path):
    path = Path(path)
    metadata = path.lstat()
    if (not path.is_absolute() or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
            or path.resolve(strict=True) != path):
        raise ValueError("bridge directory custody differs")
    return path


def read_private(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > maximum):
            raise ValueError("bridge file custody differs")
        body = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        if (len(body) != before.st_size or any(getattr(before, name) != getattr(after, name)
                for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
            raise ValueError("bridge file changed")
        return body
    finally:
        os.close(descriptor)


def write_private(path, value, maximum=MAX_RESPONSE_BYTES + 4096):
    path = Path(path)
    parent = private_directory(path.parent)
    body = encoded(value)
    if len(body) > maximum:
        raise ValueError("bridge publication exceeds its bound")
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + "-pending-", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        # Linux renameat2 publishes the complete single-link inode atomically,
        # refusing an existing destination. A temporary hardlink would expose
        # nlink=2 to the strict concurrent reader before its unlink completed.
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(temporary), -100, os.fsencode(path), 1) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code), str(path))
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return {"file": str(path), "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}


def checked_request(value, run_id, case, sequence):
    if (not isinstance(value, dict) or set(value) != {
            "version", "runId", "case", "sequence", "action"}
            or type(value["version"]) is not int or value["version"] != 1
            or not re.fullmatch(r"[a-f0-9]{32}", run_id)
            or value["runId"] != run_id or value["case"] != case
            or case not in {"semantic32", "live36", "replacement-overflow"}
            or type(sequence) is not int or not 0 <= sequence < MAX_MESSAGES
            or type(value["sequence"]) is not int or value["sequence"] != sequence
            or value["action"] not in ACTIONS):
        raise ValueError("fixed source-owner request differs")
    return value


class GuestPackHold:
    """Wait for measured Worker replies under the original Native cutoff."""

    def __init__(self, root, run_id, case, cutoff):
        self.root = private_directory(root)
        self.run_id, self.case, self.cutoff = run_id, case, cutoff
        self.sequence = 0
        self.metadata_released = False
        self.pack_released = False
        self.receipts = []

    async def _control(self, action):
        sequence = self.sequence
        self.sequence += 1
        request = checked_request({"version": 1, "runId": self.run_id,
            "case": self.case, "sequence": sequence, "action": action},
            self.run_id, self.case, sequence)
        if time.monotonic() >= self.cutoff:
            raise TimeoutError("original bridge cutoff reached")
        reference = write_private(self.root / f"request-{sequence:04d}.json", request, 1024)
        response_path = self.root / f"response-{sequence:04d}.json"
        while True:
            remaining = self.cutoff - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Worker owner reply remains unknown at original cutoff")
            try:
                response = json.loads(read_private(response_path, MAX_RESPONSE_BYTES + 4096))
                break
            except FileNotFoundError:
                await asyncio.sleep(min(0.05, remaining))
        if (set(response) != {"version", "requestSha256", "outcome", "reply", "failureClass",
                "workerResources"}
                or type(response["version"]) is not int or response["version"] != 1
                or response["requestSha256"] != reference["sha256"]
                or time.monotonic() >= self.cutoff):
            raise ValueError("Worker owner response joins another request or cutoff")
        self.receipts.append(response)
        if response["outcome"] != "returned" or response["failureClass"] is not None:
            raise RuntimeError("Worker source control refused or remains unknown")
        return response["reply"]

    async def _wait(self, roles):
        while True:
            reply = await self._control("state")
            if set(roles).issubset(reply["held"]):
                return reply
            remaining = self.cutoff - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("held source originals absent at original cutoff")
            await asyncio.sleep(min(0.25, remaining))

    async def wait_received(self):
        return await self._wait({"pack"})

    async def wait_metadata_received(self):
        return await self._wait({"pack", "metadata0", "metadata1"})

    async def release_metadata_once(self):
        if self.metadata_released:
            raise ValueError("metadata release reused")
        self.metadata_released = True
        return await self._control("release_metadata")

    async def release_once(self):
        if self.pack_released:
            raise ValueError("pack release reused")
        self.pack_released = True
        return await self._control("release_pack")

    async def cancel(self):
        return await self._control("retire")


async def dispatch_worker_request(request, root, run_id, case, sequence, cutoff, hold_type):
    """Dispatch only one fixed action and preserve its actual failure category."""
    checked_request(request, run_id, case, sequence)
    request_digest = hashlib.sha256(encoded(request)).hexdigest()
    result = {"version": 1, "requestSha256": request_digest,
        "outcome": "refused_or_unknown", "reply": None, "failureClass": None,
        "workerResources": None}
    try:
        if time.monotonic() >= cutoff:
            raise TimeoutError("original Worker control cutoff reached")
        # The source itself owns one-use release state. A new transport object
        # does not reset the running source's request or release history.
        owner = hold_type(root, cutoff)
        result["reply"] = await owner._control(request["action"])
        result["outcome"] = "returned"
    except Exception as error:
        result["failureClass"] = type(error).__name__
    return result


def worker_process_sample(expected, workerd):
    """Measure the selected runner and its actual one workerd child only."""
    parent = Path("/proc") / str(expected["pid"])
    fields = (parent / "stat").read_text().rpartition(") ")[2].split()
    if (fields[0] == "Z" or int(fields[19]) != int(expected["startTicks"])
            or parent.stat().st_uid != expected["ownerUid"]):
        raise ValueError("selected Worker runner lifetime changed")
    children = (parent / "task" / str(expected["pid"]) / "children").read_text().split()
    selected = []
    target = Path(workerd).resolve(strict=True)
    for value in children:
        directory = Path("/proc") / value
        try:
            if (directory / "exe").resolve(strict=True) == target:
                selected.append(directory)
        except FileNotFoundError:
            continue
    if len(selected) != 1:
        raise ValueError("actual selected workerd child is missing or ambiguous")
    directory = selected[0]
    fields = (directory / "stat").read_text().rpartition(") ")[2].split()
    if (fields[0] == "Z" or int(fields[1]) != expected["pid"]
            or directory.stat().st_uid != expected["ownerUid"]):
        raise ValueError("actual workerd parent/owner differs")
    status = (directory / "status").read_text()
    values = {}
    for name in ("VmRSS", "VmHWM"):
        found = re.search(r"^" + name + r":\s+([0-9]+) kB$", status, re.MULTILINE)
        values[name] = int(found[1]) * 1024 if found else None
    after = (directory / "stat").read_text().rpartition(") ")[2].split()
    if after[0] == "Z" or after[19] != fields[19]:
        raise ValueError("actual workerd lifetime changed during sample")
    return {"pid": int(directory.name), "startTicks": int(fields[19]),
        "ownerUid": expected["ownerUid"], "executable": str(target),
        "sampleMonotonicNs": time.monotonic_ns(), "residentBytes": values["VmRSS"],
        "lifetimeResidentHighWaterBytes": values["VmHWM"],
        "wholeIsolateBytes": None, "linearWasmBytes": None,
        "scope": "workerd process envelope; all isolates/startup included"}


async def worker_dispatch(selected):
    """Serve one create-only selected request on the actual pinned source owner."""
    from hold import OwnedPackHold
    from worker_owner import peer_pin

    if (set(selected) != {"version", "request", "root", "sourceOwnerReference",
            "cutoffUptimeSeconds", "runnerProcess", "workerd"}
            or type(selected["version"]) is not int or selected["version"] != 1):
        raise ValueError("Worker bridge dispatch selection differs")
    root = private_directory(selected["root"])
    request = selected["request"]
    checked_request(request, request["runId"], request["case"], request["sequence"])
    owner_ref = selected["sourceOwnerReference"]
    raw = read_private(owner_ref["file"], 8192)
    if len(raw) != owner_ref["bytes"] or hashlib.sha256(raw).hexdigest() != owner_ref["sha256"]:
        raise ValueError("selected source owner receipt changed")
    owner = json.loads(raw)
    cutoff = selected["cutoffUptimeSeconds"]
    if (type(cutoff) not in {int, float} or cutoff > owner["originalCutoffMonotonic"]
            or time.monotonic() >= cutoff or owner["socket"] != str(root / "source.sock")):
        raise ValueError("original Worker/source cutoff differs")
    peer_pin(owner["socket"], owner["process"])
    write_private(root / f"dispatch-{request['sequence']:04d}.json", request, 1024)
    result = await dispatch_worker_request(request, root, request["runId"],
        request["case"], request["sequence"], cutoff, OwnedPackHold)
    try:
        result["workerResources"] = worker_process_sample(selected["runnerProcess"], selected["workerd"])
    except (OSError, ValueError) as error:
        result["workerResources"] = {"wholeIsolateBytes": None, "linearWasmBytes": None,
            "residentBytes": None, "lifetimeResidentHighWaterBytes": None,
            "failureClass": type(error).__name__, "scope": "unavailable process sample"}
    if request["action"] != "retire":
        peer_pin(owner["socket"], owner["process"])
    write_private(root / f"dispatch-reply-{request['sequence']:04d}.json", result)
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--dispatch", required=True)
    arguments = parser.parse_args()
    selection = json.loads(read_private(arguments.dispatch, 65536))
    print(encoded(asyncio.run(worker_dispatch(selection))).decode())
