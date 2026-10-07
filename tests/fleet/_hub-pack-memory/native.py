"""Own selected auxiliary Native processes and execute the existing strict codec.

Inputs are retained files from actual current configuration/capture. This module
creates no credentials, plans, original admissions, signatures or capture facts.
"""

import asyncio
import hashlib
import types
import stat
import json
import os
from pathlib import Path
import re
import time

SELECTOR = "storage_work::external_oci::tests::fleet::pack_memory::actual_pack_memory_native_consumer"


def retained_bytes(reference, maximum):
    """Reopen an owner-private immutable reference without replacing its path."""
    expected = reference["bytes"]
    if (type(expected) is not int or not 0 <= expected <= maximum
            or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])):
        raise ValueError("reference count/hash differs")
    descriptor = os.open(reference["file"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_mode & 0o077 or before.st_size != expected):
            raise ValueError("actual reference custody differs")
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(descriptor)
        if (len(raw) != expected or hashlib.sha256(raw).hexdigest() != reference["sha256"]
                or any(getattr(before, key) != getattr(after, key)
                    for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
            raise ValueError("retained reference changed")
        return bytes(raw)
    finally:
        os.close(descriptor)


def measured_reference(path, maximum):
    """Measure a selected future output only after genuine owner publication."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_mode & 0o077 or before.st_size > maximum):
            raise ValueError("actual produced file custody differs")
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key)
                for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
            raise ValueError("actual produced file changed")
        return {"file": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    finally:
        os.close(descriptor)


COMMIT = "c33422854f98185bdbbb796e386edf3d41a50c36"
MODULES = {
    "resources": ("tests/fleet/_hub-direct-invocation-resources.py", 12018,
        "ffad790f87b466633c0221694205d00085f28f67b0b3aff9c075af089cdf4743"),
    "executeParser": ("tests/fleet/_hub-storage-work-execute-observation.py", 15947,
        "47c7eb4b7f69adf0779294ca0884d6a9bb6aab74b5c12d8ccdf208b54710ddd5"),
}


def validate_current_tuple(value):
    """Check closed current source/module and installed executable commitments."""
    if (not isinstance(value, dict) or set(value) != {"version", "runtimeParentCommit", "runtimeSourceStorePath",
            "resources", "executeParser", "nativeExecutable", "codecExecutable"}
            or type(value["version"]) is not int or value["version"] != 1
            or value["runtimeParentCommit"] != COMMIT
            or not re.fullmatch(r"/nix/store/[a-z0-9]{32}-[^/]+", value["runtimeSourceStorePath"])):
        raise ValueError("current module tuple differs")
    for role, (relative, count, sha256) in MODULES.items():
        expected = {"file": value["runtimeSourceStorePath"] + "/" + relative,
            "bytes": count, "sha256": sha256}
        if value[role] != expected:
            raise ValueError("current module source/path/hash/count differs")
    for role in ("nativeExecutable", "codecExecutable"):
        artifact = value[role]
        if (not isinstance(artifact, dict) or set(artifact) != {"file", "bytes", "sha256"}
                or not re.fullmatch(r"/nix/store/[a-z0-9]{32}-[^/]+/bin/[^/]+", artifact["file"])
                or type(artifact["bytes"]) is not int or not 0 < artifact["bytes"] <= 512 * 1024 * 1024
                or not re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])):
            raise ValueError("selected installed artifact commitment differs")
    return value


def selected_tuple(reference):
    """Read actual private tuple bytes before loading any selected module."""
    return validate_current_tuple(json.loads(retained_bytes(reference, 65536)))


def checked_installed_artifact(reference):
    """Hash exact bounded immutable installed bytes before execution."""
    descriptor = os.open(reference["file"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o222
                or before.st_size != reference["bytes"]):
            raise ValueError("selected installed artifact is mutable or changed")
        digest = hashlib.sha256()
        count = 0
        while count <= reference["bytes"]:
            chunk = os.read(descriptor, min(65536, reference["bytes"] + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (count != reference["bytes"] or digest.hexdigest() != reference["sha256"]
                or any(getattr(before, key) != getattr(after, key)
                    for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
            raise ValueError("selected installed artifact actual hash/count changed")
    finally:
        os.close(descriptor)
    return Path(reference["file"])


def load_selected_module(value, role):
    """Execute only already reviewed exact bytes from the selected source store."""
    relative, count, sha256 = MODULES[role]
    reference = value[role]
    expected_path = value["runtimeSourceStorePath"] + "/" + relative
    if reference != {"file": expected_path, "bytes": count, "sha256": sha256}:
        raise ValueError("dynamic module commitment differs")
    descriptor = os.open(expected_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != count or before.st_mode & 0o222:
            raise ValueError("selected source-store module is mutable or oversized")
        raw = os.read(descriptor, count + 1)
        after = os.fstat(descriptor)
        if (len(raw) != count or hashlib.sha256(raw).hexdigest() != sha256
                or any(getattr(before, key) != getattr(after, key)
                    for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
            raise ValueError("selected module actual bytes changed")
    finally:
        os.close(descriptor)
    module = types.ModuleType("pack_selected_" + role)
    module.__file__ = expected_path
    # The path loader must not reopen a potentially different file after checking.
    exec(compile(raw, expected_path, "exec"), module.__dict__)
    return module


async def retire_native_process(process, receipt, cutoff, *, monotonic=time.monotonic):
    """Split the remaining original reserve between TERM and KILL plus reap."""
    receipt.update({"termInvoked": False, "killInvoked": False, "reaped": None,
        "reapedWithinOriginal": None, "processRetired": None})
    remaining = cutoff - monotonic()
    if remaining <= 0:
        receipt["exit"] = process.returncode
        return
    waiter = asyncio.create_task(process.wait())
    if process.returncode is None:
        try:
            process.terminate()
            receipt["termInvoked"] = True
        except ProcessLookupError:
            pass
    done, _ = await asyncio.wait({waiter}, timeout=remaining / 2)
    if not done:
        remaining = cutoff - monotonic()
        if remaining > 0:
            if process.returncode is None:
                try:
                    process.kill()
                    receipt["killInvoked"] = True
                except ProcessLookupError:
                    pass
            done, _ = await asyncio.wait({waiter}, timeout=remaining)
    if done:
        receipt["exit"] = waiter.result()
        receipt["reaped"] = True
        receipt["reapedWithinOriginal"] = monotonic() < cutoff
        receipt["processRetired"] = receipt["reapedWithinOriginal"]
    else:
        # No awaited work or additional signal is issued after the original ends.
        # The OS/asyncio watcher may later reap, but that is not this receipt.
        waiter.cancel()
        receipt["exit"] = process.returncode


class NativeCaller:
    """Launch exactly selected Native test originals, retaining every outcome."""

    def __init__(self, current_tuple_reference, root, cutoff, capture_root):
        self.current_tuple_reference = current_tuple_reference
        self.current_tuple = selected_tuple(current_tuple_reference)
        self.executable = checked_installed_artifact(self.current_tuple["nativeExecutable"])
        self.root = Path(root)
        self.root.mkdir(mode=0o700)
        self.cutoff = cutoff
        self.capture_root = Path(capture_root)
        capture_metadata = self.capture_root.lstat()
        if (not self.capture_root.is_absolute() or self.capture_root.is_symlink()
                or not self.capture_root.is_dir() or capture_metadata.st_uid != os.getuid()
                or capture_metadata.st_mode & 0o077):
            raise ValueError("selected independent Worker capture root differs")
        self.started = set()
        self.processes = []
        self.resources = load_selected_module(self.current_tuple, "resources")

    async def _run(self, reference):
        if selected_tuple(self.current_tuple_reference) != self.current_tuple:
            raise ValueError("selected actual tuple changed before Native launch")
        raw = retained_bytes(reference, 65536)
        selection = json.loads(raw)
        identity = hashlib.sha256(raw).hexdigest()
        if identity in self.started or time.monotonic() >= self.cutoff - 2:
            raise ValueError("original reused or operation cutoff expired")
        self.started.add(identity)
        root = self.root / identity
        root.mkdir(mode=0o700)
        logs = [open(root / name, "xb") for name in ("stdout.log", "stderr.log")]
        for stream in logs:
            os.fchmod(stream.fileno(), 0o600)
        environment = os.environ.copy()
        environment["AOS_PACK_MEMORY_SELECTION"] = reference["file"]
        started = time.monotonic()
        native_cutoff = min(self.cutoff, started + 25)
        process = await asyncio.create_subprocess_exec(str(self.executable), "--exact", SELECTOR,
            "--ignored", "--nocapture", env=environment, stdout=logs[0], stderr=logs[1])
        self.processes.append(process)
        receipt = {"version": 1, "selectionSha256": identity, "startedMonotonic": started,
            "exit": None, "timedOut": False, "providerDrain": None,
            "currentTupleReference": self.current_tuple_reference,
            "resourcesModuleReference": self.current_tuple["resources"],
            "nativeExecutableReference": self.current_tuple["nativeExecutable"],
            "nativeSubwindowSeconds": 25, "nativeSubwindowCutoffMonotonic": native_cutoff,
            "originalWindowCutoffMonotonic": self.cutoff}
        try:
            receipt["process"] = self.resources.process_identity(process.pid, str(self.executable))
            receipt["initialProcessSample"] = self.resources.process_sample(receipt["process"])
            waiter = asyncio.create_task(process.wait())
            done, _ = await asyncio.wait({waiter}, timeout=max(0, native_cutoff - 2 - time.monotonic()))
            if not done:
                waiter.cancel()
                receipt["timedOut"] = True
                raise TimeoutError("Native original operation cutoff reached")
            receipt["exit"] = waiter.result()
            if receipt["exit"] != 0:
                raise ValueError("actual Native consumer refused; retained failure is not a pass")
            result_file = Path(selection["outputFile"])
            if not result_file.is_absolute():
                raise ValueError("actual Native result path differs")
            result_ref = measured_reference(result_file, 256 * 1024)
            result = json.loads(retained_bytes(result_ref, 256 * 1024))
            if result["selectionSha256"] != identity:
                raise ValueError("actual Native result selected another original")
            result_value = {"result": result, "resultReference": result_ref,
                "receiptFile": str(root / "receipt.json"), "nativeLogFile": str(root / "stderr.log")}
        finally:
            await retire_native_process(process, receipt, native_cutoff)
            try:
                receipt["nativeLogReferences"] = {
                    name: measured_reference(root / name, 8 * 1024 * 1024)
                    for name in ("stdout.log", "stderr.log")}
            except (OSError, ValueError):
                receipt["nativeLogReferences"] = None
            for stream in logs:
                stream.close()
            receipt["finishedMonotonic"] = time.monotonic()
            with open(root / "receipt.json", "x") as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump(receipt, stream)
        if receipt["reaped"] is not True or receipt["reapedWithinOriginal"] is not True:
            raise TimeoutError("Native reap remains unknown within original cutoff")
        result_value["receiptReference"] = measured_reference(root / "receipt.json", 65536)
        result_value["nativeLogReference"] = receipt["nativeLogReferences"]["stderr.log"] \
            if receipt["nativeLogReferences"] is not None else None
        return result_value

    async def inspect_pack(self, reference):
        return await self._run(reference)

    async def metadata(self, reference):
        # The header ref belongs to the independently selected Worker capture,
        # never to this helper's stdout or a configured capacity declaration.
        result = await self._run(reference["selection"])
        header_file = Path(reference["candidateBuffersHeaderFile"])
        if header_file.parent != self.capture_root:
            raise ValueError("actual candidate response header leaves selected capture root")
        header_ref = measured_reference(header_file, 1024)
        header = retained_bytes(header_ref, 1024)
        result["bufferInterval"] = json.loads(header)
        result["bufferHeaderReference"] = header_ref
        return result


def join_pack_codec(manifest_reference, native_log_reference, current_tuple_reference, *, cutoff):
    """Run current strict typed decoding and correlate real Native-consumed bytes.

    Codec structure never authenticates a reply MAC. The actual Native method's
    current SQL recheck is separately retained in its selected process result.
    """
    import subprocess
    current_tuple = selected_tuple(current_tuple_reference)
    codec_executable = checked_installed_artifact(current_tuple["codecExecutable"])
    manifest = json.loads(retained_bytes(manifest_reference, 1024 * 1024))
    parser = load_selected_module(current_tuple, "executeParser")
    logs = retained_bytes(native_log_reference, 8 * 1024 * 1024).decode()
    attempts = []
    prefix = "[INFO] message=storage_work_attempt_observed "
    for line in logs.splitlines():
        if line.startswith(prefix):
            value, end = json.JSONDecoder().raw_decode(line[len(prefix):])
            if line[len(prefix) + end:] and not line[len(prefix) + end:].startswith(" span="):
                raise ValueError("Native observation suffix differs")
            attempts.append(parser.validate_storage_work_attempt(value))
    remaining = cutoff - time.monotonic()
    if remaining <= 0 or len(attempts) > 3:
        raise ValueError("original codec cutoff or actual attempt corpus differs")
    invocation = subprocess.run([str(codec_executable), manifest_reference["file"]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(10, remaining), check=False)
    if invocation.returncode or len(invocation.stdout) > 65536:
        raise ValueError("selected strict codec refused")
    decoded = json.loads(invocation.stdout)
    if len(decoded) != len(manifest["cases"]):
        raise ValueError("actual complete codec selection differs")
    joined = []
    for case, row in zip(manifest["cases"], decoded):
        matching = [attempt for attempt in attempts if attempt["outcome"] == "typed_result_checked"
            and attempt["offeredRequestSha256"] == row["requestSha256"]
            and attempt["exposedReplySha256"] == row["replySha256"]]
        if len(matching) != 1:
            raise ValueError("actual Native checked prefix is missing or ambiguous")
        attempt = matching[0]
        reply = retained_bytes({"file":case["receivedReply"]["file"],
            "sha256":case["receivedReply"]["sha256"],
            "bytes":int(case["receivedReply"]["byteSize"])}, 256 * 1024)
        if (not attempt["replyEof"] or int(attempt["exposedReplyBytes"]) != len(reply)
                or row["sourceDigest"] != manifest["sourceDigest"]
                or row["operation"] != "inspect_mirror_pack_v1"
                or row["class"] != "mirror_storage_work_typed_observation"
                or int(row["payload"]["selectedDataBytes"]) != 32):
            raise ValueError("pack result consumed/output geometry differs")
        joined.append({"codec":row,"nativeAttempt":attempt})
    if len(joined) != len(attempts):
        raise ValueError("unassigned actual Native attempts remain unknown")
    return {"joined":joined,"currentTupleReference":current_tuple_reference,
        "parserModuleReference":current_tuple["executeParser"],
        "codecExecutableReference":current_tuple["codecExecutable"],
        "nativeLogReference":native_log_reference,"replyMacAuthentication":None,"nativeBulkBytes":None,
        "wholeIsolateBytes":None,"providerAuthority":None}
