# SPDX-License-Identifier: MIT
"""Bounds private native witness custody and authenticates current image owners.

These helpers establish mechanism evidence only. They never mint execution or
full-system admission from a caller's hashes or from a successful sample.
"""

import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import sys
import time


MAX_FILE_BYTES = 2 * 1024**3
MAX_TOTAL_BYTES = 4 * 1024**3
MAX_FILES = 4096


def fingerprint(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_nlink)


def checked_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    # Installed source-built inputs are immutable store leaves; imported and
    # captured witness resources must instead belong to this controller UID.
    installed = str(path).startswith("/nix/store/") and not metadata.st_mode & 0o222
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or (metadata.st_uid != os.getuid() and not installed)
            or not 0 <= metadata.st_size <= MAX_FILE_BYTES):
        os.close(descriptor)
        raise ValueError("native witness file exceeds regular owned finite custody")
    return descriptor, metadata


def digest(path):
    descriptor, before = checked_file(path)
    with os.fdopen(descriptor, "rb") as reader:
        result = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            part = reader.read(min(1024**2, remaining))
            if not part:
                raise ValueError("native witness asset shrank during measurement")
            result.update(part)
            remaining -= len(part)
        if reader.read(1) or fingerprint(before) != fingerprint(os.fstat(reader.fileno())):
            raise ValueError("native witness asset changed during measurement")
    return result.hexdigest()


def census(directory):
    """Preflights all leaves before allocating an archived resource tree."""
    pending = [(directory, 0)]
    directories, files = [], []
    members, total = 0, 0
    while pending:
        parent, depth = pending.pop()
        metadata = parent.lstat()
        installed = str(parent).startswith("/nix/store/") and not metadata.st_mode & 0o222
        if (depth > 32 or not stat.S_ISDIR(metadata.st_mode)
                or (metadata.st_uid != os.getuid() and not installed)):
            raise ValueError("native witness tree depth or directory custody differs")
        directories.append(parent)
        for leaf in parent.iterdir():
            members += 1
            if members > MAX_FILES:
                raise ValueError("native witness tree count exhausted before copying")
            metadata = leaf.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((leaf, depth + 1))
            else:
                descriptor, metadata = checked_file(leaf)
                os.close(descriptor)
                total += metadata.st_size
                if total > MAX_TOTAL_BYTES:
                    raise ValueError("native witness tree bytes exhausted before copying")
                files.append((leaf, metadata))
    return directories, files, total


def copy_file(source, destination, metadata, mode):
    descriptor, before = checked_file(source)
    try:
        if fingerprint(before) != fingerprint(metadata):
            raise ValueError("native witness source changed after preflight")
        target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(descriptor, "rb", closefd=False) as reader, os.fdopen(target, "wb") as writer:
            result = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                part = reader.read(min(1024**2, remaining))
                if not part:
                    raise ValueError("native witness source shrank while copying")
                result.update(part)
                writer.write(part)
                remaining -= len(part)
            if reader.read(1) or fingerprint(before) != fingerprint(os.fstat(descriptor)):
                raise ValueError("native witness copy source changed")
            writer.flush()
            os.fchmod(writer.fileno(), mode)
            os.fsync(writer.fileno())
        return result.hexdigest()
    finally:
        os.close(descriptor)


def copy_tree(source, destination, mode=0o600):
    directories, files, total = census(source)
    destination.mkdir(mode=0o700)
    for directory in sorted(directories, key=lambda path: len(path.parts)):
        if directory != source:
            (destination / directory.relative_to(source)).mkdir(mode=0o700)
    for leaf, metadata in files:
        copy_file(leaf, destination / leaf.relative_to(source), metadata, mode)
    return total


def kernel_identity(pid):
    """Reads a still-owned leader's immutable kernel start/group identity."""
    body = Path(f"/proc/{pid}/stat").read_text()
    fields = body[body.rfind(")") + 2:].split()
    if len(fields) < 20:
        raise ValueError("native leader kernel identity is incomplete")
    return (pid, int(fields[2]), fields[19])


def own_process(process):
    """Retains an unreaped original leader before readiness or termination."""
    retained = getattr(process, "_crucible_group_custody", None)
    if retained is not None:
        return retained
    if process.returncode is not None:
        raise ValueError("native leader was reaped before original group custody")
    identity = kernel_identity(process.pid)
    if identity[1] != process.pid or os.getpgid(process.pid) != process.pid:
        raise ValueError("native witness does not own a private leader group")
    retained = {"identity": identity, "signal_attempted": False,
                "reaped": False, "reclaimed": False, "wait_error": False}
    process._crucible_group_custody = retained
    return retained


def assert_waitable_anchor(process, retained):
    if (retained["reaped"] or retained["wait_error"] or process.returncode is not None
            or kernel_identity(process.pid) != retained["identity"]
            or os.getpgid(process.pid) != retained["identity"][1]):
        raise ValueError("original native group lost its unreaped kernel anchor")


def observe_exit(process):
    """Observes natural termination without releasing the original PID anchor."""
    retained = own_process(process)
    assert_waitable_anchor(process, retained)
    # ECHILD is unknown custody, never evidence of a safely absent group.
    observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if observed is not None and (observed.si_pid != process.pid or observed.si_code not in (
            os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)):
        raise ValueError("exit observation does not prove original leader termination")
    return observed


def wait_exited(process, timeout=10):
    """Waits for an exit observation while leaving the leader waitable."""
    deadline = time.monotonic() + timeout
    while True:
        observed = observe_exit(process)
        if observed is not None:
            if observed.si_pid != process.pid:
                raise ValueError("exit observation belongs to another native leader")
            return observed.si_status if observed.si_code == os.CLD_EXITED else -observed.si_status
        if time.monotonic() >= deadline:
            raise TimeoutError("native witness missed natural exit deadline")
        time.sleep(0.02)


def accept(listener, process):
    listener.settimeout(0.1)
    deadline = time.monotonic() + 180
    while True:
        try:
            stream, _ = listener.accept()
            stream.settimeout(180)
            return stream
        except TimeoutError:
            if observe_exit(process) is not None or time.monotonic() >= deadline:
                raise RuntimeError("native witness owner exited or missed readiness deadline")


def authenticate(stream, process, native, dmtcp=None, guard=None):
    pid, uid, _ = struct.unpack("3i", stream.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    if pid != process.pid or uid != os.getuid():
        raise ValueError("native witness peer differs from supervised child")
    executable = Path(f"/proc/{pid}/exe")
    # /proc/exe itself is a trusted kernel symlink, not an imported artifact.
    executable_digest = digest(Path(os.readlink(executable)))
    if executable_digest != digest(Path(dmtcp) / "bin/mtcp_restart" if dmtcp else Path(native)):
        raise ValueError("native witness executable differs from measured reconstruction code")
    mappings = Path(f"/proc/{pid}/maps").read_text().splitlines()
    if not any(len(row.split()) >= 6 and "x" in row.split()[1]
               and row.split(maxsplit=5)[5] == native for row in mappings):
        raise ValueError("native witness original emulator code is not mapped")
    if guard and not any(len(row.split()) >= 6 and row.split(maxsplit=5)[5] == guard
                         for row in mappings):
        raise ValueError("native witness resource custody helper is not mapped")


def group_members(group):
    members = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            body = (entry / "stat").read_text()
            fields = body[body.rfind(")") + 2:].split()
            if int(fields[2]) == group:
                if len(members) >= 4096:
                    raise ValueError("native helper group census exceeds finite credit")
                members.append(entry.name)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return members


def reclaim(process):
    """Signals a waitable original group once, reaps once, and checks absence."""
    retained = own_process(process)
    if retained["reclaimed"]:
        return True
    if retained["wait_error"]:
        raise ValueError("native leader retirement has unresolved wait custody")
    if not retained["reaped"]:
        assert_waitable_anchor(process, retained)
        # Preserve waitable child ownership even on the exceptional path. A
        # failed or repeated cleanup must never signal a retired/reused group.
        observe_exit(process)
        if not retained["signal_attempted"]:
            retained["signal_attempted"] = True
            try:
                os.killpg(retained["identity"][1], signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            wait_exited(process, timeout=10)
            pid, status = os.waitpid(process.pid, 0)
            if pid != process.pid:
                raise ValueError("native retirement returned another leader identity")
            process.returncode = os.waitstatus_to_exitcode(status)
        except TimeoutError:
            # The original anchor remains retained; a retry can wait again but
            # cannot repeat its group signal.
            raise
        except BaseException:
            retained["wait_error"] = True
            raise
        retained["reaped"] = True
    deadline = time.monotonic() + 10
    while True:
        members = group_members(retained["identity"][1])
        if not members:
            retained["reclaimed"] = True
            return True
        if time.monotonic() >= deadline:
            raise ValueError(f"native witness group still has members: {members}")
        time.sleep(0.02)


def audit(exchange, stream, process, root, resource, image, boundary, scope,
          native, guard, source_directory, label):
    inventory = exchange(stream, {"kind": "process_inventory"})
    assert inventory["boundary"] == boundary
    body = Path(f"/proc/{process.pid}/stat").read_text()
    start_ticks = body[body.rfind(")") + 2:].split()[19]
    paths = [Path(native), Path(guard), *resource.glob("*.py")]
    paths += [resource / name for name in ("kernel.elf", "initrd.img", "boot_v2.arm64")]
    request = {
        "schema": "crucible.gem5.process-closure-request.v1",
        "pid": str(process.pid), "start_ticks": start_ticks,
        "owned_root": str(root), "modeled_root": str(resource), "image": str(image),
        "profile": "arm-linux-vexpress-atomic-root-functional-v1", "guest_isa": "aarch64",
        "guest_executable": str(resource / "kernel.elf"), "model_scope": scope,
        "boundary_sha256": hashlib.sha256(json.dumps(
            boundary, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
        "assets": [{"path": str(path), "sha256": digest(path)} for path in paths],
        "native_inventory": inventory,
    }
    for field in ("thread_contexts", "captured_descriptors", "captured_maps",
                  "captured_file_maps", "operational_shared_maps"):
        request[field] = inventory[field]
    (root / f"{label}-closure-request.json").write_text(json.dumps(request, sort_keys=True))
    inspected = subprocess.run(
        [sys.executable, "-B", str(Path(source_directory) / "full-system-process-image-audit.py")],
        input=json.dumps(request).encode(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=180, check=False,
    )
    (root / f"{label}-closure-result.json").write_bytes(inspected.stdout)
    (root / f"{label}-closure-stderr.txt").write_bytes(inspected.stderr)
    assert inspected.returncode == 0, inspected.stderr.decode("utf-8", "replace")[:4096]
    result = json.loads(inspected.stdout)
    assert result["byte_closure_complete"] and result["omissions"] == []
    assert result["execution_admission_qualified"] is False
    assert result["full_system_admission_qualified"] is False
    return result
