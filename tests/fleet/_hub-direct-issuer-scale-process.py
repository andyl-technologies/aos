"""Keep genuine scale subprocesses and their private roots under exact custody.

The supervisor waits for its own child and retains actual terminal status. No
used journal is reinitialized, no process is selected by name, and a failed stop
never triggers a broad kill or an assertion that remote issuer work drained.
"""

import errno
import hashlib
import json
import os
import secrets
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time


SCALE_PROCESS_FILE_LIMIT = 512 * 1024 * 1024


def scale_private_bytes(path, maximum):
    """Read an immutable bounded file without following a substituted symlink."""
    path = Path(path)
    # Source-built package entrypoints may be store-local symlinks. Resolve
    # only that immutable namespace; private configuration remains no-follow.
    actual_path = path.resolve(strict=True) if str(path).startswith('/nix/store/') else path
    if str(path).startswith('/nix/store/') and not str(actual_path).startswith('/nix/store/'):
        raise ValueError("selected immutable package reference escaped the store")
    descriptor = os.open(actual_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("selected process input custody or size differs")
        body = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    current = actual_path.stat(follow_symlinks=False)
    if str(path).startswith('/nix/store/') and path.resolve(strict=True) != actual_path:
        raise ValueError("selected immutable package reference changed")
    if len(body) != before.st_size or any(getattr(before, name) != getattr(row, name)
            for row in (after, current) for name in fields):
        raise ValueError("selected process input changed")
    return body


def scale_write_private(path, value):
    """Write one new bounded private record and acknowledge its actual fsync."""
    body = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
    if len(body) > 1024 * 1024:
        raise ValueError("private process record exceeds its bound")
    parent = Path(path).parent
    metadata = parent.stat(follow_symlinks=False)
    if (parent.resolve() != parent or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ValueError("process record parent differs from selected private custody")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    return {"file": str(path), "sha256": hashlib.sha256(body).hexdigest(), "byteSize": len(body)}


def scale_publish_private(path, value):
    """Publish a complete private handshake atomically without replacing a record."""
    path = Path(path)
    temporary = path.parent / (".cpu-" + secrets.token_hex(16))
    scale_write_private(temporary, value)
    try:
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink()


def scale_process_identity(pid):
    """Observe the actual process start time, executable and complete arguments."""
    directory = Path("/proc") / str(pid)
    executable = os.readlink(directory / "exe")
    with (directory / "exe").open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    return {"pid": pid, "ownerUid": directory.stat().st_uid,
        "startTicks": (directory / "stat").read_text().rpartition(") ")[2].split()[19],
        "arguments": [os.fsdecode(item) for item in (directory / "cmdline").read_bytes().split(b"\0")[:-1]],
        "executable": executable, "executableSha256": digest}


def scale_validate_process_spec(spec):
    """Check explicit child inputs before opening any new process resource."""
    fields = {"version", "root", "arguments", "environment", "files", "runId", "role"}
    if set(spec) != fields or type(spec["version"]) is not int or spec["version"] != 1:
        raise ValueError("process selection shape differs")
    root = Path(spec["root"])
    if not root.is_absolute() or root.parent.resolve() != root.parent:
        raise ValueError("process root differs from selected absolute custody")
    parent = root.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError("process parent is not owner-private")
    if spec["role"] not in {"issuer", "worker", "workload"} or len(spec["runId"]) != 32 or any(c not in "0123456789abcdef" for c in spec["runId"]):
        raise ValueError("selected process role or run differs")
    argv = spec["arguments"]
    if (not isinstance(argv, list) or not 2 <= len(argv) <= 16
            or any(not isinstance(item, str) or len(item) > 4096 or "\0" in item for item in argv)
            or not argv[0].startswith("/nix/store/")):
        raise ValueError("process requires selected source-built executable and bounded arguments")
    allowed = {"MINIFLARE_WORKERD_PATH", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"}
    if not isinstance(spec["environment"], dict) or not set(spec["environment"]).issubset(allowed):
        raise ValueError("process environment is not the explicit bounded fixture selection")
    if not isinstance(spec["files"], dict) or not 1 <= len(spec["files"]) <= 12 or argv[0] not in spec["files"]:
        raise ValueError("process has no exact executable/input inventory")
    for path, expected in spec["files"].items():
        if (not Path(path).is_absolute() or not isinstance(expected, str) or len(expected) != 64
                or any(character not in "0123456789abcdef" for character in expected)):
            raise ValueError("process input commitment differs")
        body = scale_private_bytes(path, SCALE_PROCESS_FILE_LIMIT)
        if hashlib.sha256(body).hexdigest() != expected:
            raise ValueError("selected process bytes differ from the final tuple")
    return root


def scale_validate_cpu_mountinfo(text):
    """Refuse hidden CPU ancestors even when the visible root has cpu.max."""
    matches = [row.split() for row in text.splitlines()
        if ' - cgroup2 ' in row and row.split()[4] == '/sys/fs/cgroup']
    if len(matches) != 1 or matches[0][3] != '/':
        raise ValueError("ancestor CPU allocation is outside the observed namespace")


def scale_cpu_allocation(pid):
    """Observe affinity and all visible ancestor quotas, refusing hidden roots."""
    allocated = sorted(os.sched_getaffinity(pid))
    # A cgroup quota may impose a smaller actual allocation than affinity.
    cgroup = (Path("/proc") / str(pid) / "cgroup").read_text()
    unified = [line.split(":", 2)[2] for line in cgroup.splitlines() if line.startswith("0::")]
    quota, quota_observations = None, []
    if len(unified) == 1:
        mount = Path('/sys/fs/cgroup')
        scale_validate_cpu_mountinfo(Path('/proc/self/mountinfo').read_text())
        selected_group = Path(unified[0])
        if not selected_group.is_absolute() or '..' in selected_group.parts:
            raise ValueError("actual CPU hierarchy is not observable through the selected mount")
        directory = mount / str(selected_group).lstrip('/')
        while True:
            if directory == mount and not (directory / 'cpu.max').exists():
                # The real root cgroup has no cpu.max controller file.
                # A namespace-hidden ancestor cannot be treated as free
                # CPU: require the actual mount to expose the root.
                quota_observations.append({"directory": str(directory), "quota": None,
                    "period": None, "scope": "actual root cgroup has no cpu.max"})
                break
            values = (directory / 'cpu.max').read_text().split()
            if len(values) != 2 or int(values[1]) <= 0:
                raise ValueError("actual CPU quota observation differs")
            quota_observations.append({"directory": str(directory), "quota": values[0], "period": values[1]})
            if values[0] != 'max':
                current_quota = int(values[0]) * 1000 // int(values[1])
                quota = min(quota, current_quota) if quota is not None else current_quota
            if directory == mount:
                break
            directory = directory.parent
    else:
        raise ValueError("actual unified CPU allocation hierarchy is unknown")
    millicores = min(len(allocated) * 1000, quota) if quota is not None else len(allocated) * 1000
    if millicores <= 0:
        raise ValueError("actual process CPU allocation is absent")
    return {"affinityCpus": allocated, "cgroupCpuQuotaMillicores": quota,
        "allocatedMillicores": millicores, "cgroupQuotaObservations": quota_observations}


def scale_sample_process_cpu(process):
    """Read real issuer ticks between exact lifetime, input and allocation checks.

    Failure remains an unknown sample; it cannot produce a zero counter or a
    successful budget. This reads a selected process and creates no permission.
    """
    try:
        if process["role"] != "issuer":
            raise ValueError("CPU endpoint is not the selected issuer")
        before = scale_process_identity(process["pid"])
        if any(before[name] != process[name] for name in before):
            raise ValueError("CPU endpoint process lifetime changed")
        for path, digest in process["selectedFiles"].items():
            if hashlib.sha256(scale_private_bytes(path, SCALE_PROCESS_FILE_LIMIT)).hexdigest() != digest:
                raise ValueError("CPU endpoint executable or configuration changed")
        allocation = scale_cpu_allocation(process["pid"])
        if any(allocation[name] != process[name] for name in allocation):
            raise ValueError("CPU endpoint allocation changed")
        monotonic_before, utc_before = time.monotonic_ns(), time.time_ns()
        fields = (Path('/proc') / str(process["pid"]) / 'stat').read_text().rpartition(') ')[2].split()
        user, system = int(fields[11]), int(fields[12])
        utc_after, monotonic_after = time.time_ns(), time.monotonic_ns()
        hertz = os.sysconf('SC_CLK_TCK')
        if fields[19] != process["startTicks"] or min(user, system) < 0 or hertz <= 0:
            raise ValueError("CPU endpoint counters or clock differ")
        if scale_cpu_allocation(process["pid"]) != allocation or scale_process_identity(process["pid"]) != before:
            raise ValueError("CPU endpoint lifetime or allocation changed during read")
        # Inputs are rechecked after the sample, not merely at process startup.
        for path, digest in process["selectedFiles"].items():
            if hashlib.sha256(scale_private_bytes(path, SCALE_PROCESS_FILE_LIMIT)).hexdigest() != digest:
                raise ValueError("CPU endpoint input changed during read")
        return {"outcome": "observed", "process": before, "selectedFiles": process["selectedFiles"],
            "allocation": allocation, "userTicks": user, "systemTicks": system, "ticksPerSecond": hertz,
            "monotonicBeforeNs": monotonic_before, "monotonicAfterNs": monotonic_after,
            "utcBeforeNs": utc_before, "utcAfterNs": utc_after}
    except (OSError, ValueError, KeyError, IndexError) as error:
        return {"outcome": "unknown", "reason": type(error).__name__}


def scale_supervise(spec):
    """Start one selected child and retain its real exit without a late listener."""
    root = scale_validate_process_spec(spec)
    root.mkdir(mode=0o700, exist_ok=False)
    started_ns = time.time_ns()
    environment = {"PATH": "", "LANG": "C", **spec["environment"]}
    descriptor = os.open(root / "process.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as log:
        child = subprocess.Popen(spec["arguments"], env=environment, cwd=root,
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        try:
            observed = scale_process_identity(child.pid)
            if observed["arguments"] != spec["arguments"] or observed["executableSha256"] != spec["files"][spec["arguments"][0]]:
                raise ValueError("actual subprocess differs from its selected final tuple")
            allocation = scale_cpu_allocation(child.pid)
            receipt = {"version": 1, **observed, "runId": spec["runId"], "role": spec["role"],
                "startedUnixNs": started_ns, "logFile": str(root / "process.log"),
                "selectedFiles": spec["files"], **allocation,
                "scope": "actual local child lifetime and permitted CPU allocation; not dedicated-host headroom"}
            scale_write_private(root / "process.json", receipt)
            exit_code = child.wait()
            log.flush()
            os.fsync(log.fileno())
            scale_write_private(root / "terminal.json", {"version": 1, "pid": child.pid,
                "startTicks": observed["startTicks"], "exitCode": exit_code,
                "completedUnixNs": time.time_ns(), "resourceRoot": str(root),
                "scope": "actual child terminal status; no remote-drain assertion"})
        except BaseException:
            # Unknown startup remains retained. No blind cleanup or owner retry.
            scale_write_private(root / "supervisor-error.json", {"version": 1,
                "pid": child.pid, "settlement": "unknown"})
            raise


def scale_stop_process(process, root, interrupt):
    """Signal only the selected live child and wait for its supervisor receipt."""
    current = scale_process_identity(process["pid"])
    if any(current[name] != process[name] for name in current):
        raise ValueError("selected process lifetime changed before scoped stop")
    root = Path(root)
    descriptor = os.pidfd_open(process["pid"])
    try:
        if scale_process_identity(process["pid"]) != current:
            raise ValueError("selected process lifetime changed before its pinned signal")
        signal.pidfd_send_signal(descriptor, signal.SIGINT if interrupt else signal.SIGTERM)
    finally:
        os.close(descriptor)
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        terminal = root / "terminal.json"
        if terminal.exists():
            result = json.loads(scale_private_bytes(terminal, 65536))
            if (result["pid"] != process["pid"] or result["startTicks"] != process["startTicks"]
                    or result["resourceRoot"] != str(root)):
                raise ValueError("terminal receipt belongs to another process")
            return result
        time.sleep(0.05)
    raise ValueError("owned process has no actual terminal receipt; no broad cleanup attempted")


def scale_listener_absent(port):
    """Observe that the selected loopback listener is absent before a fresh run."""
    with socket.socket() as probe:
        probe.settimeout(1)
        result = probe.connect_ex(("127.0.0.1", port))
    if result != errno.ECONNREFUSED:
        raise ValueError("selected issuer listener is present or its absence is unresolved")
    return {"port": port, "outcome": "connection_refused", "observedUnixNs": time.time_ns()}


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in {"supervise", "stop"}:
        raise ValueError("expected one explicit process action and private selection")
    selected = json.loads(scale_private_bytes(sys.argv[2], 65536))
    if sys.argv[1] == "supervise":
        scale_supervise(selected)
    else:
        print(json.dumps(scale_stop_process(selected["process"], selected["root"], selected["interrupt"])))
