"""Retain and restore exact local runner originals for one OCI audience check.

Only the selected same-owner runner and its independently pinned workerd child
are stopped. Exited processes do not prove SDK/provider drain. Original private
configuration, argv and raw environment remain available after every unknown.
"""

import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import time


MAX_ENVIRONMENT = 256 * 1024
MAX_CONFIG = 1024 * 1024


def require(value, message):
    if not value:
        raise ValueError(message)


def private_file(file, maximum):
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and not before.st_mode & 0o077
                and 0 < before.st_size <= maximum, "profile private file custody differs")
        body = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    require(len(body) == before.st_size and len(body) <= maximum
            and (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
            "profile private file changed")
    return body


def retained(path, body):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return {"file": str(path), "sha256": hashlib.sha256(body).hexdigest(), "byteSize": str(len(body))}


def process_identity(pin):
    directory = Path("/proc") / str(pin["pid"])
    before = (directory / "stat").read_text().rpartition(") ")[2].split()
    require(before[0] != "Z" and before[19] == pin["startTicks"]
            and directory.stat().st_uid == pin["ownerUid"] == os.getuid(),
            "profile process lifetime differs")
    with (directory / "exe").open("rb") as stream:
        executable = hashlib.file_digest(stream, "sha256").hexdigest()
    require(executable == pin["executableSha256"], "profile process executable differs")
    after = (directory / "stat").read_text().rpartition(") ")[2].split()
    require(before[19] == after[19] and after[0] != "Z", "profile process changed")
    return directory


def child_of(child, parent):
    current = child["pid"]
    for _ in range(16):
        require(current > 1, "profile workerd is not a runner descendant")
        fields = (Path("/proc") / str(current) / "stat").read_text().rpartition(") ")[2].split()
        current = int(fields[1])
        if current == parent["pid"]:
            return
    raise ValueError("profile process ancestry exceeds bound")


def capture_runner(root, runner, workerd, configuration_file):
    """Capture actual originals while both independently selected pins are live."""
    root = Path(root)
    root.mkdir(mode=0o700, exist_ok=False)
    process = process_identity(runner)
    process_identity(workerd)
    child_of(workerd, runner)
    with (process / "environ").open("rb") as stream:
        environment = stream.read(MAX_ENVIRONMENT + 1)
    with (process / "cmdline").open("rb") as stream:
        command = stream.read(65537)
    require(environment.endswith(b"\0") and 0 < len(environment) <= MAX_ENVIRONMENT
            and command.endswith(b"\0") and 0 < len(command) <= 65536,
            "profile process originals exceed bounds")
    require(hashlib.sha256(environment).hexdigest() == runner["environmentSha256"]
            and hashlib.sha256(command).hexdigest() == runner["commandLineSha256"],
            "profile process originals differ from launch")
    arguments = [os.fsdecode(value) for value in command[:-1].split(b"\0")]
    require(configuration_file in arguments and arguments[0].startswith("/nix/store/"),
            "profile runner argv does not select actual configuration")
    configuration = private_file(configuration_file, MAX_CONFIG)
    log = Path(runner["logFile"]).lstat()
    output = (process / "fd/1").stat()
    require(stat.S_ISREG(log.st_mode) and log.st_uid == os.getuid() and log.st_nlink == 1
            and not log.st_mode & 0o077 and (log.st_dev, log.st_ino) == (output.st_dev, output.st_ino),
            "profile actual runner stdout inode differs")
    process_identity(runner)
    process_identity(workerd)
    capture = {"version": 1, "runner": runner, "workerd": workerd,
        "configurationFile": configuration_file,
        "log": {"file": runner["logFile"], "device": log.st_dev, "inode": log.st_ino},
        "configuration": retained(root / "configuration-A.json", configuration),
        "environment": retained(root / "environment.private", environment),
        "command": retained(root / "command.private", command)}
    retained(root / "capture.json", json.dumps(capture, separators=(",", ":")).encode())
    return capture


def configuration_b(original, origin_a="https://localhost:4643", origin_b="https://localhost:4648"):
    """Derive only the reviewed B listener, audience and private control socket."""
    require(original["host"] == "127.0.0.1" and original["port"] == 4645,
            "profile original A listener differs")
    candidate = json.loads(json.dumps(original))
    candidate["port"] = 4647
    changed = 0
    for field in ("HUB_EXTERNAL_URL", "HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN", "HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN"):
        if field in candidate["bindings"]:
            require(candidate["bindings"][field] == origin_a, "profile original A origin differs")
            candidate["bindings"][field] = origin_b
            changed += 1
    require(changed >= 2 and candidate["bindings"]["HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN"] == origin_b,
            "profile original A purpose audience absent")
    candidate["acceptanceSocketPath"] = original["acceptanceSocketPath"] + ".profile-b"
    return candidate


def stop_runner(capture, deadline):
    """Wait for actual pinned runner and workerd exit before reusing persistence."""
    runner, child = capture["runner"], capture["workerd"]
    process_identity(runner)
    process_identity(child)
    child_of(child, runner)
    descriptors = [os.pidfd_open(pin["pid"]) for pin in (runner, child)]
    try:
        process_identity(runner)
        process_identity(child)
        signal.pidfd_send_signal(descriptors[0], signal.SIGTERM)
        poller = select.poll()
        for fd in descriptors:
            poller.register(fd, select.POLLIN)
        pending = set(descriptors)
        while pending:
            remaining = min(5.0, deadline - time.time())
            require(remaining > 0, "profile process exit unknown at original deadline")
            for fd, _ in poller.poll(int(remaining * 1000)):
                pending.discard(fd)
                poller.unregister(fd)
        return {"version": 1, "runner": runner, "workerd": child,
            "observedExitAtUnixMillis": str(time.time_ns() // 1_000_000),
            "scope": "actual_process_exit_not_provider_drain"}
    finally:
        for fd in descriptors:
            os.close(fd)


def launch_runner(capture, root, configuration_file, label):
    """Start the selected runner with retained exact environment and argv."""
    # Persistence may only be reused after both original process lifetimes ended.
    for pin in (capture["runner"], capture["workerd"]):
        path = Path("/proc") / str(pin["pid"])
        if path.exists():
            fields = (path / "stat").read_text().rpartition(") ")[2].split()
            require(fields[19] != pin["startTicks"] or fields[0] == "Z",
                    "profile original process still alive")
    environment_body = private_file(capture["environment"]["file"], MAX_ENVIRONMENT)
    command_body = private_file(capture["command"]["file"], 65536)
    require(hashlib.sha256(environment_body).hexdigest() == capture["environment"]["sha256"]
            and hashlib.sha256(command_body).hexdigest() == capture["command"]["sha256"],
            "profile retained launch originals changed")
    environment = {}
    for item in environment_body[:-1].split(b"\0"):
        name, separator, value = item.partition(b"=")
        require(separator and os.fsdecode(name) not in environment, "profile captured environment malformed")
        environment[os.fsdecode(name)] = os.fsdecode(value)
    arguments = [os.fsdecode(value) for value in command_body[:-1].split(b"\0")]
    require(arguments.count(capture["configurationFile"]) == 1, "profile original configuration argv ambiguous")
    arguments[arguments.index(capture["configurationFile"])] = configuration_file
    with Path(arguments[0]).open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == capture["runner"]["executableSha256"],
                "profile selected runner executable changed")
    original_bytes = private_file(capture["configuration"]["file"], MAX_CONFIG)
    original = json.loads(original_bytes)
    selected_bytes = private_file(configuration_file, MAX_CONFIG)
    expected = original if configuration_file == capture["configurationFile"] else configuration_b(original)
    require(json.loads(selected_bytes) == expected, "profile selected configuration differs from exact A/B")
    if configuration_file == capture["configurationFile"]:
        require(selected_bytes == original_bytes, "profile restored A bytes differ")
    root = Path(root)
    if label == "A-restored":
        log_file = capture["log"]["file"]
        fd = os.open(log_file, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        observed = os.fstat(fd)
        try:
            require(stat.S_ISREG(observed.st_mode) and observed.st_uid == os.getuid()
                    and observed.st_nlink == 1 and not observed.st_mode & 0o077
                    and (observed.st_dev, observed.st_ino)
                        == (capture["log"]["device"], capture["log"]["inode"]),
                    "profile restored stdout inode differs")
        except Exception:
            os.close(fd)
            raise
    else:
        log_file = str(root / (label + ".log"))
        fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        child = subprocess.Popen(arguments, env=environment, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
    time.sleep(0.05)
    proc = Path("/proc") / str(child.pid)
    fields = (proc / "stat").read_text().rpartition(") ")[2].split()
    pin = {"version": 1, "pid": child.pid, "startTicks": fields[19], "ownerUid": proc.stat().st_uid,
        "executableSha256": capture["runner"]["executableSha256"], "arguments": arguments,
        "environmentSha256": hashlib.sha256((proc / "environ").read_bytes()).hexdigest(),
        "commandLineSha256": hashlib.sha256((proc / "cmdline").read_bytes()).hexdigest(),
        "commandLineBytes": str(len((proc / "cmdline").read_bytes())), "logFile": log_file,
        "invocationObservationMode": "original_argv"}
    process_identity(pin)
    require(pin["environmentSha256"] == capture["environment"]["sha256"],
            "profile launched environment differs")
    retained(root / (label + ".process.json"), json.dumps(pin, separators=(",", ":")).encode())
    return pin


def capture_from_namespace(root, runner, namespace_file, configuration_file):
    """Join a retained live namespace observer's actual workerd lifetime."""
    report = json.loads(private_file(namespace_file, 65536))
    require(report["observationScope"] == "oci_sdk_emulator_namespace_readback"
            and report["runnerPid"] == runner["pid"]
            and report["runnerStartTicks"] == runner["startTicks"],
            "profile namespace observation belongs to another runner")
    directory = Path("/proc") / str(report["workerdPid"])
    child = {"pid": report["workerdPid"], "startTicks": report["workerdStartTicks"],
        "executableSha256": report["workerdExecutableSha256"], "ownerUid": directory.stat().st_uid}
    configuration = private_file(configuration_file, MAX_CONFIG)
    require(hashlib.sha256(configuration).hexdigest() == report["configurationSha256"],
            "profile namespace configuration differs")
    return capture_runner(root, runner, child, configuration_file)


def records(log_file, capture_id):
    """Read bounded actual console records; no missing event is synthesized."""
    body = private_file(log_file, 32 * 1024 * 1024)
    groups = {}
    for line in body.splitlines():
        prefix = b"oci_profile_load_observer "
        position = line.find(prefix)
        if position < 0:
            continue
        raw = line[position + len(prefix):]
        require(len(raw) <= 8192, "profile actual console record exceeds bound")
        record = json.loads(raw)
        if record.get("capture_id") != capture_id:
            continue
        require(record.get("scope") == "managed_oci_profile_load", "profile record scope differs")
        key = record["request_sha256"]
        groups.setdefault(key, []).append(record)
        require(len(groups) <= 256 and len(groups[key]) <= 4, "profile actual record corpus exceeds bound")
    return groups


def workerd_child(runner, expected_executable):
    """Find the actual selected workerd child without inventing a process pin."""
    process_identity(runner)
    directories = [entry for entry in Path('/proc').iterdir() if entry.name.isdigit()]
    require(len(directories) <= 16384, 'profile process census exceeds bound')
    matches = []
    for directory in directories:
        try:
            fields = (directory/'stat').read_text().rpartition(') ')[2].split()
            if fields[0] == 'Z' or directory.stat().st_uid != os.getuid():
                continue
            child = {'pid':int(directory.name),'startTicks':fields[19],
                'ownerUid':directory.stat().st_uid,'executableSha256':expected_executable}
            child_of(child, runner)
            process_identity(child)
            matches.append(child)
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
            continue
    require(len(matches) == 1, 'profile selected workerd child missing or ambiguous')
    process_identity(runner)
    return matches[0]
