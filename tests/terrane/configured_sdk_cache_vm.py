"""Checks actual configured CLI snapshots with separately recovered native caches."""

import contextlib
import errno
import fcntl
import json
import os
import pathlib
import runpy
import select
import shutil
import signal
import socket
import struct
import stat
import types
import subprocess
import sys
import tempfile
import time
import tomllib


PAYLOAD = b"independent configured SDK snapshot payload\n"
NAMESPACE_OBSERVATION = b"NATIVE_SDK_NAMESPACE "
REPOSITORY_OBSERVATION = b"NATIVE_SDK_READONLY_REPOSITORY "
PUBLISHER_PRIVATE_ROOTS = ["sealed", "staging", "pending-delete", "state/publication"]


def namespace_actor(driver, image, arguments, policy, stack, launcher=False, repository_paths=()):
    """Keeps the publisher outside a fresh client's private mount namespace."""
    credentials = ["setpriv", "--reuid", "840", "--regid", "840", "--groups", "844,845",
                   "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                   "--no-new-privs"]
    executable = [str(image / "bin" / arguments[0]), *map(str, arguments[1:])]
    if launcher:
        driver.require(policy == "readonly" and arguments[0] == "surface-index-owner-fixture"
            and arguments[1] in {"configured-worker", "configured-mounted", "configured-mounted-late", "configured-mounted-expiry", "configured-mounted-manifest"},
            "invalid configured worker fixture launcher")
    if policy is None:
        return credentials + executable

    bindings = []
    for domain in ["public", "private"]:
        for suffix in PUBLISHER_PRIVATE_ROOTS:
            path = driver.ROOT / "positive" / domain / suffix
            metadata = path.stat()
            driver.require(metadata.st_uid == 841 and metadata.st_mode & 0o7777 == 0o700,
                           "namespace input lacks publisher-private custody")
            bindings.append([str(path), metadata.st_dev, metadata.st_ino])
    if repository_paths:
        driver.require(policy == "readonly" and not launcher and len(repository_paths) == 2,
                       "repository read-only fixture requires the original confined CLI actor")
        for path in repository_paths:
            metadata = path.lstat()
            driver.require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 840
                           and stat.S_IMODE(metadata.st_mode) == 0o700,
                           "repository read-only input lacks original owner custody")
            bindings.append([str(path), metadata.st_dev, metadata.st_ino])
    encoded = json.dumps(bindings, separators=(",", ":"))
    scratch = stack.enter_context(tempfile.TemporaryDirectory(
        prefix="sdk-namespace-", dir=driver.ROOT / "scratch"))
    script = str(driver.IMAGE / "share/configured_sdk_cache_vm.py")
    verify = [sys.executable, script, "--verify-namespace", policy, encoded, *executable]
    if launcher:
        verify = [sys.executable, script, "--configured-worker-launcher", policy,
                  encoded, json.dumps(executable)]
        credentials = []
    return ["unshare", "--mount", "--propagation", "private", sys.executable, script,
            "--mount-namespace", policy, scratch, encoded, *credentials, *verify]


def mount_namespace(policy, scratch, bindings, command):
    """Applies the unit's inode-preserving policy or its old masking control."""
    if (os.geteuid() != 0 or policy not in {"readonly", "masked"}
            or len(bindings) not in {8, 10} or len(bindings) == 10 and policy != "readonly"):
        raise RuntimeError("invalid privileged namespace fixture")
    mask = pathlib.Path(scratch) / "inaccessible"
    mask.mkdir(mode=0)
    for path, _, _ in bindings:
        source = str(mask) if policy == "masked" else path
        subprocess.run(["mount", "--bind", source, path], check=True, timeout=5)
        subprocess.run(["mount", "-o", "remount,bind,ro", path], check=True, timeout=5)
    os.execvp(command[0], command)


def verify_namespace(policy, bindings, command):
    """Checks real mount identities and read denial after dropping all capabilities."""
    if (os.geteuid() != 840 or policy not in {"readonly", "masked"}
            or len(bindings) not in {8, 10} or len(bindings) == 10 and policy != "readonly"):
        raise RuntimeError("invalid unprivileged namespace fixture")
    for index, (path, device, inode) in enumerate(bindings):
        descriptor = os.open(path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            same = (metadata.st_dev, metadata.st_ino) == (device, inode)
            if same != (policy == "readonly"):
                raise RuntimeError("namespace inode policy differs from original roots")
            if not os.fstatvfs(descriptor).f_flag & os.ST_RDONLY:
                raise RuntimeError("bound root is writable in client namespace")
        finally:
            os.close(descriptor)
        if index >= 8:
            # The actor owns this existing directory. EROFS, rather than DAC
            # denial, proves its repository and authority mounts are read-only.
            probe = pathlib.Path(path) / ".terrane-readonly-probe"
            try:
                writable = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except OSError as error:
                if error.errno != errno.EROFS:
                    raise
            else:
                os.close(writable)
                raise RuntimeError("original repository root is writable in client namespace")
            continue
        try:
            readable = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as error:
            if error.errno != errno.EACCES:
                raise
        else:
            os.close(readable)
            raise RuntimeError("unprivileged client can read a publisher-private directory")
    print(NAMESPACE_OBSERVATION.decode() + json.dumps({
        "policy": policy, "roots": 8, "read_denied": True,
        "readonly": True, "original_inodes": policy == "readonly",
    }, sort_keys=True), flush=True)
    if len(bindings) == 10:
        print(REPOSITORY_OBSERVATION.decode() + json.dumps({
            "roots": bindings[8:], "readonly": True, "write_errno": errno.EROFS,
            "uid": os.geteuid(),
        }, sort_keys=True), flush=True)
    os.execv(command[0], command)


def configured_worker_launcher(policy, bindings, command):
    """Starts the actual child before Rust irrevocably enters UID 840 custody."""
    if (os.geteuid() != 0 or policy != "readonly" or len(command) != 3
            or pathlib.Path(command[0]).name != "surface-index-owner-fixture"
            or command[1] not in {"configured-worker", "configured-mounted", "configured-mounted-late", "configured-mounted-expiry", "configured-mounted-manifest"}):
        raise RuntimeError("invalid configured worker fixture launcher")
    # Observe the very same namespace as the actual unprivileged actor. The
    # short verifier opens no readable publisher-private aliases for its parent.
    subprocess.run(["setpriv", "--reuid", "840", "--regid", "840", "--groups", "844,845",
                    "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                    "--no-new-privs", sys.executable, __file__, "--verify-namespace",
                    policy, json.dumps(bindings), sys.executable, "-c", "pass"],
                   check=True, timeout=5,
                   stdout=sys.stderr if command[1] in {"configured-mounted", "configured-mounted-late", "configured-mounted-expiry", "configured-mounted-manifest"} else None)
    setpriv = shutil.which("setpriv")
    if setpriv is None:
        raise RuntimeError("missing AOS-built fixture launcher")
    os.environ["TERRANE_WORKER_SETPRIV"] = setpriv
    os.execv(command[0], command)


def manifest_payload():
    """Computes the supervisor's independent expected multi-chunk plaintext."""
    state = 7
    result = bytearray()
    for _ in range(2097153):
        state ^= (state << 13) & 0xffffffff
        state ^= state >> 17
        state ^= (state << 5) & 0xffffffff
        result.append(state & 255)
    return bytes(result)


def actor(driver, image, label, arguments, success=True, mount_policy=None, maintained=False,
          launcher=False, on_ready=None, environment=None, repository_paths=()):
    """Runs one fresh source-bound actor under the original supervisor's bounds."""
    with contextlib.ExitStack() as stack:
        command = namespace_actor(driver, image, arguments, mount_policy, stack, launcher, repository_paths)
        return run_actor(driver, label, command, success, mount_policy, maintained, on_ready, environment, repository_paths)


def run_actor(driver, label, command, success, mount_policy, maintained, on_ready=None, environment=None,
              repository_paths=()):
    """Collects bounded actor output and retains every namespace observation."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, env=environment)
    output = [bytearray(), bytearray()]
    streams = {process.stdout: output[0], process.stderr: output[1]}
    started = time.monotonic()
    actor_deadline = started + 30
    deadline = min(driver.DEADLINE, actor_deadline)
    stop_at = None
    stopped = False
    state_inodes = None
    try:
        while streams:
            if maintained and not stopped:
                snapshots = [line for line in output[0].splitlines(keepends=True)
                             if line.startswith(b"completed SDK snapshot ") and line.endswith(b"\n")]
                if len(snapshots) == 2:
                    driver.require(process.poll() is None,
                                   "native cache exited at SDK completion: " + label)
                    if stop_at is None:
                        state_inodes = verify_owner_locks(driver, True)
                        if on_ready is not None:
                            on_ready(process.pid)
                            verify_owner_locks(driver, True, state_inodes)
                        stop_at = time.monotonic() + 2
                    if time.monotonic() >= stop_at:
                        verify_owner_locks(driver, True, state_inodes)
                        process.send_signal(signal.SIGTERM)
                        stopped = True
            remaining = deadline - time.monotonic()
            driver.require(remaining > 0, "native SDK actor deadline: " + label)
            if stop_at is not None and not stopped:
                remaining = min(remaining, max(0, stop_at - time.monotonic()))
            ready, _, _ = select.select(list(streams), [], [], remaining)
            if not ready and stop_at is not None and not stopped:
                continue
            driver.require(ready, "native SDK actor output timeout: " + label)
            for stream in ready:
                chunk = os.read(stream.fileno(), 4096)
                if chunk:
                    streams[stream].extend(chunk)
                    driver.require(len(streams[stream]) <= driver.MAX_OUTPUT,
                                   "native SDK actor output bound: " + label)
                else:
                    stream.close()
                    del streams[stream]
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        driver.stop(process)
        timing = {
            "actor": label,
            "elapsed_seconds": time.monotonic() - started,
            "whole_remaining_at_start": driver.DEADLINE - started,
            "deadline_source": "whole" if driver.DEADLINE < actor_deadline else "actor",
            "maintained": maintained,
            "exit_status": process.returncode,
        }
        encoded = json.dumps(timing, sort_keys=True)
        (driver.ROOT / "proof-logs" / ("native-sdk-" + label + ".timing.json")).write_text(encoded + "\n")
        print("NATIVE_SDK_ACTOR_TIMING " + encoded, flush=True)
        for suffix, data in zip(["stdout", "stderr"], output):
            (driver.ROOT / "proof-logs" / ("native-sdk-" + label + "." + suffix)).write_bytes(data)
            print(data.decode("utf-8", errors="replace"), end="", flush=True)

    driver.require(process.returncode == (0 if success else 1),
                   "native SDK actor exit status: " + label)
    if maintained:
        driver.require(stopped, "native cache exited before supervised SIGTERM: " + label)
        verify_owner_locks(driver, False, state_inodes)
        print("PASS actual maintained native cache owns both original state locks after SDK completion and releases them after SIGTERM", flush=True)
    if mount_policy is not None:
        rows = [json.loads(line[len(NAMESPACE_OBSERVATION):])
                for line in output[0].splitlines() if line.startswith(NAMESPACE_OBSERVATION)]
        driver.require(rows == [{"policy": mount_policy, "roots": 8, "read_denied": True,
                                 "readonly": True, "original_inodes": mount_policy == "readonly"}],
                       "missing actual unprivileged namespace observation: " + label)
        output[0] = b"".join(line for line in output[0].splitlines(keepends=True)
                             if not line.startswith(NAMESPACE_OBSERVATION))
    if repository_paths:
        rows = [json.loads(line[len(REPOSITORY_OBSERVATION):])
                for line in output[0].splitlines() if line.startswith(REPOSITORY_OBSERVATION)]
        expected = [[str(path), path.stat().st_dev, path.stat().st_ino] for path in repository_paths]
        driver.require(rows == [{"roots": expected, "readonly": True,
                                 "write_errno": errno.EROFS, "uid": 840}],
                       "missing original read-only repository mount observation: " + label)
        output[0] = b"".join(line for line in output[0].splitlines(keepends=True)
                             if not line.startswith(REPOSITORY_OBSERVATION))
    return tuple(map(bytes, output))


def verify_owner_locks(driver, held, expected=None):
    """Checks kernel exclusion on both original cache directories, including the unused domain."""
    identities = {}
    for domain in ["public", "private"]:
        path = driver.ROOT / "positive" / domain / "state/cache"
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            identities[domain] = (metadata.st_dev, metadata.st_ino)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                driver.require(held and error.errno in {errno.EAGAIN, errno.EWOULDBLOCK},
                               "native cache state lock refusal differs")
            else:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                driver.require(not held, "maintained native owner lost kernel state exclusion")
        finally:
            os.close(descriptor)
    driver.require(expected is None or identities == expected,
                   "maintained native cache replaced an original state directory")
    return identities


def host_configuration(driver, refused=False, mode="never"):
    """Uses the same explicit one-second retirement/grace policy as reassembly controls."""
    root = driver.ROOT / "positive"
    text = f"""
[host_tier]
path = "{root}"
size_bytes = 67108864
reassembly = "{mode}"
[host_tier.publisher]
socket_path = "/run/terrane-initial-publisher/publisher.sock"
serve_uid = 840
publish_uid = 841
content_uid = 840
content_gid = 845
max_connections = 8
[host_tier.quota]
socket_path = "{root}/quota.sock"
configuration_epoch = "00000000000000000000000000000001"
"""
    for domain, directory in [("public", "public"), ("private:fixture", "private")]:
        owner = "not-enrolled" if refused else "fixture-" + directory
        text += f"""
[host_tier.domains."{domain}"]
path = "{root}/{directory}"
administrative_root = "{root}/{directory}-admin"
wipe = "none"
quota_owner_id = "{owner}"
[host_tier.domains."{domain}".publisher]
retirement_grace_ms = 1000
chunk_profile = "cdc-1m"
chunk_seed = "{"07" * 32}"
[host_tier.domains."{domain}".cache]
state_gid = 844
capacity_bytes = 25165824
low_watermark_bytes = 16777216
probation_bytes = 65536
release_grace_seconds = 1
scan_limit = 64
max_read_bytes = 2097152
state_bytes = 65536
state_records = 64
inventory_entries = 128
queued_commands = 4
metadata_sync_hold_bytes = 262144
publisher_wait_budget_ms = 10000
consumer_lease_seconds = 30
[host_tier.domains."{domain}".cache.portable]
max_file_bytes = 67108864
max_input_bytes = 268435456
max_files = 4096
max_selected_bytes = 33554432
[host_tier.domains."{domain}".cache.lower]
budget_ms = 10000
failure_threshold = 3
probe_interval_ms = 5000
"""
    return text


def maintenance_gc_actor(executable, config, private_paths):
    """Checks actual fresh GC credentials and denied private state before exec."""
    status = dict(line.split(":", 1) for line in pathlib.Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    if status["Uid"].split() != ["843"] * 4 or status["Gid"].split() != ["843"] * 4:
        raise RuntimeError("maintenance GC credentials differ")
    if status["Groups"].split() != ["846"]:
        raise RuntimeError("maintenance GC retains a non-transport group")
    if status["NoNewPrivs"].strip() != "1" or any(
            int(status[field], 16) for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]):
        raise RuntimeError("maintenance GC retains capabilities or lacks NNP")
    for path in private_paths:
        try:
            with open(path, "rb"):
                pass
        except PermissionError:
            continue
        raise RuntimeError("maintenance GC could open private owner state")
    print("CONFIGURED_MAINTENANCE_GC_IDENTITY uid=843 gid=843 capabilities=0 nnp=1 private-state=denied", file=sys.stderr, flush=True)
    os.execv(executable, [executable, "--config", config, "--role", "gc"])


def maintenance_exchange(driver, image, config, label, success=True, foreign=False):
    """Executes a fresh actual CLI; replies can originate only from retained Serve owners."""
    command = ["setpriv", "--reuid", "842" if foreign else "843",
               "--regid", "842" if foreign else "843", "--groups", "846",
               "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs"]
    executable = str(image / "bin/configured-sdk-maintenance-cli")
    if foreign:
        command += [executable, "--config", str(config), "--role", "gc"]
    else:
        private = [str(driver.ROOT / "positive" / domain / "state/cache/records.toml")
                   for domain in ["public", "private"]]
        command += [sys.executable, str(driver.IMAGE / "share/configured_sdk_cache_vm.py"),
                    "--maintenance-gc-actor", executable, str(config), json.dumps(private)]
    remaining = min(5, driver.DEADLINE - time.monotonic())
    driver.require(remaining > 0, "configured maintenance whole-guest deadline")
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, timeout=remaining)
    log = driver.ROOT / "proof-logs" / label
    log.with_suffix(".stdout").write_bytes(result.stdout)
    log.with_suffix(".stderr").write_bytes(result.stderr)
    log.with_suffix(".timing.json").write_text(json.dumps({
        "exit_status": result.returncode, "elapsed_seconds": time.monotonic() - started,
        "whole_remaining_at_start": driver.DEADLINE - started, "deadline_seconds": remaining,
    }, sort_keys=True) + "\n")
    driver.require(len(result.stdout) + len(result.stderr) <= driver.MAX_OUTPUT,
                   "configured maintenance output bound")
    if result.returncode != (0 if success else 1):
        # Guest cleanup removes its private scratch disk. Retain bounded actual
        # transport diagnostics in the immutable serial log before refusing.
        print("CONFIGURED_MAINTENANCE_EXCHANGE_FAILURE " + json.dumps({
            "label": label, "exit_status": result.returncode,
            "stdout": result.stdout.decode("utf-8", errors="replace"),
            "stderr": result.stderr.decode("utf-8", errors="replace"),
        }, sort_keys=True), flush=True)
    driver.require(result.returncode == (0 if success else 1), "configured GC CLI exit status differs")
    if success:
        expected = [f"domain {domain}: checked 0, completed 0, blocked 0 draining exposures"
                    for domain in ["private:fixture", "public"]]
        driver.require(result.stdout.decode().splitlines() == expected, "actual original-owner responses differ")
        driver.require(result.stderr.decode().splitlines() == [
            "CONFIGURED_MAINTENANCE_GC_IDENTITY uid=843 gid=843 capabilities=0 nnp=1 private-state=denied"],
            "actual GC identity or private-state refusal witness differs")
    else:
        driver.require(not result.stdout, "refused GC synthesized successful responses")
    print("CONFIGURED_MAINTENANCE_EXCHANGE_PROOF " + json.dumps({
        "label": label, "image": str(image), "exit_status": result.returncode,
        "stdout": result.stdout.decode(), "stderr": result.stderr.decode(),
        "elapsed_seconds": time.monotonic() - started, "deadline_seconds": remaining,
    }, sort_keys=True), flush=True)
    return result


def run_maintenance(driver, image):
    """Checks configured listeners and GC dispatch without claiming exposure release."""
    subprocess.run([sys.executable, str(image / "share/configured_sdk_proof.py"),
                    "verify", str(image), str(driver.SOURCE)], check=True, timeout=30)
    parent = pathlib.Path("/run/terrane-configured-maintenance")
    parent.mkdir(mode=0o750)
    os.chown(parent, 840, 846)
    parent.chmod(0o2750)
    repository_parent = driver.ROOT / "configured-maintenance"
    repository_parent.mkdir(mode=0o700)
    os.chown(repository_parent, 840, 840)
    root = repository_parent / "repository"
    config = driver.ROOT / "configured-maintenance.toml"
    sockets = [parent / name for name in ["public.sock", "private.sock"]]
    notify_path = parent / "notify.sock"
    notifier = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        notifier.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        notifier.bind(str(notify_path))
        notify_path.chmod(0o666)
        notifier.settimeout(2)
        actor(driver, image, "maintenance-setup", ["configured-sdk-cache-example", "setup-public", root, 840])
        text = (root / "config.toml").read_text() + host_configuration(driver)
        for domain in ["public", "private:fixture"]:
            text += f'\n[host_tier.domains."{domain}".cache.surface_index]\nmax_entries=16\nmax_node_bytes=65536\nmax_index_bytes=65536\ncapacity_bytes=25165824\nfuture_hold_bytes=327680\n'
        text += f'\n[host_tier.maintenance]\ngc_uid=843\nmax_connections=2\nmax_requests=1\nconnection_timeout_ms=3000\nrequest_timeout_ms=2000\n[host_tier.maintenance.sockets]\npublic="{sockets[0]}"\n"private:fixture"="{sockets[1]}"\n'
        config.write_text(text)
        original_inodes = []

        def ready(expected_pid):
            message, ancillary, flags, _ = notifier.recvmsg(256, socket.CMSG_SPACE(struct.calcsize("3i")))
            driver.require(message == b"READY=1\nSTATUS=Serving configured Terrane snapshots and host cache"
                           and flags == 0 and len(ancillary) == 1,
                           "configured serving readiness notification differs")
            level, kind, credentials = ancillary[0]
            pid, uid, gid = struct.unpack("3i", credentials)
            driver.require(level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS
                           and pid == expected_pid and uid == 840 and gid == 840,
                           "configured serving notification lacks actual kernel identity")
            original_inodes.extend((path.stat().st_dev, path.stat().st_ino) for path in sockets)
            for path in sockets:
                metadata = path.lstat()
                driver.require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == 840
                               and metadata.st_gid == 846 and stat.S_IMODE(metadata.st_mode) == 0o660,
                               "configured maintenance listener protection differs")
            maintenance_exchange(driver, image, config, "maintenance-gc-foreign", success=False, foreign=True)
            maintenance_exchange(driver, image, config, "maintenance-gc-first")
            maintenance_exchange(driver, image, config, "maintenance-gc-second")
            driver.require(original_inodes == [(path.stat().st_dev, path.stat().st_ino) for path in sockets],
                           "GC replaced original listener inodes")
            print("PASS configured Serve binds both protected domain listeners before readiness; two fresh confined GC CLI processes authenticate original owners while private state remains denied", flush=True)
            print("PASS actual configured CLI sends one complete manager readiness datagram as kernel UID/GID 840 after original owners and protected listeners are ready", flush=True)
            print("CONFIGURED_MAINTENANCE_READY " + json.dumps({
                "sender_pid": pid, "main_pid": expected_pid, "uid": uid, "gid": gid,
                "listener_inodes": original_inodes, "owners_locked": True,
                "notification": message.decode(),
            }, sort_keys=True), flush=True)

        stdout, stderr = actor(driver, image, "maintenance-serve",
              ["configured-sdk-cache-cli", "--config", config, "--role", "serve"],
              mount_policy="readonly", maintained=True, on_ready=ready,
              environment=dict(os.environ, NOTIFY_SOCKET=str(notify_path)),
              repository_paths=(root / "bucket", root / "authority"))
        notifier.setblocking(False)
        try:
            notifier.recv(256)
        except BlockingIOError:
            pass
        else:
            raise RuntimeError("configured CLI sent repeated readiness notifications")
        maintenance_exchange(driver, image, config, "maintenance-gc-stopped", success=False)
        driver.require(all(not path.exists() and not path.is_symlink() for path in sockets),
                       "acknowledged serving shutdown retained or replaced listener names")
        print("CONFIGURED_MAINTENANCE_RETIRED " + json.dumps({
            "listener_inodes": original_inodes, "names_absent": True,
            "owners_unlocked": True, "stopped_gc_refused": True,
        }, sort_keys=True), flush=True)
        actor(driver, image, "maintenance-publication",
              ["configured-sdk-cache-example", "verify-reopen-publication", root, 840])
        root.with_suffix(".stdout").write_bytes(stdout)
        root.with_suffix(".stderr").write_bytes(stderr)
        actor(driver, image, "maintenance-snapshots",
              ["configured-sdk-cache-example", "verify-cli", root, 840])
        print("PASS configured GC refuses stopped serving owners without rebinding listeners; original owner locks release after acknowledged SIGTERM and signed publication remains intact", flush=True)
        print("PASS configured Serve opens its original repository and authority through read-only mounts while preserving signed snapshots and maintenance", flush=True)
        print("PASS acknowledged Serve shutdown retires only its original maintenance socket names after all borrowed request futures stop", flush=True)
    finally:
        notifier.close()
        notify_path.unlink(missing_ok=True)
        for path in sockets:
            path.unlink(missing_ok=True)
        parent.rmdir()


def cache_states(driver):
    """Reads actual durable native policy without treating it as a live grant."""
    result = {}
    for domain in ["public", "private"]:
        path = driver.ROOT / "positive" / domain / "state/cache/records.toml"
        result[domain] = path.read_bytes() if path.exists() else None
    return result


def native_content_inodes(driver):
    """Captures actual persistent object identities without treating rows as custody."""
    result = {}
    for domain in ["public", "private"]:
        root = driver.ROOT / "positive" / domain
        for directory in ["objects", "sealed"]:
            for path in (root / directory).rglob("*"):
                if path.is_file():
                    metadata = path.stat()
                    result[str(path)] = (metadata.st_dev, metadata.st_ino, metadata.st_size)
    return result


def verify_funding(driver, directory, before, after):
    """Checks distinct startup, metadata retention and released-consumer holds."""
    owner = "fixture-" + directory
    reservations = after["reservations"]
    driver.require(len({row["id"] for row in reservations}) == len(reservations),
                   "native SDK repeats a reservation token")
    added = [row for row in reservations if row not in before["reservations"]]
    bootstraps = []
    for row in added:
        driver.require(row["owner"] == owner and row["bytes"] == 262144,
                       "native SDK changed a new hold's exact owner or funding")
        metadata_owner = "metadata:" + row["id"]
        metadata_leases = [lease for lease in after["leases"]
                           if lease["owner"] == metadata_owner]
        if metadata_leases:
            # Manifest bodies and their source packs stay funded independently
            # of consumer release. These rows do not prove native custody.
            pins = [pin for pin in after["pins"] if pin["owner"] == metadata_owner]
            driver.require(len(metadata_leases) == 1
                           and metadata_leases[0]["expires"] == 9223372036854775807
                           and len(pins) == 2 and len({pin["hash"] for pin in pins}) == 2
                           and all(pin["expires"] == metadata_leases[0]["expires"]
                                   and len(pin["hash"]) == 64
                                   and all(char in "0123456789abcdef" for char in pin["hash"])
                                   for pin in pins)
                           and not any(lease["owner"] in
                                       {"consumer:" + row["id"], "consumer-grace:" + row["id"]}
                                       for lease in after["leases"]),
                           "native SDK metadata hold lacks its exact durable pin closure")
            continue
        names = {"consumer:" + row["id"], "consumer-grace:" + row["id"]}
        leases = [lease for lease in after["leases"] if lease["owner"] in names]
        if not leases:
            bootstraps.append(row)
            continue
        driver.require(len(leases) == 1, "native SDK gives one consumer two lifecycle owners")
        lease = leases[0]
        driver.require(lease["owner"].startswith("consumer-grace:"),
                       "completed SDK still owns a live consumer grant")
        pins = [pin for pin in after["pins"] if pin["owner"] == lease["owner"]]
        driver.require(pins and all(pin["expires"] == lease["expires"]
                                   and len(pin["hash"]) == 64
                                   and all(char in "0123456789abcdef" for char in pin["hash"])
                                   for pin in pins),
                       "native SDK consumer hold lacks its exact durable pin closure")
    driver.require(len(bootstraps) == 1,
                   "native SDK lacks exactly one new bootstrap hold: "
                   + repr({"holds": added, "leases": after["leases"]}))
    now = int(time.time())
    for row in before["reservations"]:
        if row in reservations:
            continue
        names = {"consumer:" + row["id"], "consumer-grace:" + row["id"]}
        leases = [lease for lease in before["leases"] if lease["owner"] in names]
        driver.require(len(leases) == 1 and row["owner"] == owner and row["bytes"] == 262144,
                       "native SDK dropped an original non-consumer hold")
        lease = leases[0]
        end = lease["expires"] + (1 if lease["owner"].startswith("consumer:") else 0)
        driver.require(end <= now,
                       "native SDK dropped consumer funding before its original grace expired")


def run_manifest(driver, surface_image):
    """Checks original native manifest open independently of kernel registration."""
    verify = runpy.run_path(str(surface_image / "share/surface_index_owner_vm.py"))["verify_surface"]
    verify(surface_image, driver.SOURCE)
    parent = driver.ROOT / "manifest-open"
    parent.mkdir(mode=0o700)
    os.chown(parent, 840, 840)
    config = parent / "config.toml"
    config.write_text('store = "disk(/unused-manifest-source)"\n'
                      + host_configuration(driver, mode="always") + """
[host_tier.domains.public.cache.surface_index]
max_entries = 16
max_node_bytes = 65536
max_index_bytes = 65536
capacity_bytes = 25165824
future_hold_bytes = 327680
""")
    stdout, _ = actor(driver, surface_image, "manifest-open",
        ["surface-index-owner-fixture", "configured-surface", config, "manifest-open"],
        mount_policy="readonly")
    driver.require(stdout.decode().splitlines() == [
        "PASS signed manifest index compiles and maps with zero manifest or chunk reads",
        "PASS authenticated manifest open resolves original CDC ranges and closes Read around the measured sealed inode and durable exposure binding",
        "PASS warm manifest open reuses the original measured inode without another manifest or chunk read; retained descriptor survives consumer release",
    ], "manifest open lacks its exact original-owner witnesses")
    verify(surface_image, driver.SOURCE)
    print("PASS native configured manifest open defers signed resolution until file open and preserves original sealed custody", flush=True)


def run_surface(driver, image, surface_image, service_only=False,
                mounted_only=False, late_only=False, expiry_only=False,
                manifest_only=False):
    """Requires configured bounds to reach the original enrolled physical owners."""
    subprocess.run([sys.executable, str(image / "share/configured_sdk_proof.py"),
                    "verify", str(image), str(driver.SOURCE)], check=True, timeout=30)
    runpy.run_path(str(surface_image / "share/surface_index_owner_vm.py"))["verify_surface"](
        surface_image, driver.SOURCE)
    parent = driver.ROOT / "configured-surface"
    parent.mkdir(mode=0o700)
    os.chown(parent, 840, 840)
    root = parent / "original"
    actor(driver, image, "surface-source-setup",
          ["configured-sdk-cache-example", "setup", root, 840])
    config = root / "config.toml"
    # This actor qualifies native factory policy, without starting presentation.
    # The FUSE-only binary must still reject the SDK fixture's exposure endpoint.
    store = tomllib.loads(config.read_text())["store"]
    original = 'role = "serve"\nstore = ' + json.dumps(store) + "\n"

    # Index recovery measures unchanged original exposure pins and leases. Run
    # it before cold manifest publication: later recovery legitimately funds
    # independently verified reconstruction metadata with additional pins.
    if manifest_only:
        modes = ["mounted-manifest"]
    elif expiry_only:
        modes = ["mounted-expiry"]
    elif late_only:
        modes = ["mounted-late"]
    elif mounted_only:
        modes = ["mounted"]
    elif service_only:
        modes = ["service"]
    else:
        modes = ["disabled", "bound", "recover-draining", "admit", "service"]
    for mode in modes:
        text = original + host_configuration(driver,
            mode="always" if mode in {"admit", "service", "mounted", "mounted-late", "mounted-expiry", "mounted-manifest"} else "never")
        if mode != "disabled":
            node_bytes = 32 if mode == "bound" else 65536
            text += f"""
[host_tier.domains.public.cache.surface_index]
max_entries = 16
max_node_bytes = {node_bytes}
max_index_bytes = 65536
capacity_bytes = 25165824
future_hold_bytes = 327680
"""
        config.write_text(text)
        if mode in {"mounted", "mounted-late", "mounted-expiry", "mounted-manifest"}:
            run_configured_mount(driver, surface_image, config,
                late=mode == "mounted-late", expiry=mode == "mounted-expiry",
                manifest=mode == "mounted-manifest")
            continue
        arguments = (["surface-index-owner-fixture", "configured-worker", config]
                     if mode == "service" else
                     ["surface-index-owner-fixture", "configured-surface", config, mode])
        stdout, _ = actor(driver, surface_image, "surface-" + mode, arguments,
                          mount_policy="readonly", launcher=mode == "service")
        if mode == "service":
            witness = "PASS retained configured worker service completes original cold cache handoff after cancelled wait and acknowledged drain without disclosing backing"
        elif mode == "recover-draining":
            witness = "PASS configured funded cache reopen completes actual recovery and new Resume while retaining the original draining mapping; exact final-unmap charge release precedes authenticated policy discharge"
        elif mode == "admit":
            witness = "PASS configured funded surface policy reaches actual recovered owner and warm reuse retains original sealed inode"
        else:
            witness = f"PASS configured surface {mode} policy refuses before durable mutation"
        witnesses = [witness]
        if mode == "admit":
            witnesses.append("PASS signed cold inline and multi-chunk preparations seal original native backing before closing Read; warm grants preserve inode without lower content traffic")
            witnesses.append("PASS oversized lower body refuses before decoding and native policy mutation; incompatible signed reassembly refuses before content traffic")
        driver.require(stdout.decode().splitlines() == witnesses,
                       "configured surface control lacks its exact native witness: " + mode)

    runpy.run_path(str(surface_image / "share/surface_index_owner_vm.py"))["verify_surface"](
        surface_image, driver.SOURCE)
    if manifest_only:
        print("PASS native configured mounted manifest component; production broker and task acceptance remain unqualified", flush=True)
    elif expiry_only:
        print("PASS native configured exposure-expiry component; production broker and task acceptance remain unqualified", flush=True)
    elif late_only:
        print("PASS native configured expired-open retained cold component; production broker and task acceptance remain unqualified", flush=True)
    elif mounted_only:
        print("PASS native configured cold backing serves actual mounted production worker; production broker and task acceptance remain unqualified", flush=True)
    elif service_only:
        print("PASS native configured retained worker service component; deployed FUSE and task acceptance remain unqualified", flush=True)
    else:
        print("PASS native configured surface-index policy component; deployed FUSE and task acceptance remain unqualified", flush=True)



def run_configured_mount(driver, image, config, late=False, expiry=False, manifest=False):
    """Uses the genuine guest device and original configured owner in one mount."""
    fuse = pathlib.Path("/dev/fuse")
    if not fuse.exists():
        os.mknod(fuse, stat.S_IFCHR | 0o600, os.makedev(10, 229))
    observed = fuse.stat()
    driver.require(stat.S_ISCHR(observed.st_mode)
                   and observed.st_rdev == os.makedev(10, 229),
                   "original configured FUSE character device unavailable")
    fuse.chmod(0o666)
    runtime = driver.ROOT / "configured-mounted-runtime"
    runtime.mkdir(mode=0o700)
    try:
        with contextlib.ExitStack() as stack:
            if manifest:
                mode = "configured-mounted-manifest"
            elif expiry:
                mode = "configured-mounted-expiry"
            elif late:
                mode = "configured-mounted-late"
            else:
                mode = "configured-mounted"
            command = namespace_actor(driver, image,
                ["surface-index-owner-fixture", mode, config],
                "readonly", stack, launcher=True)
            support = types.SimpleNamespace(RUNTIME=runtime, require=driver.require)
            runpy.run_path(str(image / "share/mounted_worker_vm.py"))["run"](
                support, str(image / "bin/surface-index-owner-fixture"), dict(os.environ),
                driver.SOURCE, owner_command=command, configured=True, late=late, expiry=expiry, manifest=manifest)
        observations = [json.loads(line[len(NAMESPACE_OBSERVATION):])
                        for line in (runtime / "mounted-owner.log").read_bytes().splitlines()
                        if line.startswith(NAMESPACE_OBSERVATION)]
        driver.require(observations == [{"policy": "readonly", "roots": 8,
            "read_denied": True, "readonly": True, "original_inodes": True}],
            "configured mounted owner lacks actual original namespace observation")
    finally:
        # The mounted supervisor already removed its mount and original child.
        # Preserve its log in the ordinary guest proof packet before cleanup.
        log = runtime / "mounted-owner.log"
        if log.exists():
            shutil.move(log, driver.ROOT / "proof-logs/configured-mounted-owner.log")
        runtime.rmdir()


def run(driver, image, wipe_only=False, refusals=False):
    """Requires real native startup and a closed failure before SDK presentation."""
    driver.require((image / "share/configured_sdk_proof.py").read_bytes()
                   == (driver.SOURCE / "tests/terrane/configured_sdk_proof.py").read_bytes(),
                   "native SDK launcher differs from bound source")
    subprocess.run([sys.executable, str(image / "share/configured_sdk_proof.py"),
                    "verify", str(image), str(driver.SOURCE)], check=True, timeout=30)
    parent = driver.ROOT / "configured-sdk"
    parent.mkdir(mode=0o700)
    os.chown(parent, 840, 840)

    large = manifest_payload()
    driver.require(not (wipe_only and refusals), "native SDK proof scopes overlap")
    if wipe_only:
        cases = [("wipe-default", True, "never", PAYLOAD)]
    elif refusals:
        # Keep real populated native backing before testing failed startup. Each
        # refusal compares unchanged original policy and publication afterward.
        cases = [("inline", False, "never", PAYLOAD),
                 ("profile", True, "never", PAYLOAD),
                 ("refused", True, "never", PAYLOAD)]
    else:
        cases = [("masked", True, "never", PAYLOAD),
                 ("inline", False, "never", PAYLOAD),
                 ("never", False, "never", large),
                 ("always", False, "always", large)]
    for name, refused, mode, payload in cases:
        root = parent / name
        setup = ("setup-default-wipe" if name == "wipe-default" else
                 "setup-manifest-public" if payload == large else "setup-public")
        actor(driver, image, name + "-setup",
              ["configured-sdk-cache-example", setup, root, 840])
        config = root / "config.toml"
        host = host_configuration(driver, name == "refused", mode)
        if name == "profile":
            host = host.replace("07" * 32, "08" * 32)
        config.write_text(config.read_text() + host)
        before = cache_states(driver)
        before_content = native_content_inodes(driver) if name == "wipe-default" else None
        stdout, stderr = actor(driver, image, name + "-cli",
              ["configured-sdk-cache-cli", "--config", config, "--role", "serve"],
              success=not refused, mount_policy="masked" if name == "masked" else "readonly",
              maintained=not refused)
        after = cache_states(driver)
        actor(driver, image, name + "-publication",
              ["configured-sdk-cache-example", "verify-reopen-publication", root, 840])
        if refused:
            if name == "wipe-default":
                driver.require(not stdout and stderr ==
                               b"terrane: configured SDK exposure preparation failed\n",
                               "private default wipe did not refuse presentation")
                driver.require(native_content_inodes(driver) == before_content,
                               "private default wipe caused persistent content admission")
            if name == "profile":
                driver.require(not stdout and stderr ==
                               b"terrane: configured SDK native cache profile differs from original repository\n",
                               "profile mismatch did not fail at the original/native binding")
            driver.require(after == before
                           and all(not (root / ("snapshot-" + item)).exists()
                                   for item in ["first", "second"]),
                           "unavailable native custody started presentation or changed policy")
            if name == "masked":
                driver.require(not stdout and stderr ==
                               b"terrane: configured SDK native cache recovery failed\n",
                               "masked roots did not refuse actual native startup")
                print("PASS actual inaccessible namespace roots refuse native startup before cache or snapshot effects", flush=True)
                continue
            if name == "wipe-default":
                print("PASS actual signed private zero-wipe default refuses sealed admission before content or snapshot effects", flush=True)
                continue
            witness = ("mismatched original profile" if name == "profile" else "an unenrolled native cache")
            print("PASS actual configured SDK refuses " + witness + " before any snapshot or policy effect", flush=True)
            continue

        root.with_suffix(".stdout").write_bytes(stdout)
        root.with_suffix(".stderr").write_bytes(stderr)
        actor(driver, image, name + "-verify",
              ["configured-sdk-cache-example", "verify-cli", root, 840])
        for directory, encoded in after.items():
            state = tomllib.loads(encoded.decode())
            old = tomllib.loads(before[directory].decode()) if before[directory] else {"reservations": [], "leases": [], "pins": []}
            verify_funding(driver, directory, old, state)
        for item in ["first", "second"]:
            path = root / ("snapshot-" + item) / "file"
            driver.require(path.read_bytes() == payload and path.stat().st_uid == 840,
                           "native SDK snapshot differs from independent original payload")
        # Persistent-cache controls use a genuine signed public repository.
        # Private lifetime is independently checked through actual final release.
        domain = tomllib.loads(config.read_text())["local_repository"]["domain"]
        driver.require(domain == "public", "cache retention control lacks a signed public root")
        sealed = driver.ROOT / "positive/public/sealed"
        candidates = [path for path in sealed.rglob("*")
                      if path.is_file() and path.stat().st_size == len(payload)
                      and path.read_bytes() == payload]
        if name == "never":
            driver.require(not candidates, "never-mode manifest unexpectedly assembled a whole object")
            print("PASS actual configured SDK never policy reads a native multi-chunk object without whole-object sealing", flush=True)
        else:
            driver.require(len(candidates) == 1, "native SDK did not read a genuine whole sealed object")
            metadata = candidates[0].stat()
            driver.require(metadata.st_uid == metadata.st_gid == 841
                           and metadata.st_nlink == 1 and metadata.st_mode & 0o7777 == 0o400,
                           "native SDK sealed object has different original custody")
            measurement = bytearray(68)
            struct.pack_into("=HH", measurement, 0, 0, 64)
            with candidates[0].open("rb") as file:
                fcntl.ioctl(file, 0xc0046686, measurement, True)
            algorithm, digest_size = struct.unpack_from("=HH", measurement)
            driver.require(algorithm == 1 and digest_size == 32,
                           "native SDK whole object lacks actual SHA-256 fs-verity")
            print("PASS actual configured SDK " + mode + " policy reads genuine fs-verity object and completes cache handoff", flush=True)
        offline, _ = actor(driver, image, name + "-offline",
                           ["configured-sdk-cache-example", "read-cache-offline", root, 840],
                           mount_policy="readonly")
        for witness in [
                b"PASS: actual native driver bounds an indefinitely pending lower read",
                b"PASS: actual shared native circuit blocks lower misses while resident content remains readable",
                b"PASS: actual native circuit permits one bounded scheduled lower probe and reopens on failure",
                b"PASS: actual confined SDK reads recovered native residents while original lower chunks are unavailable"]:
            driver.require(offline.splitlines().count(witness) == 1,
                           "native SDK actor omitted or repeated a lower failure control")
        print("PASS actual configured CLI recovers both native cache owners and materializes signed original-authority SDK snapshots", flush=True)


if __name__ == "__main__":
    if len(sys.argv) >= 7 and sys.argv[1] == "--mount-namespace":
        mount_namespace(sys.argv[2], sys.argv[3], json.loads(sys.argv[4]), sys.argv[5:])
    elif len(sys.argv) >= 6 and sys.argv[1] == "--verify-namespace":
        verify_namespace(sys.argv[2], json.loads(sys.argv[3]), sys.argv[4:])
    elif len(sys.argv) == 5 and sys.argv[1] == "--configured-worker-launcher":
        configured_worker_launcher(sys.argv[2], json.loads(sys.argv[3]), json.loads(sys.argv[4]))
    elif len(sys.argv) == 5 and sys.argv[1] == "--maintenance-gc-actor":
        maintenance_gc_actor(sys.argv[2], sys.argv[3], json.loads(sys.argv[4]))
    else:
        raise SystemExit("expected a privileged mount fixture or unprivileged namespace verifier")
