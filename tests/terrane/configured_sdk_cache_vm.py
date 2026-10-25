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
import struct
import subprocess
import sys
import tempfile
import time
import tomllib


PAYLOAD = b"independent configured SDK snapshot payload\n"
NAMESPACE_OBSERVATION = b"NATIVE_SDK_NAMESPACE "
PUBLISHER_PRIVATE_ROOTS = ["sealed", "staging", "pending-delete", "state/publication"]


def namespace_actor(driver, image, arguments, policy, stack, launcher=False):
    """Keeps the publisher outside a fresh client's private mount namespace."""
    credentials = ["setpriv", "--reuid", "840", "--regid", "840", "--groups", "844,845",
                   "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                   "--no-new-privs"]
    executable = [str(image / "bin" / arguments[0]), *map(str, arguments[1:])]
    if launcher:
        driver.require(policy == "readonly" and arguments[:2] == [
            "surface-index-owner-fixture", "configured-worker"],
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
    if os.geteuid() != 0 or policy not in {"readonly", "masked"}:
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
    if os.geteuid() != 840 or policy not in {"readonly", "masked"}:
        raise RuntimeError("invalid unprivileged namespace fixture")
    for path, device, inode in bindings:
        descriptor = os.open(path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            same = (metadata.st_dev, metadata.st_ino) == (device, inode)
            if same != (policy == "readonly"):
                raise RuntimeError("namespace inode policy differs from original roots")
            if not os.fstatvfs(descriptor).f_flag & os.ST_RDONLY:
                raise RuntimeError("publisher-private root is writable in client namespace")
        finally:
            os.close(descriptor)
        try:
            readable = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as error:
            if error.errno != errno.EACCES:
                raise
        else:
            os.close(readable)
            raise RuntimeError("unprivileged client can read a publisher-private directory")
    print(NAMESPACE_OBSERVATION.decode() + json.dumps({
        "policy": policy, "roots": len(bindings), "read_denied": True,
        "readonly": True, "original_inodes": policy == "readonly",
    }, sort_keys=True), flush=True)
    os.execv(command[0], command)


def configured_worker_launcher(policy, bindings, command):
    """Starts the actual child before Rust irrevocably enters UID 840 custody."""
    if (os.geteuid() != 0 or policy != "readonly" or len(command) != 3
            or pathlib.Path(command[0]).name != "surface-index-owner-fixture"
            or command[1] != "configured-worker"):
        raise RuntimeError("invalid configured worker fixture launcher")
    # Observe the very same namespace as the actual unprivileged actor. The
    # short verifier opens no readable publisher-private aliases for its parent.
    subprocess.run(["setpriv", "--reuid", "840", "--regid", "840", "--groups", "844,845",
                    "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                    "--no-new-privs", sys.executable, __file__, "--verify-namespace",
                    policy, json.dumps(bindings), sys.executable, "-c", "pass"],
                   check=True, timeout=5)
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
          launcher=False):
    """Runs one fresh source-bound actor under the original supervisor's bounds."""
    with contextlib.ExitStack() as stack:
        command = namespace_actor(driver, image, arguments, mount_policy, stack, launcher)
        return run_actor(driver, label, command, success, mount_policy, maintained)


def run_actor(driver, label, command, success, mount_policy, maintained):
    """Collects bounded actor output and retains every namespace observation."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
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


def run_surface(driver, image, surface_image, service_only=False):
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

    modes = ["service"] if service_only else ["disabled", "bound", "admit", "recover-draining", "service"]
    for mode in modes:
        text = original + host_configuration(driver,
            mode="always" if mode in {"admit", "service"} else "never")
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
    if service_only:
        print("PASS native configured retained worker service component; deployed FUSE and task acceptance remain unqualified", flush=True)
    else:
        print("PASS native configured surface-index policy component; deployed FUSE and task acceptance remain unqualified", flush=True)


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
    else:
        raise SystemExit("expected a privileged mount fixture or unprivileged namespace verifier")
