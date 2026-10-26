"""Checks original native owners and rendered Terrane units under guest PID 1.

The actor launcher retains the actual Cargo CLI bytes and checks the service
manager's real identity before exec. The supervisor uses the existing enrolled
partitions and original guest deadline. It neither replaces listener names nor
claims restart recovery or physical release from zero draining counts.
"""

import hashlib
import json
import os
import pathlib
import runpy
import stat
import subprocess
import sys
import time
import tomllib


ROOT = pathlib.Path("/var/lib/terrane-enrollment-proof/data")
CONFIG = pathlib.Path("/etc/terrane/terrane.toml")
ROLES = {"serve": (840, {844, 845}), "publish": (841, {845}), "gc": (843, {846})}


def require(condition, message):
    """Rejects missing evidence before invoking another managed operation."""
    if not condition:
        raise RuntimeError(message)


def verify_serve_mounts():
    """Checks the real role's read-only namespace and writable allocation binds."""
    configuration = tomllib.loads(CONFIG.read_text())
    observations = []
    for domain, settings in configuration["host_tier"]["domains"].items():
        root = pathlib.Path(settings["path"])
        for label in [".", "chunks", "objects", "quarantine", "state/cache",
                      "sealed", "staging", "pending-delete", "state/publication"]:
            readonly = bool(os.statvfs(root / label).f_flag & os.ST_RDONLY)
            expected = label not in {"chunks", "objects", "quarantine", "state/cache"}
            require(readonly == expected, "managed Serve allocation mount policy differs")
            observations.append({"domain": domain, "directory": label, "readonly": readonly})

    print("TERRANE_MANAGED_MOUNT_POLICY " + json.dumps(observations, sort_keys=True),
          file=sys.stderr, flush=True)


def check_publisher_mount_policy(proof, domains):
    """Requires complete ordered mount and namespace-denial observations."""
    labels = [".", "chunks", "objects", "quarantine", "state/cache",
              "sealed", "staging", "pending-delete", "state/publication"]
    expected = [{"domain": domain, "directory": label,
                 "readonly": label == "state/cache"}
                for domain in domains for label in labels]
    rows = proof["mounts"]
    require([{key: value for key, value in row.items() if key != "mount_id"}
             for row in rows] == expected, "managed publisher mount policy differs")
    require(all(type(row["mount_id"]) is int and row["mount_id"] > 0 for row in rows),
            "managed publisher mount identity is invalid")
    for domain in domains:
        require(len({row["mount_id"] for row in rows
                     if row["domain"] == domain and not row["readonly"]}) == 1,
                "managed publication directories cross mount boundaries")
    require(proof["protected_roots"] == [
        {"domain": domain, "directory": label, "write_denied": True}
        for domain in domains for label in [".", "state"]],
        "managed publisher namespace write denials are incomplete")
    require(proof["private_state_denied"] is True,
            "managed publisher can read private cache state")


def check_gc_ordering(records, active_enter, boot_id, runs):
    """Requires complete same-boot PID 1 start/finish pairs after Serve readiness."""
    require(type(active_enter) is int and active_enter > 0
            and type(runs) is int and runs > 0, "invalid managed readiness observation")
    require(isinstance(boot_id, str) and len(boot_id) == 32
            and all(character in "0123456789abcdef" for character in boot_id),
            "invalid managed boot identity")
    messages = ["Starting Terrane gc role...", "Finished Terrane gc role."]
    events = []
    for row in records:
        if (row.get("_PID") != "1" or row.get("UNIT") != "terrane-gc.service"
                or row.get("MESSAGE") not in messages):
            continue
        timestamp = row.get("__MONOTONIC_TIMESTAMP")
        require(row.get("_BOOT_ID") == boot_id and isinstance(timestamp, str)
                and timestamp.isdecimal() and int(timestamp) > 0,
                "managed GC journal lacks trusted same-boot timing")
        events.append({key: row[key] for key in
                       ["_PID", "UNIT", "MESSAGE", "_BOOT_ID", "__MONOTONIC_TIMESTAMP"]})

    require([row["MESSAGE"] for row in events] == messages * runs,
            "managed GC manager start/finish records are incomplete")
    previous = active_enter
    for row in events:
        timestamp = int(row["__MONOTONIC_TIMESTAMP"])
        require(timestamp >= previous, "managed GC ran before serving readiness or out of order")
        previous = timestamp
    return events


def gc_journal(driver, serve, runs):
    """Reads trusted manager timing retained after a one-shot completes."""
    boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    output = command(driver, ["journalctl", "--boot=0", "--no-pager", "--output=json",
                              "--unit=terrane-gc.service"])
    records = [json.loads(line) for line in output.splitlines()]
    return check_gc_ordering(records, int(serve["ActiveEnterTimestampMonotonic"]), boot_id, runs)


def verify_publisher_mounts():
    """Observes one actual publication mount while requiring protected parents."""
    domains = tomllib.loads(CONFIG.read_text())["host_tier"]["domains"]
    observations, protected = [], []
    for domain, settings in domains.items():
        root = pathlib.Path(settings["path"])
        for label in [".", "chunks", "objects", "quarantine", "state/cache",
                      "sealed", "staging", "pending-delete", "state/publication"]:
            descriptor = os.open(root / label, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = dict(line.split(":", 1) for line in
                            pathlib.Path(f"/proc/self/fdinfo/{descriptor}").read_text().splitlines())
                observations.append({"domain": domain, "directory": label,
                    "readonly": bool(os.statvfs(root / label).f_flag & os.ST_RDONLY),
                    "mount_id": int(info["mnt_id"])})
            finally:
                os.close(descriptor)
        for label in [".", "state"]:
            parent = root / label
            metadata = parent.stat()
            require(metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) & 0o022 == 0,
                    "managed publication namespace parent is writable by another identity")
            probe = parent / f".managed-publisher-denied-{os.getpid()}"
            try:
                descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except PermissionError:
                protected.append({"domain": domain, "directory": label, "write_denied": True})
            else:
                os.close(descriptor)
                probe.unlink()
                raise RuntimeError("managed publisher can modify a namespace parent")
        try:
            descriptor = os.open(root / "state/cache", os.O_RDONLY | os.O_DIRECTORY)
        except PermissionError:
            pass
        else:
            os.close(descriptor)
            raise RuntimeError("managed publisher can read private cache state")

    proof = {"mounts": observations, "protected_roots": protected, "private_state_denied": True}
    check_publisher_mount_policy(proof, domains)
    print("TERRANE_MANAGED_PUBLISHER_MOUNT_POLICY " + json.dumps(proof, sort_keys=True),
          file=sys.stderr, flush=True)


def actor(image, arguments):
    """Executes the original CLI after observing actual manager-applied custody."""
    require(len(arguments) == 4 and arguments[:3] == ["--config", str(CONFIG), "--role"]
            and arguments[3] in ROLES, "invalid managed actor arguments")
    role = arguments[3]
    uid, required_groups = ROLES[role]
    status = dict(line.split(":", 1) for line in pathlib.Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    require(status["Uid"].split() == [str(uid)] * 4
            and status["Gid"].split() == [str(uid)] * 4, "managed actor credentials differ")
    # initgroups may retain the primary GID in its supplementary list. It adds
    # no authority; every other supplementary group must be explicitly funded.
    groups = set(os.getgroups())
    require(required_groups <= groups <= required_groups | {uid}, "managed actor groups differ")
    require(status["NoNewPrivs"].strip() == "1" and all(
        int(status[name], 16) == 0 for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]),
        "managed actor retains capabilities or lacks NNP")
    require(pathlib.Path("/proc/self/uid_map").read_text().split() == ["0", "0", "4294967295"],
            "managed actor has a private user namespace")
    if role == "serve":
        verify_serve_mounts()
    if role == "publish":
        verify_publisher_mounts()
    if role == "gc":
        for domain in ["public", "private"]:
            try:
                with (ROOT / "positive" / domain / "state/cache/records.toml").open("rb"):
                    pass
            except PermissionError:
                continue
            raise RuntimeError("managed GC can read private owner state")

    identity = json.loads((image / "share/identity.json").read_text())
    executable = image / "libexec/cli"
    artifact = identity["artifacts"]["cli"]
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    require(digest == artifact["binary_sha256"], "managed CLI differs from retained Cargo bytes")
    print("TERRANE_MANAGED_ACTOR_IDENTITY " + json.dumps({
        "role": role, "pid": os.getpid(), "uid": uid, "gid": uid,
        "groups": sorted(groups), "capabilities": 0, "nnp": 1,
        "private_state_denied": role == "gc", "cli_sha256": digest,
    }, sort_keys=True), file=sys.stderr, flush=True)
    os.execve(executable, [str(executable), *arguments],
              dict(os.environ, LD_LIBRARY_PATH=artifact["runtime_library_path"]))


def command(driver, arguments):
    """Bounds every manager query by the unchanged whole-guest deadline."""
    remaining = min(30, driver.DEADLINE - time.monotonic())
    driver.require(remaining > 0, "managed maintenance whole-guest deadline")
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=remaining)
    driver.require(len(result.stdout) + len(result.stderr) <= driver.MAX_OUTPUT,
                   "managed maintenance command output bound")
    driver.require(result.returncode == 0,
                   "managed command failed: " + json.dumps({"argv": arguments,
                       "stdout": result.stdout, "stderr": result.stderr}))
    return result.stdout


def properties(driver, role, names):
    """Reads actual manager properties for the original named role unit."""
    output = command(driver, ["systemctl", "show", "terrane-" + role + ".service",
                             *["--property=" + name for name in names]])
    values = dict(line.split("=", 1) for line in output.splitlines())
    driver.require(set(values) == set(names), "managed unit properties are incomplete")
    return values


def configuration(driver, common, repository):
    """Matches generated trust inputs and complete funded native policy."""
    expected = json.loads(pathlib.Path(os.environ["TERRANE_MANAGED_EXPECTED"]).read_text())
    driver.require(expected["source"] == str(driver.SOURCE)
                   and CONFIG.read_text() == expected["configuration"],
                   "managed configuration differs from its evaluated source")
    actual = tomllib.loads(expected["configuration"])
    portable = tomllib.loads((repository / "config.toml").read_text())
    driver.require(actual["store"] == portable["store"]
                   and actual["local_repository"] == portable["local_repository"],
                   "managed configuration changed the original repository authority")
    driver.require(actual["tokens"] == portable["tokens"],
                   "managed configuration changed explicit public trust or startup Read")
    normalize = lambda rows: [{**row, "options": row.get("options", {})} for row in rows]
    # Only the independently declared destination moves. Authority, selected
    # views, capabilities and modes must still equal the original signed setup.
    relocated = [{**row, "at": str(ROOT / "managed-sdk" / f"snapshot-{row['id']}")}
                 for row in portable["expose"]]
    driver.require(normalize(actual["expose"]) == normalize(relocated),
                   "managed exposures differ from the original setup and fixed output relocation")
    host = tomllib.loads(common["host_configuration"](driver))["host_tier"]
    host["path"] = str(ROOT / "layout-admin")
    host["publisher"]["socket_path"] = "/run/terrane-publish/publisher.sock"
    for domain in host["domains"].values():
        domain["cache"]["surface_index"] = dict(max_entries=16, max_node_bytes=65536,
            max_index_bytes=65536, capacity_bytes=25165824, future_hold_bytes=327680)
    host["maintenance"] = dict(gc_uid=843, max_connections=2, max_requests=1,
        connection_timeout_ms=3000, request_timeout_ms=2000,
        sockets={"public": "/run/terrane-maintenance/public.sock",
                 "private:fixture": "/run/terrane-maintenance/private.sock"})
    driver.require(actual["host_tier"] == host, "managed native policy differs from enrolled fixture")
    return expected


def run(driver, image):
    """Starts GC through real dependencies, then checks original owner shutdown."""
    driver.require(pathlib.Path("/proc/1/comm").read_text().strip() == "systemd",
                   "managed proof requires the actual guest service manager")
    runpy.run_path(str(image / "share/configured_sdk_proof.py"))["verify"](image, driver.SOURCE)
    common = runpy.run_path(str(driver.IMAGE / "share/configured_sdk_cache_vm.py"))
    parent = ROOT / "configured-maintenance"
    parent.mkdir(mode=0o700)
    os.chown(parent, 840, 840)
    repository = parent / "repository"
    common["actor"](driver, image, "managed-setup",
                    ["configured-sdk-cache-example", "setup-public", repository, 840])
    output = ROOT / "managed-sdk"
    output.mkdir(mode=0o700)
    os.chown(output, 840, 840)
    expected = configuration(driver, common, repository)
    original_state = common["verify_owner_locks"](driver, False)
    sockets = [pathlib.Path("/run/terrane-maintenance") / name for name in ["public.sock", "private.sock"]]
    completed = False
    try:
        for role in ROLES:
            unit = properties(driver, role, ["FragmentPath", "ActiveState"])
            driver.require(unit["ActiveState"] != "active", "managed role started before enrollment")
            driver.require(pathlib.Path(unit["FragmentPath"]).read_text() == expected["units"]["terrane-" + role + ".service"],
                           "manager unit differs from the rendered module")
        command(driver, ["systemctl", "start", "terrane-publish.service"])
        deadline = min(driver.DEADLINE, time.monotonic() + 20)
        while not pathlib.Path("/run/terrane-publish/publisher.sock").exists():
            driver.require(time.monotonic() < deadline, "managed publisher listener deadline")
            time.sleep(0.02)

        command(driver, ["systemctl", "start", "terrane-gc.service"])
        serve = properties(driver, "serve", ["MainPID", "Type", "NotifyAccess", "ActiveState", "ActiveEnterTimestampMonotonic"])
        gc = properties(driver, "gc", ["ExecMainStatus", "Result", "ExecMainStartTimestampMonotonic"])
        driver.require(serve["Type"] == "notify" and serve["NotifyAccess"] == "main"
                       and serve["ActiveState"] == "active" and int(serve["MainPID"]) > 0,
                       "managed Serve did not become ready through main-process notification")
        driver.require(gc["ExecMainStatus"] == "0" and gc["Result"] == "success",
                       "managed GC did not complete successfully")
        # Completed one-shots can report a zero retained exec start property.
        # PID 1's same-boot journal must still prove the actual start ordering.
        original_gc_events = gc_journal(driver, serve, 1)
        common["verify_owner_locks"](driver, True, original_state)
        original_inodes = [(path.stat().st_dev, path.stat().st_ino) for path in sockets]
        for path in sockets:
            metadata = path.lstat()
            driver.require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == 840
                           and metadata.st_gid == 846 and stat.S_IMODE(metadata.st_mode) == 0o660,
                           "managed listener custody differs")
        common["maintenance_exchange"](driver, image, CONFIG, "managed-gc-foreign", success=False, foreign=True)
        command(driver, ["systemctl", "start", "terrane-gc.service"])
        driver.require(properties(driver, "gc", ["ExecMainStatus", "Result"]) == {"ExecMainStatus": "0", "Result": "success"},
                       "second managed GC failed")
        gc_events = gc_journal(driver, serve, 2)
        driver.require(gc_events[:2] == original_gc_events,
                       "managed GC replaced its original manager timing")
        common["verify_owner_locks"](driver, True, original_state)
        gc_log = command(driver, ["journalctl", "--no-pager", "--output=cat", "--unit=terrane-gc.service"])
        identities = [json.loads(line.removeprefix("TERRANE_MANAGED_ACTOR_IDENTITY ")) for line in gc_log.splitlines()
                      if line.startswith("TERRANE_MANAGED_ACTOR_IDENTITY ")]
        driver.require(len(identities) == 2 and len({row["pid"] for row in identities}) == 2
                       and all(row["role"] == "gc" and row["uid"] == 843 and row["private_state_denied"] for row in identities),
                       "managed GC did not retain two fresh denied-state identities")
        for domain in ["private:fixture", "public"]:
            driver.require(gc_log.splitlines().count(f"domain {domain}: checked 0, completed 0, blocked 0 draining exposures") == 2,
                           "managed GC responses differ from the original owners")
        serve_log = command(driver, ["journalctl", "--no-pager", "--output=cat", "--unit=terrane-serve.service",
                                     "_PID=" + serve["MainPID"]])
        publisher = properties(driver, "publish", ["MainPID", "ActiveState"])
        driver.require(publisher["ActiveState"] == "active" and int(publisher["MainPID"]) > 0,
                       "managed original publisher is no longer active")
        publisher_log = command(driver, ["journalctl", "--no-pager", "--output=cat",
            "--unit=terrane-publish.service", "_PID=" + publisher["MainPID"]])
        publisher_policy = [json.loads(line.removeprefix("TERRANE_MANAGED_PUBLISHER_MOUNT_POLICY "))
                            for line in publisher_log.splitlines()
                            if line.startswith("TERRANE_MANAGED_PUBLISHER_MOUNT_POLICY ")]
        driver.require(len(publisher_policy) == 1, "managed publisher mount evidence is missing or duplicated")
        check_publisher_mount_policy(publisher_policy[0], tomllib.loads(expected["configuration"])["host_tier"]["domains"])
        publisher_identity = [json.loads(line.removeprefix("TERRANE_MANAGED_ACTOR_IDENTITY "))
                              for line in publisher_log.splitlines()
                              if line.startswith("TERRANE_MANAGED_ACTOR_IDENTITY ")]
        driver.require(len(publisher_identity) == 1
                       and publisher_identity[0]["pid"] == int(publisher["MainPID"])
                       and publisher_identity[0]["role"] == "publish"
                       and publisher_identity[0]["uid"] == 841,
                       "managed mount policy did not belong to the original publisher")
        serve_identity = [json.loads(line.removeprefix("TERRANE_MANAGED_ACTOR_IDENTITY ")) for line in serve_log.splitlines()
                          if line.startswith("TERRANE_MANAGED_ACTOR_IDENTITY ")]
        driver.require(len(serve_identity) == 1 and serve_identity[0]["pid"] == int(serve["MainPID"])
                       and len([line for line in serve_log.splitlines() if line.startswith("completed SDK snapshot ")]) == 2,
                       "manager readiness did not belong to the original SDK process")
        mount_policy = [json.loads(line.removeprefix("TERRANE_MANAGED_MOUNT_POLICY "))
                        for line in serve_log.splitlines()
                        if line.startswith("TERRANE_MANAGED_MOUNT_POLICY ")]
        expected_mounts = [{"domain": domain, "directory": label,
                            "readonly": label not in {"chunks", "objects", "quarantine", "state/cache"}}
                           for domain in tomllib.loads(expected["configuration"])["host_tier"]["domains"]
                           for label in [".", "chunks", "objects", "quarantine", "state/cache",
                                         "sealed", "staging", "pending-delete", "state/publication"]]
        driver.require(mount_policy == [expected_mounts],
                       "managed Serve mount observations are missing, duplicated or differ from policy")
        # The journal merges stdout and stderr. Compare that combined stream
        # directly; do not manufacture separate process-stream receipts for the
        # standalone CLI verifier. Its independent guest retains that control.
        completion = [line for line in serve_log.splitlines()
                      if not line.startswith(("TERRANE_MANAGED_ACTOR_IDENTITY ",
                                              "TERRANE_MANAGED_MOUNT_POLICY "))]
        commit = (repository / "expected.commit").read_bytes()
        driver.require(len(commit) == 32, "managed original commit witness length differs")
        expected_completion = [f'completed SDK snapshot "{name}": commit {commit.hex()}, state Stopped, '
                               f'endpoint "{output}/snapshot-{name}"' for name in ["first", "second"]]
        driver.require(completion == expected_completion,
                       "managed CLI produced unexpected journal output")
        driver.require(original_inodes == [(path.stat().st_dev, path.stat().st_ino) for path in sockets],
                       "managed GC replaced an original listener inode")
        command(driver, ["systemctl", "stop", "terrane-serve.service"])
        driver.require(properties(driver, "serve", ["Result", "MainPID"]) == {"Result": "success", "MainPID": "0"},
                       "managed Serve did not acknowledge shutdown")
        common["verify_owner_locks"](driver, False, original_state)
        common["maintenance_exchange"](driver, image, CONFIG, "managed-gc-stopped", success=False)
        driver.require(all(not path.exists() and not path.is_symlink() for path in sockets),
                       "managed shutdown retained or replaced listener names")
        command(driver, ["systemctl", "stop", "terrane-publish.service"])
        common["actor"](driver, image, "managed-publication",
                        ["configured-sdk-cache-example", "verify-reopen-publication", repository, 840])
        for name in ["first", "second"]:
            driver.require((output / f"snapshot-{name}/file").read_bytes()
                           == b"independent configured SDK snapshot payload\n",
                           "managed shutdown changed an original durable SDK snapshot")
        print("TERRANE_MANAGED_SERVICE_PROOF " + json.dumps({
            "source": str(driver.SOURCE), "image": str(image), "serve": serve, "gc": gc,
            "gc_identities": identities, "serve_identity": serve_identity[0],
            "serve_mount_policy": mount_policy[0],
            "listener_inodes": original_inodes, "original_state_inodes": original_state,
            "listener_names_retired": True, "cli_combined_journal": completion,
            "units_sha256": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in expected["units"].items()},
            "systemd_pid1": True, "restart_recovery": False, "physical_release": False,
            "publisher_mount_policy": publisher_policy[0], "publisher_identity": publisher_identity[0],
            "gc_manager_journal": gc_events,
        }, sort_keys=True), flush=True)
        print("PASS actual systemd starts GC only after original Serve owners and listeners are ready; fresh confined roles preserve custody and acknowledge shutdown", flush=True)
        completed = True
    finally:
        if not completed:
            for role in ROLES:
                result = subprocess.run(["journalctl", "--no-pager", "--output=cat", "--unit=terrane-" + role + ".service"],
                                        capture_output=True, text=True, timeout=5)
                print("TERRANE_MANAGED_FAILURE_JOURNAL " + json.dumps({"role": role,
                    "stdout": result.stdout[:driver.MAX_OUTPUT], "stderr": result.stderr[:driver.MAX_OUTPUT]}), flush=True)
        command(driver, ["systemctl", "stop", "terrane-serve.service", "terrane-publish.service"])


if __name__ == "__main__":
    require(len(sys.argv) == 7 and sys.argv[1] == "actor", "requires managed actor arguments")
    actor(pathlib.Path(sys.argv[2]), sys.argv[3:])
