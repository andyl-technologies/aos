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
        driver.require(gc["ExecMainStatus"] == "0" and gc["Result"] == "success"
                       and int(gc["ExecMainStartTimestampMonotonic"]) >= int(serve["ActiveEnterTimestampMonotonic"]) > 0,
                       "managed GC ran before serving readiness")
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
        serve_identity = [json.loads(line.removeprefix("TERRANE_MANAGED_ACTOR_IDENTITY ")) for line in serve_log.splitlines()
                          if line.startswith("TERRANE_MANAGED_ACTOR_IDENTITY ")]
        driver.require(len(serve_identity) == 1 and serve_identity[0]["pid"] == int(serve["MainPID"])
                       and len([line for line in serve_log.splitlines() if line.startswith("completed SDK snapshot ")]) == 2,
                       "manager readiness did not belong to the original SDK process")
        # The journal merges stdout and stderr. Compare that combined stream
        # directly; do not manufacture separate process-stream receipts for the
        # standalone CLI verifier. Its independent guest retains that control.
        completion = [line for line in serve_log.splitlines()
                      if not line.startswith("TERRANE_MANAGED_ACTOR_IDENTITY ")]
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
            "listener_inodes": original_inodes, "original_state_inodes": original_state,
            "listener_names_retired": True, "cli_combined_journal": completion,
            "units_sha256": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in expected["units"].items()},
            "systemd_pid1": True, "restart_recovery": False, "physical_release": False,
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
