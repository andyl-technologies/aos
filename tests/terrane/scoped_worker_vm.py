"""Qualifies scoped owner Send to an original distinct worker in a guest."""

import importlib.util
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import subprocess
import sys
import time


def crash_actor(support, executable, environment):
    """Kills the actual owner and original worker through retained incarnations."""
    support.require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
        "actual Linux pidfd process control unavailable")
    log_path = support.RUNTIME / "crash-owner.log"
    worker_pidfd = None
    actor = None
    try:
        with log_path.open("wb") as log:
            actor = subprocess.Popen([executable, "worker-crash"], env=environment,
                stdout=subprocess.PIPE, stderr=log)
            support.require(actor.stdout is not None, "actual owner output unavailable")
            deadline = time.monotonic() + 30
            data = b""
            while len(data.splitlines()) < 3 or not data.endswith(b"\n"):
                remaining = deadline - time.monotonic()
                support.require(remaining > 0 and actor.poll() is None,
                    "actual owner failed bounded crash readiness")
                ready, _, _ = select.select([actor.stdout], [], [], remaining)
                support.require(ready, "actual owner crash readiness timed out")
                chunk = os.read(actor.stdout.fileno(), 4096)
                support.require(chunk and len(data) + len(chunk) <= 4096,
                    "actual owner output exceeds bounded crash protocol")
                data += chunk
            lines = data.decode().splitlines()
            support.require(len(lines) == 3 and lines[0].startswith("WORKER_PID ")
                and lines[1:] == [
                    "PASS surface admission requires actual recovery and acknowledged Resume",
                    "PASS original worker holds retired index mapping before forced owner death"],
                "actual owner crash rendezvous differs from expected protocol")
            worker_pid = int(lines[0].removeprefix("WORKER_PID "))
            candidate = os.pidfd_open(worker_pid)
            try:
                status = dict(line.split(":", 1) for line in
                    Path(f"/proc/{worker_pid}/status").read_text().splitlines() if ":" in line)
                support.require(int(status["PPid"]) == actor.pid
                    and status["Uid"].split() == ["848"] * 4
                    and actor.poll() is None,
                    "worker pidfd does not belong to original distinct owner child")
            except BaseException:
                os.close(candidate)
                raise
            # Cleanup may signal only the independently checked incarnation.
            worker_pidfd = candidate
            support.require(not select.select([worker_pidfd], [], [], 0)[0],
                "original worker exited before owner SIGKILL")
            print(data.decode(), end="", flush=True)
            actor.kill()
            support.require(actor.wait(timeout=5) == -signal.SIGKILL,
                "owner did not die by actual SIGKILL")
            support.require(not select.select([worker_pidfd], [], [], 0)[0],
                "original worker mapping did not survive owner SIGKILL")

            refused = subprocess.run(support.role_command(840, [executable, "crash-refuse"]),
                env=environment, text=True, capture_output=True, timeout=15)
            print(refused.stdout, end="", flush=True)
            print(refused.stderr, end="", flush=True)
            support.require(refused.returncode == 0 and refused.stdout.splitlines() == [
                "PASS forced owner death preserves exact policy while original worker mapping survives"],
                "cold owner changed policy while original worker mapping survived")
            support.require(not select.select([worker_pidfd], [], [], 0)[0],
                "original worker exited during cold refusal")
            signal.pidfd_send_signal(worker_pidfd, signal.SIGKILL)
            support.require(select.select([worker_pidfd], [], [], 5)[0],
                "original worker pidfd did not observe actual process death")
            recovered = subprocess.run(support.role_command(840, [executable, "crash-recover"]),
                env=environment, text=True, capture_output=True, timeout=15)
            print(recovered.stdout, end="", flush=True)
            print(recovered.stderr, end="", flush=True)
            support.require(recovered.returncode == 0 and recovered.stdout.splitlines() == [
                "PASS actual worker death permits authenticated closure and funded recovery before Resume"],
                "actual worker death did not permit funded cold recovery")
            print("PASS forced owner SIGKILL and original worker pidfd death preserve physical custody through authenticated closure", flush=True)
    finally:
        if worker_pidfd is not None:
            try:
                if not select.select([worker_pidfd], [], [], 0)[0]:
                    signal.pidfd_send_signal(worker_pidfd, signal.SIGKILL)
                    select.select([worker_pidfd], [], [], 5)
            finally:
                os.close(worker_pidfd)
        if actor is not None:
            if actor.poll() is None:
                actor.kill()
                actor.wait(timeout=5)
            if actor.stdout is not None:
                actor.stdout.close()
        if sys.exc_info()[0] is not None and log_path.exists():
            print("actual crash owner log:", flush=True)
            print(log_path.read_text(), flush=True)


def pressure_actors(support, executable, environment_for, admission=False):
    """Calibrates a genuine project before exercising actual pressure elsewhere."""
    calibration = subprocess.run(support.role_command(840, [executable, "pressure-calibrate"]),
        env=environment_for("pressure-calibration"), text=True, capture_output=True, timeout=30)
    print(calibration.stdout, end="", flush=True)
    print(calibration.stderr, end="", flush=True)
    lines = calibration.stdout.splitlines()
    support.require(calibration.returncode == 0 and len(lines) == 2
        and lines[0] == "PASS surface admission requires actual recovery and acknowledged Resume",
        "actual pressure calibration failed")
    fields = lines[1].split()
    support.require(len(fields) == 3 and fields[0] == "CALIBRATION",
        "actual pressure measurements unavailable")
    snapshot, allocation = map(int, fields[1:])
    support.require(0 <= snapshot <= support.HARD and 0 < allocation <= support.HARD,
        "actual pressure measurements exceed the genuine project budget")
    for case in (["host-admission"] if admission else ["pressure", "global-pressure"]):
        environment = dict(environment_for(case),
            TERRANE_PRESSURE_SNAPSHOT=str(snapshot), TERRANE_PRESSURE_ALLOCATION=str(allocation))
        try:
            result = subprocess.run(support.role_command(840, [executable, case]),
                env=environment, text=True, capture_output=True, timeout=60)
        except subprocess.TimeoutExpired as error:
            for stream in [error.stdout, error.stderr]:
                if stream:
                    print(stream.decode(errors="replace") if isinstance(stream, bytes)
                        else stream, end="", flush=True)
            raise
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", flush=True)
        expected = ["PASS surface admission requires actual recovery and acknowledged Resume"]
        if admission:
            expected.extend([
                "PASS verified index admission requests bounded host eviction before funding; retained receipts and real grace refuse without mutation while the original mapped victim remains fully charged",
                "PASS automatic host-pressure index admission preserves unrelated exposure and funding; actual final unmap releases exactly the original victim allocation"])
        elif case == "global-pressure":
            expected.extend([
                "PASS shared host FIFO selects the original derived index after real release grace while preserving active exposure and exact mapped charge",
                "PASS shared host retirement releases only the original index future hold; actual final unmap precedes bounded index-cap retry with durable custody unchanged"])
        else:
            expected.extend([
                "PASS automatic index pressure preserves retained receipts and release grace; active exposure survives while original unlinked mapping prevents capacity credit",
                "PASS actual final unmap releases exact original index charge before bounded pressure retry admits a new canonical index with unrelated durable custody unchanged"])
        support.require(result.returncode == 0 and result.stdout.splitlines() == expected,
            "actual automatic index-pressure control failed: " + case)


def load(name, path):
    """Loads an already verified installed supervisor without running its main."""
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError("native supervisor unavailable: " + name)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def main():
    """Runs real administrative helpers and a capability-free scoped owner."""
    if len(sys.argv) not in [3, 4] or (len(sys.argv) == 4
            and sys.argv[3] not in ["--crash", "--pressure", "--admission", "--maintenance", "--maintenance-listener", "--worker-network"]):
        raise RuntimeError("expected image, source and optional --crash, --pressure, --admission, --maintenance, --maintenance-listener or --worker-network")
    image, source = map(Path, sys.argv[1:3])
    network = len(sys.argv) == 4 and sys.argv[3] == "--worker-network"
    crash = len(sys.argv) == 4 and sys.argv[3] == "--crash"
    pressure = len(sys.argv) == 4 and sys.argv[3] == "--pressure"
    admission = len(sys.argv) == 4 and sys.argv[3] == "--admission"
    listener = len(sys.argv) == 4 and sys.argv[3] == "--maintenance-listener"
    maintenance = listener or (len(sys.argv) == 4 and sys.argv[3] == "--maintenance")
    case = ("worker-network" if network else "gc-maintenance-listener" if listener else "gc-maintenance" if maintenance else "host-admission" if admission
        else "pressure" if pressure else "worker-crash" if crash else "scoped-worker")
    if os.geteuid() != 0:
        raise RuntimeError("scoped supervisor requires explicit administration")
    support = load("scoped_native_support", image / "share/host_cache_vm.py")
    surface = load("scoped_surface_support", image / "share/surface_index_owner_vm.py")
    support.verify_image()
    surface.verify_surface(image, source)
    support.require(Path(__file__).read_bytes()
        == (source / "tests/terrane/scoped_worker_vm.py").read_bytes(),
        "installed scoped supervisor differs from immutable source")
    support.CASES = (["pressure-calibration", "host-admission"] if admission
        else ["pressure-calibration", "pressure", "global-pressure"] if pressure else [case])
    support.BUDGET = support.HARD * len(support.CASES)
    support.administrative_preflight("before")
    support.scaffold()
    if network:
        fuse = Path("/dev/fuse")
        if not fuse.exists():
            os.mknod(fuse, 0o20600, os.makedev(10, 229))
        device = fuse.stat()
        support.require(stat.S_ISCHR(device.st_mode)
            and device.st_rdev == os.makedev(10, 229),
            "original FUSE character device unavailable")
    maintenance_socket = support.RUNTIME / "maintenance" / "owner.sock"
    if listener:
        maintenance_socket.parent.mkdir()
        support.metadata(maintenance_socket.parent, 840, 843, 0o2750)
    support.administrative_preflight("after")
    quota_config, publisher_config = support.configurations()
    if crash or maintenance:
        # Cold physical closure uses the same explicitly configured native
        # census as the owning surface proof. A peer cannot enable traversal.
        quota_config.write_text(
            "project_census = { retained_inodes = 512, directory_entries = 4096, depth = 16 }\n"
            + quota_config.read_text())
    helper = image / "bin/aos-terrane-host"
    support.run(support.admin_command(support.PROVISION_CAPS,
        [helper, "provision", "--config", quota_config,
         "--ledger", support.ADMIN / "ledger.toml"]),
        preexec_fn=support.native_descriptor_budget)
    uuid = subprocess.check_output(["blkid", "-s", "UUID", "-o", "value",
        os.environ["TERRANE_CACHE_VM_IMAGE"]], text=True, timeout=5).strip().replace("-", "")
    support.require(len(uuid) == 32, "actual scoped project UUID unavailable")
    setpriv = shutil.which("setpriv")
    support.require(setpriv is not None, "AOS-built setpriv unavailable")
    def environment_for(selected):
        """Names one actually provisioned project without supplying authority."""
        return dict(os.environ,
            TERRANE_CACHE_ROOT=str(support.root(selected)),
            TERRANE_CACHE_DOMAIN=support.domain(selected),
            TERRANE_CACHE_OWNER=support.owner(selected),
            TERRANE_CACHE_PROJECT=str(support.project(selected)),
            TERRANE_CACHE_UUID=uuid, TERRANE_CACHE_BUDGET=str(support.BUDGET),
            TERRANE_CACHE_QUOTA_SOCKET=str(support.RUNTIME / "quota.sock"),
            TERRANE_CACHE_PUBLISHER_SOCKET=str(support.PUB_RUNTIME / "publisher.sock"),
            TERRANE_WORKER_SETPRIV=setpriv,
            TERRANE_MAINTENANCE_SOCKET=str(maintenance_socket))

    environment = environment_for(case)

    children, logs = [], []
    try:
        for name in ["scoped-helper", "scoped-publisher"]:
            logs.append((support.RUNTIME / (name + ".log")).open("wb"))
        query = subprocess.Popen(support.admin_command(support.QUERY_CAPS,
            [helper, "serve", "--config", quota_config,
             "--ledger", support.ADMIN / "ledger.toml"]),
            stdout=logs[0], stderr=subprocess.STDOUT,
            preexec_fn=support.native_descriptor_budget)
        children.append(query)
        publisher = subprocess.Popen(support.role_command(841,
            [image / "bin/terrane", "--config", publisher_config, "--role", "publish"]),
            stdout=logs[1], stderr=subprocess.STDOUT,
            preexec_fn=support.native_descriptor_budget)
        children.append(publisher)
        executable = image / "bin/surface-index-owner-fixture"
        deadline = time.monotonic() + 15
        while True:
            prepared = subprocess.run(support.role_command(840, [executable, "prepare"]),
                env=environment, text=True, capture_output=True, timeout=12)
            if prepared.returncode == 0:
                break
            support.require(query.poll() is None and publisher.poll() is None
                and time.monotonic() < deadline,
                "actual scoped helper or publisher failed readiness: " + prepared.stderr)
            time.sleep(0.02)
        if pressure or admission:
            pressure_actors(support, executable, environment_for, admission)
            support.verify_image()
            surface.verify_surface(image, source)
            print("PASS native automatic host-admission pressure component; production broker, worker sandbox and FUSE remain unqualified" if admission else
                "PASS native automatic index pressure component; production broker, worker sandbox and FUSE remain unqualified", flush=True)
            return
        if crash:
            crash_actor(support, executable, environment)
            support.verify_image()
            surface.verify_surface(image, source)
            print("PASS native forced owner crash component; production broker, worker sandbox and FUSE remain unqualified", flush=True)
            return
        if maintenance:
            try:
                result = subprocess.run([executable, "maintenance-listener" if listener else "maintenance"], env=environment,
                    text=True, capture_output=True, timeout=30)
            except subprocess.TimeoutExpired as error:
                for stream in [error.stdout, error.stderr]:
                    if stream:
                        print(stream.decode(errors="replace") if isinstance(stream, bytes)
                            else stream, end="", flush=True)
                raise
            print(result.stdout, end="", flush=True)
            print(result.stderr, end="", flush=True)
            expected = [
                "PASS surface admission requires actual recovery and acknowledged Resume",
                "PASS draining index retirement closes owner descriptors; actual retained mapping prevents exposure release until final unmap and authenticated closure",
                "PASS original-owner batch reconciliation skips active exposure, preserves blocked custody and closes a later draining mapping only after final unmap",
                "PASS distinct capability-free GC requests original-owner closure without opening private cache state; retained mappings and unrelated obligations survive until authenticated final unmap"]
            if listener:
                expected.insert(1, "PASS bounded maintenance runtime expires actual idle GC connection without changing owner policy")
                expected.insert(2, "PASS bounded GC client times out against actual unserved connection without changing owner policy")
                expected.append("PASS protected GC listener preserves its original mode-0660 inode and refuses unsafe ancestors, existing names and wrong-role connections")
                expected.append("PASS bounded maintenance runtime serves actual original-owner reconciliation and shuts down without replacing its protected listener")
                expected.append("PASS bounded GC client receives actual original-owner closure reports through kernel readiness")
            support.require(result.returncode == 0 and result.stdout.splitlines() == expected,
                "actual distinct-role GC maintenance failed")
            support.verify_image()
            surface.verify_surface(image, source)
            print("PASS native GC maintenance listener component; deployed role startup and production worker remain unqualified" if listener else
                "PASS native GC maintenance channel component; deployed role listeners and production worker remain unqualified", flush=True)
            return
        try:
            # Only fixture launch runs administratively. The same process drops
            # every UID/GID/capability before native inspection and confinement.
            result = subprocess.run([executable, "worker-network" if network else "worker-send"], env=environment,
                text=True, capture_output=True, timeout=30)
        except subprocess.TimeoutExpired as error:
            for stream in [error.stdout, error.stderr]:
                if stream:
                    print(stream.decode(errors="replace") if isinstance(stream, bytes)
                        else stream, end="", flush=True)
            raise
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", flush=True)
        expected = [
            "PASS surface admission requires actual recovery and acknowledged Resume",
            "PASS bounded worker receipt times out and cancels abandoned handoffs without changing original exposure policy or retaining live socket aliases",
            "PASS original owner queue refuses Send ordered after Drain despite completed scoped Read",
            "PASS actual scoped owner Send grants original signed-root index and sealed file to the original worker; draining denies new grants while retained descriptors and mapping remain readable"]
        if network:
            expected.append("PASS original worker retains checked FUSE descriptor and kernel-enforced Unix-only network boundary through actual scoped grants and draining")
        support.require(result.returncode == 0 and result.stdout.splitlines() == expected,
            "actual scoped owner Send failed")
        support.verify_image()
        surface.verify_surface(image, source)
        print("PASS native worker network boundary component; full worker sandbox, broker and mounted FUSE remain unqualified" if network else
            "PASS native scoped worker grant component; production broker, worker sandbox and FUSE remain unqualified", flush=True)
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.send_signal(signal.SIGCONT)
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        for log in logs:
            log.close()
        if sys.exc_info()[0] is not None:
            for name in ["scoped-helper", "scoped-publisher"]:
                path = support.RUNTIME / (name + ".log")
                if path.exists():
                    print(name + " actual process log:", flush=True)
                    print(path.read_text(), flush=True)


if __name__ == "__main__":
    main()
