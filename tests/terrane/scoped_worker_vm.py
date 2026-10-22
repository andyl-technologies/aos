"""Qualifies scoped owner Send to an original distinct worker in a guest."""

import importlib.util
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


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
    image, source = map(Path, sys.argv[1:])
    if os.geteuid() != 0:
        raise RuntimeError("scoped supervisor requires explicit administration")
    support = load("scoped_native_support", image / "share/host_cache_vm.py")
    surface = load("scoped_surface_support", image / "share/surface_index_owner_vm.py")
    support.verify_image()
    surface.verify_surface(image, source)
    support.require(Path(__file__).read_bytes()
        == (source / "tests/terrane/scoped_worker_vm.py").read_bytes(),
        "installed scoped supervisor differs from immutable source")
    support.CASES = ["scoped-worker"]
    support.BUDGET = support.HARD
    support.administrative_preflight("before")
    support.scaffold()
    support.administrative_preflight("after")
    quota_config, publisher_config = support.configurations()
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
    environment = dict(os.environ,
        TERRANE_CACHE_ROOT=str(support.root("scoped-worker")),
        TERRANE_CACHE_DOMAIN=support.domain("scoped-worker"),
        TERRANE_CACHE_OWNER=support.owner("scoped-worker"),
        TERRANE_CACHE_PROJECT=str(support.project("scoped-worker")),
        TERRANE_CACHE_UUID=uuid, TERRANE_CACHE_BUDGET=str(support.BUDGET),
        TERRANE_CACHE_QUOTA_SOCKET=str(support.RUNTIME / "quota.sock"),
        TERRANE_CACHE_PUBLISHER_SOCKET=str(support.PUB_RUNTIME / "publisher.sock"),
        TERRANE_WORKER_SETPRIV=setpriv)

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
        try:
            # Only fixture launch runs administratively. The same process drops
            # every UID/GID/capability before native inspection and confinement.
            result = subprocess.run([executable, "worker-send"], env=environment,
                text=True, capture_output=True, timeout=30)
        except subprocess.TimeoutExpired as error:
            for stream in [error.stdout, error.stderr]:
                if stream:
                    print(stream.decode(errors="replace") if isinstance(stream, bytes)
                        else stream, end="", flush=True)
            raise
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", flush=True)
        support.require(result.returncode == 0 and result.stdout.splitlines() == [
            "PASS surface admission requires actual recovery and acknowledged Resume",
            "PASS original owner queue refuses Send ordered after Drain despite completed scoped Read",
            "PASS actual scoped owner Send grants original signed-root index and sealed file to the original worker; draining denies new grants while retained descriptors and mapping remain readable"],
            "actual scoped owner Send failed")
        support.verify_image()
        surface.verify_surface(image, source)
        print("PASS native scoped worker grant component; production broker, worker sandbox and FUSE remain unqualified", flush=True)
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
