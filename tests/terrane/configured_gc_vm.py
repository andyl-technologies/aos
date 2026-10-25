"""Exercises the actual confined collector in fresh, unprivileged ext4 actors."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time


def require(condition, message):
    """Fails the guest without substituting a decoded record for authority."""
    if not condition:
        raise RuntimeError(message)


def status(pid):
    """Observes the real running actor's kernel identity and confinement."""
    rows = dict(line.split(":", 1) for line in
                Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
    require(all(int(value) == 840 for name in ["Uid", "Gid"]
                for value in rows[name].split()), "collector actor identity changed")
    require(rows["NoNewPrivs"].strip() == "1" and rows["Seccomp"].strip() == "2",
            "collector boundary is not installed")
    require(all(int(rows[name].strip(), 16) == 0
                for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]),
            "collector actor retained capabilities")
    return {name: rows[name].strip() for name in
            ["Uid", "Gid", "NoNewPrivs", "Seccomp", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]}


def main():
    """Requires full native deletion, recurring cycles and acknowledged shutdown."""
    image, storage = map(Path, sys.argv[1:])
    require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 840
            and os.getgroups() == [], "driver requires dedicated unprivileged guest identity")
    root = storage / "repository"
    executable = image / "bin/configured-sdk-gc"
    subprocess.run([str(executable), "setup", str(root), "840"], check=True, timeout=60)
    for name in ["issuer.seed", "terminal.seed", "token.cbor"]:
        require(not (root / "authority" / name).exists(), "private authority survived setup")
    pack = (root / "expected.pack").read_bytes()
    require(len(pack) == 16, "invalid actual pack identity")
    prefix = root / "bucket/objects/pack" / pack.hex()[:2] / pack.hex()
    pair = [prefix.with_suffix(".pack"), prefix.with_suffix(".idx")]
    require(all(path.is_file() for path in pair), "actual native orphan pair missing")
    versions = [{"device": path.stat().st_dev, "inode": path.stat().st_ino,
                 "size": path.stat().st_size, "modified_ns": path.stat().st_mtime_ns}
                for path in pair]

    # Actual descriptor times and an external monotonic wait supply fixture age.
    # No creation journal, inode timestamp or clock implementation is rewritten.
    age_started = time.monotonic()
    time.sleep(62)
    require(time.monotonic() - age_started >= 62
            and all(time.time_ns() - row["modified_ns"] > 60_000_000_000 for row in versions),
            "actual native pack grace has not elapsed")

    stdout_path, stderr_path = storage / "collector.stdout", storage / "collector.stderr"
    started = time.monotonic()
    process = None
    try:
        with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
            process = subprocess.Popen([str(executable), "run", str(root), "840"],
                                       stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            ready = None
            deadline = started + 180
            last_observation = None
            while time.monotonic() < deadline:
                require(process.poll() is None, "collector exited before durable collection")
                if ready is None and "CONFIGURED_GC_READY\n" in stdout_path.read_text():
                    ready = time.monotonic()
                    actor_status = status(process.pid)
                if ready is not None and all(not path.exists() for path in pair):
                    cycles = list((root / "bucket/gc").glob("*/roots"))
                    if len(cycles) >= 2:
                        # Pair absence precedes durable Done. Wait for the actual
                        # protected acknowledgment before asking for shutdown.
                        observed = subprocess.run(
                            [str(executable), "observe", str(root), "840"],
                            capture_output=True, text=True, timeout=10)
                        last_observation = {"returncode": observed.returncode,
                                            "stdout": observed.stdout, "stderr": observed.stderr}
                        if observed.returncode == 0:
                            require(observed.stdout == "CONFIGURED_GC_OBSERVED_DONE\n",
                                    "unexpected native Done observation")
                            print(observed.stdout, end="", flush=True)
                            break
                time.sleep(0.1)
            else:
                diagnostics = {"native_pair_present": [path.exists() for path in pair],
                               "physical_cycles": sorted(path.parent.name for path in
                                                         (root / "bucket/gc").glob("*/roots")),
                               "last_observation": last_observation}
                raise RuntimeError("collector did not reclaim and start fresh cycles within its bound: "
                                   + json.dumps(diagnostics, sort_keys=True))
            reclaimed = time.monotonic()
            require(reclaimed - started >= 60, "physical deletion preceded a full external D")
            # SIGTERM exercises cancellation and executor joining in the actual
            # service. Exit success is required; forceful cleanup is never a pass.
            process.terminate()
            require(process.wait(timeout=30) == 0, "collector did not acknowledge shutdown")
            stopped = time.monotonic()
        subprocess.run([str(executable), "verify", str(root), "840"], check=True, timeout=60)
        identity = json.loads((image / "share/identity.json").read_text())
        artifact = identity["artifacts"]["gc"]
        print("CONFIGURED_GC_PROOF " + json.dumps({
            "source": identity["source"], "image": str(image),
            "actual_binary_sha256": artifact["binary_sha256"],
            "native_pair": versions, "actor_status": actor_status,
            "real_grace_seconds": time.monotonic() - age_started,
            "ready_seconds": ready - started,
            "reclaimed_seconds": reclaimed - started,
            "shutdown_seconds": stopped - reclaimed,
            "private_authority_absent": True,
        }, sort_keys=True), flush=True)
    except BaseException:
        for path in [stdout_path, stderr_path]:
            if path.exists():
                print(path.read_text(), file=sys.stderr, flush=True)
        raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
