"""Runs one bounded Nix command through a private AOS builder microVM."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from proxy import connect_vsock


def verify_probe(work, receipt):
    """Binds the returned sandbox proof to the actual live VM and source."""
    outputs = (work / "command.stdout").read_text().splitlines()
    if not outputs or any(not re.fullmatch(r"/nix/store/[a-z0-9]+-[^/]+", path) for path in outputs):
        raise RuntimeError("build did not return ordinary store outputs")
    probes = [path for path in outputs if re.fullmatch(
        r"/nix/store/[a-z0-9]+-terrane-native-builder-probe", path
    )]
    if len(probes) != 1:
        raise RuntimeError("probe did not return one expected output")
    output = Path(probes[0])
    source = b"terrane-native-builder-probe-v1\n"
    if (output / "source").read_bytes() != source:
        raise RuntimeError("probe output has another source identity")
    rows = (output / "proof").read_text().splitlines()
    proof = dict(row.split("=", 1) for row in rows)
    if len(proof) != len(rows) or set(proof) != {
        "uid", "guest_uid", "capabilities", "kernel", "boot_id", "build_filesystem",
        "temporary_filesystem", "output_filesystem", "source_sha256",
        "nonce",
    }:
        raise RuntimeError("probe proof has missing, duplicate or unknown fields")
    if proof["uid"] != "1000" or not 30001 <= int(proof["guest_uid"]) <= 30016:
        raise RuntimeError("probe did not run as an original build identity")
    if (output / "uid-map").read_text().split() != [proof["uid"], proof["guest_uid"], "1"]:
        raise RuntimeError("probe kernel UID map does not bind the guest build identity")
    expected = {
        "capabilities": "0000000000000000", "kernel": receipt["kernel"],
        "boot_id": receipt["boot_id"], "build_filesystem": "ext4",
        "temporary_filesystem": "ext4", "output_filesystem": "ext4",
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "nonce": receipt["probe_nonce"],
    }
    if any(proof[key] != value for key, value in expected.items()):
        raise RuntimeError("probe does not match this VM, source or disk policy")
    receipt["outputs"] = outputs
    receipt["probe"] = {"output": str(output), **proof}


def stop_process(process):
    """Reaps the process group before its private resources are retired."""
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=7200)
    parser.add_argument("--memory-mib", type=int, default=16384)
    parser.add_argument("--disk-gib", type=int, default=80)
    parser.add_argument("--verify-probe", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if command.count("@BUILDER@") != 1:
        parser.error("command requires one literal @BUILDER@ argument")
    for flag in ("--max-jobs", "--builders"):
        if command.count(flag) != 1:
            parser.error(f"command requires exactly one {flag}")
    if command[command.index("--max-jobs") + 1] != "0":
        parser.error("host local builds must be disabled with --max-jobs 0")
    if command[command.index("--builders") + 1] != "@BUILDER@":
        parser.error("the only builder must be the private VM")
    probe_nonce = None
    if args.verify_probe:
        nonces = [command[index + 2] for index in range(len(command) - 2)
                  if command[index:index + 2] == ["--argstr", "nonce"]]
        if len(nonces) != 1 or not re.fullmatch(r"[a-zA-Z0-9_-]{16,128}", nonces[0]):
            parser.error("probe requires one explicit --argstr nonce of 16 to 128 safe characters")
        probe_nonce = nonces[0]
    if args.timeout <= 0 or not 1024 <= args.memory_mib <= 32768:
        parser.error("invalid timeout or memory bound")
    if not 8 <= args.disk_gib <= 256:
        parser.error("invalid disk bound")

    work = args.work_dir.absolute()
    if len(os.fsencode(work / "daemon.sock")) >= 100:
        parser.error("private Unix socket path is too long")
    if not re.fullmatch(r"/[a-zA-Z0-9/_-]+", str(work)):
        parser.error("private work path requires ASCII letters, numbers, underscores, hyphens and slashes")
    work.mkdir(mode=0o700)
    environment = args.environment.resolve(strict=True)
    filesystem = subprocess.check_output([
        str(environment / "findmnt"), "--noheadings", "--output", "FSTYPE",
        "--target", str(work),
    ], text=True).strip()
    if filesystem in {"tmpfs", "ramfs"}:
        raise RuntimeError("builder disks require persistent host storage")

    kernel, = (environment / "kernel").glob("vmlinux-*")
    root = work / "root.img"
    storage = work / "builder.img"
    subprocess.run([
        str(environment / "cp"), "--reflink=auto", "--sparse=always",
        str(environment / "root.img"), str(root),
    ], check=True)
    root.chmod(0o600)
    with storage.open("xb") as disk:
        disk.truncate(args.disk_gib * 1024**3)

    endpoint = work / "vsock"
    relay = work / "stdio-relay"
    relay.write_text(
        f"#!{environment}/bash\nset -euo pipefail\n"
        f'exec "{environment}/python3" "{environment}/proxy.py" "{endpoint}" "$@"\n'
    )
    relay.chmod(0o700)
    configuration = {
        "boot-source": {
            "kernel_image_path": str(kernel),
            "boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/init quiet",
        },
        "drives": [
            {"drive_id": "rootfs", "path_on_host": str(root),
             "is_root_device": True, "is_read_only": False},
            {"drive_id": "test-input", "path_on_host": str(environment / "input.img"),
             "is_root_device": False, "is_read_only": True},
            {"drive_id": "builder-data", "path_on_host": str(storage),
             "is_root_device": False, "is_read_only": False},
        ],
        "machine-config": {
            "vcpu_count": 8, "mem_size_mib": args.memory_mib,
            "smt": False, "track_dirty_pages": False, "huge_pages": "None",
        },
        "vsock": {"guest_cid": 42, "uds_path": str(endpoint)},
    }
    config = work / "firecracker.json"
    config.write_text(json.dumps(configuration, indent=2) + "\n")
    command = [f"ssh-ng://localhost?remote-program={relay} x86_64-linux - 1 1 terrane-native-builder" if arg == "@BUILDER@" else arg
               for arg in command]
    # Keep the command's explicit sandbox policy independent of host defaults.
    command.extend([
        "--option", "build-dir", "/build",
        "--option", "sandbox-paths", "",
        "--option", "extra-sandbox-paths", "",
        "--option", "sandbox", "true",
        "--option", "sandbox-fallback", "false",
    ])
    (work / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    vm = build = None
    success = False
    guest_ready = False
    started = time.monotonic()
    serial = work / "serial.log"
    receipt = {"command": command, "host_filesystem": filesystem,
               "native_host_builds_allowed": False, "probe_nonce": probe_nonce}
    try:
        with serial.open("wb") as out, (work / "firecracker.stderr").open("wb") as err:
            vm = subprocess.Popen([
                str(environment / "firecracker"), "--no-api", "--config-file", str(config),
            ], stdout=out, stderr=err, env=env, start_new_session=True)

        deadline = time.monotonic() + 120
        while True:
            transcript = re.sub(
                r"\x1b\[[0-?]*[ -/]*[@-~]", "", serial.read_text(errors="replace")
            )
            ready = re.search(r"^NATIVE_BUILDER_READY kernel=(\S+) boot_id=(\S+) nix=(.+)$",
                              transcript, re.MULTILINE)
            if ready:
                break
            if vm.poll() is not None:
                raise RuntimeError("builder VM exited before readiness")
            if time.monotonic() >= deadline:
                raise TimeoutError("builder VM did not become ready within 120 seconds")
            time.sleep(0.2)
        receipt.update(kernel=ready[1], boot_id=ready[2], nix=ready[3])
        guest_ready = True

        with (work / "command.stdout").open("wb") as out, (work / "command.stderr").open("wb") as err:
            build = subprocess.Popen(command, stdout=out, stderr=err, env=env,
                                     start_new_session=True)
            receipt["command_exit_code"] = build.wait(timeout=args.timeout)
        if receipt["command_exit_code"] != 0:
            raise RuntimeError("remote build command failed")
        if args.verify_probe:
            verify_probe(work, receipt)

        with connect_vsock(endpoint, 65) as control:
            control.sendall(b"stop\n")
            control.shutdown(1)
        receipt["vm_exit_code"] = vm.wait(timeout=30)
        transcript = serial.read_text(errors="replace")
        if receipt["vm_exit_code"] != 0 or "TEST_RESULT:PASS" not in transcript:
            raise RuntimeError("builder VM did not acknowledge clean shutdown")
        if "TEST_RESULT:FAIL" in transcript or "NATIVE_BUILDER_STOPPED" not in transcript:
            raise RuntimeError("builder VM shutdown evidence is incomplete")
        success = True
    except BaseException as error:
        receipt["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        stop_process(build)
        if guest_ready and vm.poll() is None:
            try:
                with connect_vsock(endpoint, 65) as control:
                    control.sendall(b"stop\n")
                    control.shutdown(1)
                receipt["vm_exit_code"] = vm.wait(timeout=30)
            except (OSError, TimeoutError, subprocess.TimeoutExpired) as error:
                receipt["shutdown_failure"] = str(error)
        stop_process(vm)
        receipt.update(success=success, elapsed_seconds=time.monotonic() - started)
        (work / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        # Failed disks remain evidence. Successful runs retain only logs/configuration.
        if success:
            root.unlink()
            storage.unlink()
            relay.unlink(missing_ok=True)
            endpoint.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
