"""Runs the native published-image qualification scenario.

The coordinator has already authenticated the release and copied every object
into this private attempt directory. This program verifies the format encodings,
boots the exact image in the contract's QEMU environment, and exercises the
retained predecessor-to-candidate transition. It writes a report only after all
required operations have completed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import subprocess
import threading
import time
import tomllib
import urllib.parse
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path.cwd()
REQUEST = ROOT / "request.json"
OBJECTS = ROOT / "objects.json"
PREDECESSOR_OBJECTS = ROOT / "predecessor-objects.json"
DOWNLOADS = ROOT / "downloads.json"
REPORT = ROOT / "scenario-report.json"

PLATFORM = os.environ["AOS_QUALIFICATION_PLATFORM"]
ASSESSMENT_ROOT = pathlib.Path(os.environ["AOS_QUALIFICATION_ASSESSMENTS"])
STAGING_HUB_URL = os.environ["AOS_QUALIFICATION_STAGING_HUB_URL"]
QEMU = os.environ["AOS_QUALIFICATION_QEMU"]
QEMU_IMG = os.environ["AOS_QUALIFICATION_QEMU_IMG"]
FIRMWARE_CODE = os.environ["AOS_QUALIFICATION_FIRMWARE_CODE"]
FIRMWARE_VARS = os.environ["AOS_QUALIFICATION_FIRMWARE_VARS"]
SWTPM = os.environ["AOS_QUALIFICATION_SWTPM"]
SGDISK = os.environ["AOS_QUALIFICATION_SGDISK"]
MKE2FS = os.environ["AOS_QUALIFICATION_MKE2FS"]
ZSTD = os.environ["AOS_QUALIFICATION_ZSTD"]
SSH = os.environ["AOS_QUALIFICATION_SSH"]
SCP = os.environ["AOS_QUALIFICATION_SCP"]
SSH_KEYGEN = os.environ["AOS_QUALIFICATION_SSH_KEYGEN"]
OPENSSL = os.environ["AOS_QUALIFICATION_OPENSSL"]

EXPECTED_CHECKS = {
    "anonymous-download-and-resume",
    "disk-format-equivalence",
    "uefi-boot",
    "repeated-warm-and-cold-boot",
    "provisioning",
    "host-configuration",
    "ssh-dns-time-network",
    "boot-integrity-and-encrypted-state",
    "no-fixture-authorities",
    "configuration-activation-and-rollback",
    "package-install-change-remove-recover",
    "nginx-http-tls",
    "persistent-workload",
    "reboot-persistence",
    "bounded-generation-retention",
    "disk-and-memory-pressure",
    "preceding-image-identity",
    "upgrade",
    "configuration-rebind",
    "boot-blessing",
    "interrupted-writes-and-reboots",
    "automatic-fallback",
    "explicit-rollback",
    "repeated-update-and-rollback",
    "committed-data-preserved",
    "offline-recovery",
    "update-after-recovery",
}


def canonical(value: Any) -> bytes:
    """Encodes the canonical JSON form used by release evidence."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def digest(domain: str, value: Any) -> str:
    """Computes a domain-separated canonical SHA-256 identity."""

    hashed = hashlib.sha256()
    hashed.update(domain.encode())
    hashed.update(b"\0")
    hashed.update(canonical(value))
    return "sha256:" + hashed.hexdigest()


def read_json(path: pathlib.Path) -> Any:
    with path.open("rb") as source:
        return json.load(source)


def hash_file(path: pathlib.Path) -> str:
    hashed = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(8 * 1024 * 1024):
            hashed.update(block)
    return hashed.hexdigest()


def run(
    arguments: list[str],
    *,
    timeout: int = 1800,
) -> subprocess.CompletedProcess[str]:
    """Runs a host command and retains its output on failure."""

    result = subprocess.run(
        arguments,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {arguments!r}\n{result.stdout}"
        )
    return result


def object_with_suffix(objects: dict[str, str], suffix: str) -> tuple[str, pathlib.Path]:
    matches = [
        (name, pathlib.Path(path))
        for name, path in objects.items()
        if name.endswith("/" + suffix)
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one {suffix!r} object, found {len(matches)}")
    return matches[0]


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@dataclass
class Counts:
    reboot_cycles: int = 0
    cold_boot_cycles: int = 0
    update_rollback_cycles: int = 0
    workload_operations: int = 0


class VirtualMachine:
    """Owns one persistent QEMU disk, firmware store, TPM, and SSH endpoint."""

    def __init__(
        self,
        name: str,
        source: pathlib.Path,
        host_config: pathlib.Path,
        ssh_key: pathlib.Path,
        counts: Counts,
        recovery_media: pathlib.Path | None = None,
    ) -> None:
        self.name = name
        self.root = ROOT / name
        self.root.mkdir()
        self.disk = self.root / "disk.raw"
        vars_name = (
            "OVMF_VARS.fd"
            if PLATFORM == "x86_64-linux"
            else "AAVMF_VARS.json"
        )
        self.vars = self.root / vars_name
        self.serial_socket = self.root / "serial.sock"
        self.serial_log = self.root / "serial.log"
        self.tpm_socket = self.root / "tpm.sock"
        self.tpm_state = self.root / "tpm-state"
        self.tpm_state.mkdir()
        self.qemu_log = self.root / "qemu.log"
        self.swtpm_log = self.root / "swtpm.log"
        self.host_config = host_config
        self.ssh_key = ssh_key
        self.recovery_media = recovery_media
        self.port = available_port()
        self.counts = counts
        self.qemu: subprocess.Popen[bytes] | None = None
        self.swtpm: subprocess.Popen[bytes] | None = None
        self.serial: socket.socket | None = None
        self.serial_bytes = bytearray()
        self.serial_lock = threading.Lock()

        run([QEMU_IMG, "convert", "-O", "raw", str(source), str(self.disk)])
        with self.disk.open("r+b") as output:
            output.truncate(32768 * 1024 * 1024)
        run([SGDISK, "-e", str(self.disk)])
        if PLATFORM == "x86_64-linux":
            shutil.copyfile(FIRMWARE_VARS, self.vars)
        else:
            self.vars.write_text("{}", encoding="ascii")

    def _start_swtpm(self) -> None:
        if self.tpm_socket.exists():
            self.tpm_socket.unlink()
        log = self.swtpm_log.open("ab")
        self.swtpm = subprocess.Popen(
            [
                SWTPM,
                "socket",
                "--tpm2",
                f"--tpmstate=dir={self.tpm_state}",
                f"--ctrl=type=unixio,path={self.tpm_socket}",
                "--flags=startup-clear",
                "--log=level=5",
            ],
            stdout=log,
            stderr=log,
        )
        self._wait_path(self.tpm_socket, 10)

    @staticmethod
    def _wait_path(path: pathlib.Path, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while not path.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError(f"timed out waiting for {path}")
            time.sleep(0.05)

    def _arguments(self) -> list[str]:
        arguments = [QEMU]
        if PLATFORM == "x86_64-linux":
            if not os.access("/dev/kvm", os.R_OK | os.W_OK):
                raise RuntimeError(
                    "the x86_64 image qualification target requires accessible KVM"
                )
            arguments += [
                "-machine", "q35,smm=on,accel=kvm",
                "-cpu", "host",
                "-global", "driver=cfi.pflash01,property=secure,value=on",
                "-global", "ICH9-LPC.disable_s3=1",
                "-drive", f"if=pflash,unit=0,format=raw,readonly=on,file={FIRMWARE_CODE}",
                "-drive", f"if=pflash,unit=1,format=raw,file={self.vars}",
            ]
            tpm_device = "tpm-tis,tpmdev=tpm0"
        else:
            arguments += [
                "-machine", "virt,accel=tcg",
                "-cpu", "max",
                "-bios", FIRMWARE_CODE,
                "-device", f"uefi-vars-sysbus,jsonfile={self.vars}",
            ]
            tpm_device = "tpm-tis-device,tpmdev=tpm0"
        arguments += [
            "-m", "8192",
            "-smp", "2",
            "-nographic",
            "-monitor", "none",
            "-drive", f"file={self.disk},format=raw,if=virtio",
            "-nic", f"user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{self.port}-:22",
            "-fw_cfg", f"name=opt/org.andyl/host-nix,file={self.host_config}",
            "-chardev", f"socket,id=serial,path={self.serial_socket},server=on,wait=off",
            "-serial", "chardev:serial",
            "-device", "virtio-rng-pci",
            "-chardev", f"socket,id=chrtpm,path={self.tpm_socket}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            "-device", tpm_device,
        ]
        if self.recovery_media is not None:
            arguments += [
                "-drive", f"id=recovery,file={self.recovery_media},format=raw,if=none",
                "-device", "qemu-xhci,id=recovery-usb",
                "-device",
                "usb-storage,drive=recovery,bus=recovery-usb.0,"
                "serial=aos-recovery-media,removable=on",
            ]
        return arguments

    def start(self) -> None:
        self._start_swtpm()
        if self.serial_socket.exists():
            self.serial_socket.unlink()
        log = self.qemu_log.open("ab")
        self.qemu = subprocess.Popen(self._arguments(), stdout=log, stderr=log)
        self._wait_path(self.serial_socket, 20)
        self.serial = socket.socket(socket.AF_UNIX)
        self.serial.connect(str(self.serial_socket))
        threading.Thread(target=self._drain_serial, args=(self.serial,), daemon=True).start()
        self.wait_for_ssh(600)

    def _drain_serial(self, serial: socket.socket) -> None:
        while True:
            try:
                data = serial.recv(65536)
            except OSError:
                return
            if not data:
                return
            with self.serial_lock:
                self.serial_bytes.extend(data)
            with self.serial_log.open("ab") as output:
                output.write(data)

    def ssh(
        self,
        command: str,
        *,
        user: str = "root",
        timeout: int = 600,
        check: bool = True,
    ) -> str:
        arguments = [
            SSH,
            "-i", str(self.ssh_key),
            "-p", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            f"{user}@127.0.0.1",
            command,
        ]
        result = subprocess.run(
            arguments,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            raise RuntimeError(
                f"guest command failed ({result.returncode}): "
                f"{command}\n{result.stdout}"
            )
        return result.stdout

    def copy_to(self, source: pathlib.Path, destination: str) -> None:
        run([
            SCP,
            "-i", str(self.ssh_key),
            "-P", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            str(source),
            f"root@127.0.0.1:{destination}",
        ])

    def wait_for_ssh(self, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.qemu is not None and self.qemu.poll() is not None:
                raise RuntimeError(f"{self.name} QEMU exited while waiting for SSH")
            try:
                active = self.ssh(
                    "systemctl is-active multi-user.target",
                    timeout=15,
                    check=False,
                )
                if active.strip() == "active":
                    return
            except (subprocess.TimeoutExpired, OSError):
                pass
            time.sleep(2)
        raise RuntimeError(f"timed out waiting for SSH on {self.name}")

    def reboot(self) -> None:
        before = self.ssh("cat /proc/sys/kernel/random/boot_id").strip()
        self.ssh("systemctl reboot", timeout=30, check=False)
        deadline = time.monotonic() + 720
        while time.monotonic() < deadline:
            try:
                after = self.ssh(
                    "cat /proc/sys/kernel/random/boot_id",
                    timeout=15,
                    check=False,
                ).strip()
                if after and after != before:
                    self.wait_for_ssh(420)
                    self.counts.reboot_cycles += 1
                    return
            except (subprocess.TimeoutExpired, OSError):
                pass
            time.sleep(2)
        raise RuntimeError(f"timed out rebooting {self.name}")

    def power_cycle(self) -> None:
        self.ssh("systemctl poweroff", timeout=30, check=False)
        self._wait_exit(180)
        self.stop_processes()
        self.start()
        self.counts.cold_boot_cycles += 1

    def _wait_exit(self, timeout: int) -> None:
        if self.qemu is None:
            raise RuntimeError(f"{self.name} has no running QEMU process")
        try:
            status = self.qemu.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"{self.name} did not power off") from error
        if status != 0:
            raise RuntimeError(f"{self.name} QEMU exited with {status}")

    def serial_mark(self) -> int:
        with self.serial_lock:
            return len(self.serial_bytes)

    def serial_send(self, line: str) -> None:
        if self.serial is None:
            raise RuntimeError("serial console is disconnected")
        self.serial.sendall((line + "\n").encode())

    def serial_wait(self, text: str, mark: int, timeout: int = 900) -> str:
        needle = text.encode()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.serial_lock:
                captured = bytes(self.serial_bytes[mark:])
            if needle in captured:
                return captured.decode(errors="replace")
            if self.qemu is not None and self.qemu.poll() is not None:
                raise RuntimeError(f"QEMU exited while waiting for serial text {text!r}")
            time.sleep(0.2)
        raise RuntimeError(f"timed out waiting for serial text {text!r}")

    def stop_processes(self) -> None:
        if self.serial is not None:
            self.serial.close()
            self.serial = None
        for process in (self.qemu, self.swtpm):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=20)
        self.qemu = None
        self.swtpm = None


class Scenario:
    def __init__(self) -> None:
        self.request = read_json(REQUEST)
        self.case = self.request["qualification_case"]
        self.objects: dict[str, str] = read_json(OBJECTS)
        self.predecessor_objects: dict[str, str] = read_json(PREDECESSOR_OBJECTS)
        self.counts = Counts()
        self.started = time.time()
        self.started_at = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(self.started),
        )
        self.current: VirtualMachine | None = None

        self.work = ROOT / "image-work"
        self.work.mkdir()
        self.key = self.work / "ssh-key"
        run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)])
        public_key = (self.key.with_suffix(".pub")).read_text(encoding="ascii").strip()
        self.host_config = self.work / "host.nix"
        self.host_config.write_text(self._host_config(public_key), encoding="utf-8")

    @staticmethod
    def _host_config(public_key: str) -> str:
        return f'''{{ pkgs, ... }}: {{
  aos.roles.server.enable = true;
  aos.services.ssh.enable = true;
  aos.services.ssh.permitRootLogin = "prohibit-password";
  aos.networking.hostName = "qualification-initial";
  environment.etc."ssh/authorized_keys/root".text = "{public_key}";
}}
'''

    def validate_inputs(self) -> None:
        if PLATFORM not in {"x86_64-linux", "aarch64-linux"}:
            raise RuntimeError(
                "image scenario supports only native Linux release platforms"
            )
        if self.request["platform"] != PLATFORM:
            raise RuntimeError("request platform differs from native executor")
        if self.case["target"]["kind"] != "image" or self.case["phase"] != "staging":
            raise RuntimeError("scenario received a non-staging image claim")
        if self.case["claim"]["minimum_assurance"] != "A2":
            raise RuntimeError("scenario requires the A2 image claim")
        if set(self.case["checks"]) != EXPECTED_CHECKS:
            raise RuntimeError("image claim check set differs from the implemented program")
        if self.case.get("predecessor") is None or not self.predecessor_objects:
            raise RuntimeError("image transition lacks its verified retained predecessor")
        registry_name = self.request["registry"]
        self.registry_client = (
            "andyl"
            if registry_name == "andyl/main"
            else registry_name.replace("/", "-")
        )
        if not re.fullmatch(r"[A-Za-z0-9_-]+", self.registry_client):
            raise RuntimeError("request registry does not map to a safe client name")

        staging_hub = urllib.parse.urlsplit(STAGING_HUB_URL)
        if (
            staging_hub.scheme != "https"
            or not staging_hub.hostname
            or staging_hub.username is not None
            or staging_hub.password is not None
            or staging_hub.query
            or staging_hub.fragment
            or staging_hub.path not in {"", "/"}
        ):
            raise RuntimeError("staging Hub URL is not a bounded HTTPS origin")
        registry_path = urllib.parse.quote(registry_name, safe="/")
        self.staging_url = STAGING_HUB_URL.rstrip("/") + f"/{registry_path}/"

        downloads = read_json(DOWNLOADS)
        resumed = [
            trace
            for trace in downloads.values()
            if trace["mode"] == "range-resume"
        ]
        if len(resumed) != 1 or [
            request["status"] for request in resumed[0]["requests"]
        ] != [206, 206]:
            raise RuntimeError("public download did not exercise the exact two-range resume path")

        candidate_manifest = read_json(
            pathlib.Path(self.objects["control/release-manifest-envelope"])
        )
        predecessor_manifest = read_json(
            pathlib.Path(
                self.predecessor_objects["control/release-manifest-envelope"]
            )
        )
        if (
            candidate_manifest["payload"]["registry"] != self.request["registry"]
            or candidate_manifest["payload"]["release_id"]
            != self.request["release_id"]
            or candidate_manifest["payload_digest"]
            != self.request["manifest_digest"]
        ):
            raise RuntimeError("candidate manifest differs from the executor request")
        if (
            predecessor_manifest["payload"]["registry"]
            != self.case["predecessor"]["registry"]
            or predecessor_manifest["payload"]["release_id"]
            != self.case["predecessor"]["release_id"]
            or predecessor_manifest["payload_digest"]
            != self.case["predecessor"]["manifest_digest"]
        ):
            raise RuntimeError("retained predecessor differs from the frozen transition")
        self.candidate_version = candidate_manifest["payload"]["version"]
        self.predecessor_version = predecessor_manifest["payload"]["version"]

        target = self.case["target"]["id"]
        assessment_path = ASSESSMENT_ROOT / f"{target}.json"
        if assessment_path.is_symlink() or not assessment_path.is_file():
            raise RuntimeError("reviewed image target assessment is missing or is a symlink")
        raw = assessment_path.read_bytes()
        self.assessment = json.loads(raw)
        if raw != canonical(self.assessment) + b"\n":
            raise RuntimeError("reviewed assessment is not canonical JSON")
        profile = self.case["target"]["environment"]
        profile_digest = digest("aos.release.environment-profile/v1", profile)
        if self.assessment["scope_digest"] != profile_digest:
            raise RuntimeError("reviewed assessment covers another environment profile")

    def verify_formats(self) -> None:
        _, logical = object_with_suffix(self.objects, "logical-disk")
        _, raw = object_with_suffix(self.objects, "raw")
        _, qcow2 = object_with_suffix(self.objects, "qcow2")
        _, vmdk = object_with_suffix(self.objects, "vmdk")
        _, vhd = object_with_suffix(self.objects, "vhd")

        expected = hash_file(logical)
        process = subprocess.Popen(
            [ZSTD, "-q", "-d", "-c", str(raw)],
            stdout=subprocess.PIPE,
        )
        hashed = hashlib.sha256()
        if process.stdout is None:
            raise RuntimeError("zstd decoder did not expose its output pipe")
        while block := process.stdout.read(8 * 1024 * 1024):
            hashed.update(block)
        if process.wait() != 0 or hashed.hexdigest() != expected:
            raise RuntimeError("compressed raw image differs from the logical disk")
        for image_format, path in (("qcow2", qcow2), ("vmdk", vmdk), ("vpc", vhd)):
            run(
                [
                    QEMU_IMG,
                    "compare",
                    "-f",
                    "raw",
                    "-F",
                    image_format,
                    str(logical),
                    str(path),
                ]
            )

    def enroll(self, machine: VirtualMachine) -> str:
        machine.start()
        machine.ssh(
            "test $(od -An -tu1 -j4 -N1 "
            "/sys/firmware/efi/efivars/"
            "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c) -eq 1"
        )
        machine.ssh("test -e /dev/tpm0 && test -e /sys/class/tpm/tpm0")
        machine.ssh("PATH=/usr/bin:/usr/sbin:/bin:/sbin aos-sb-enroll", timeout=300)
        machine.reboot()
        machine.ssh(
            "test $(od -An -tu1 -j4 -N1 "
            "/sys/firmware/efi/efivars/"
            "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c) -eq 1"
        )
        machine.ssh("findmnt -n -o SOURCE /var | grep -Fx /dev/mapper/var")
        machine.ssh(
            "set -eu; "
            "var_device=$(basename $(readlink -f /dev/mapper/var)); "
            "grep -Eq '^CRYPT-LUKS2-' /sys/class/block/$var_device/dm/uuid"
        )
        machine.ssh("findmnt -n -o FSTYPE,OPTIONS / | grep -E '^erofs .*ro'")
        machine.ssh(
            "set -eu; "
            "grep -Eq '(^| )roothash=[0-9a-f]{64}($| )' /proc/cmdline; "
            "root=$(findmnt -n -o SOURCE /); "
            "block=$(basename $(readlink -f $root)); "
            "grep -Eq '^CRYPT-VERITY|^verity-' /sys/class/block/$block/dm/uuid"
        )
        machine.ssh(
            "set -eu; "
            "systemctl is-active --quiet aos-image-measurement-index.service; "
            "test -s /run/systemd/tpm2-pcr-signature.json"
        )
        recovery_key = machine.ssh("cat /run/aos-var-recovery.key").strip()
        if not recovery_key:
            raise RuntimeError("first enforcing boot did not produce the escrow recovery key")
        return recovery_key

    def exercise_candidate(self) -> None:
        _, qcow2 = object_with_suffix(self.objects, "qcow2")
        machine = VirtualMachine("candidate", qcow2, self.host_config, self.key, self.counts)
        self.current = machine
        self.enroll(machine)

        self._assert_release(machine, self.candidate_version, "candidate")

        machine.ssh("test -s /var/lib/aos-provisioning/audit.json")
        machine.ssh("systemctl is-active --quiet sshd.service")
        machine.ssh(
            "for attempt in $(seq 1 150); do "
            "resolvectl query aos.andyl.org >/dev/null 2>&1 && exit 0; "
            "sleep 2; done; exit 1",
            timeout=330,
        )
        machine.ssh(
            "for attempt in $(seq 1 150); do "
            "timedatectl show -p NTPSynchronized --value | grep -Fx yes && exit 0; "
            "sleep 2; done; exit 1",
            timeout=330,
        )
        machine.ssh("grep -Fx tier=testing /etc/aos/release-profile")
        machine.ssh(
            "test ! -e /usr/share/aos-test-agent && "
            "test ! -e /nix/var/nix/.aos-test-fixture"
        )

        self._exercise_configuration_and_packages(machine)
        for _ in range(9):
            machine.reboot()
            self._assert_persistent_workload(machine)
        for _ in range(3):
            machine.power_cycle()
            machine.ssh(
                "test $(od -An -tu1 -j4 -N1 "
                "/sys/firmware/efi/efivars/"
                "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c) -eq 1"
            )
            machine.ssh("test -e /dev/tpm0")
            self._assert_persistent_workload(machine)

        machine.ssh("apm clean --system --generations --keep 3")
        machine.ssh(
            "test $(find /var/lib/profiles/system -maxdepth 1 "
            "-type d -name 'gen-*' | wc -l) -le 4"
        )
        self._exercise_pressure(machine)
        self._assert_persistent_workload(machine)
        machine.ssh("systemctl poweroff", check=False)
        machine._wait_exit(180)
        machine.stop_processes()

    def _stage_registry(self, machine: VirtualMachine) -> None:
        config_path = f"/etc/apm/registries.d/{self.registry_client}.toml"
        source = machine.ssh(f"cat {shlex.quote(config_path)}")
        config = tomllib.loads(source)
        registry = config.get("registry", {})
        signing = registry.get("signing", {})
        if (
            registry.get("name") != self.registry_client
            or signing.get("required") is not True
            or not isinstance(signing.get("public_key"), str)
            or not signing["public_key"].startswith(self.registry_client + ":Ed25519:")
        ):
            raise RuntimeError("baked registry does not carry the required trust anchor")
        lines = source.splitlines()
        url_lines = [index for index, line in enumerate(lines) if line.startswith("url = ")]
        channel_lines = [
            index for index, line in enumerate(lines) if line.startswith("channel = ")
        ]
        tag_lines = [index for index, line in enumerate(lines) if line.startswith("tag = ")]
        if len(url_lines) != 1 or len(channel_lines) != 1 or tag_lines:
            raise RuntimeError(
                "baked registry does not have the expected URL and channel selector"
            )
        lines[url_lines[0]] = f"url = {json.dumps(self.staging_url)}"

        # Canonical registry finalization signs the release version as its exact Git tag.
        lines[channel_lines[0]] = f"tag = {json.dumps(self.candidate_version)}"

        overlay = self.work / f"{self.registry_client}.toml"
        overlay.write_text("\n".join(lines) + "\n", encoding="utf-8")
        destination = f"/var/lib/apm/config/registries.d/{self.registry_client}.toml"
        machine.ssh("install -d -m 0755 /var/lib/apm/config/registries.d")
        machine.copy_to(overlay, destination + ".new")
        machine.ssh(
            f"set -eu; install -m 0644 {shlex.quote(destination + '.new')} "
            f"{shlex.quote(destination)}; "
            f"rm {shlex.quote(destination + '.new')}; "
            f"apm update --system --registry {shlex.quote(self.registry_client)}",
            timeout=600,
        )

    def _exercise_configuration_and_packages(self, machine: VirtualMachine) -> None:
        self._stage_registry(machine)
        machine.ssh(
            "set -eu; "
            "printf 'packages = [\"cryptsetup\", \"curl\", \"iproute2\", "
            "\"nginx\"]\\n' >/run/desired.toml; "
            "apm install --system --from /run/desired.toml --yes",
            timeout=1200,
        )
        machine.ssh(
            "set -eu; "
            "command -v curl; command -v ip; command -v nginx; "
            "command -v veritysetup"
        )
        self._exercise_verity_rejection(machine)

        certificate = self.work / "tls.crt"
        private_key = self.work / "tls.key"
        run(
            [
                OPENSSL,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout",
                str(private_key),
                "-out",
                str(certificate),
            ]
        )
        machine.ssh(
            "set -eu; mkdir -p /var/lib/qualification/www; "
            "printf 'acknowledged-payload\\n' "
            ">/var/lib/qualification/www/state"
        )
        machine.copy_to(certificate, "/var/lib/qualification/cert.pem")
        machine.copy_to(private_key, "/var/lib/qualification/key.pem")
        nginx_config = self.work / "nginx.conf"
        nginx_config.write_text(
            """user nobody;
worker_processes 1;
pid /run/qualification-nginx.pid;
error_log /var/lib/qualification/error.log;
events { worker_connections 128; }
http {
  access_log /var/lib/qualification/access.log;
  client_body_temp_path /var/lib/qualification/body;
  proxy_temp_path /var/lib/qualification/proxy;
  fastcgi_temp_path /var/lib/qualification/fastcgi;
  uwsgi_temp_path /var/lib/qualification/uwsgi;
  scgi_temp_path /var/lib/qualification/scgi;
  server {
    listen 8080;
    listen 8443 ssl;
    server_name localhost;
    add_header X-AOS-Qualification initial;
    ssl_certificate /var/lib/qualification/cert.pem;
    ssl_certificate_key /var/lib/qualification/key.pem;
    root /var/lib/qualification/www;
  }
}
""",
            encoding="utf-8",
        )
        machine.copy_to(nginx_config, "/var/lib/qualification/nginx.conf")
        machine.ssh("chmod 0600 /var/lib/qualification/key.pem")

        network = machine.ssh(
            "set -eu; "
            "interface=$(ip -4 route show default | awk 'NR == 1 {print $5}'); "
            "address=$(ip -4 -o address show dev $interface scope global "
            "| awk 'NR == 1 {print $4}'); "
            "gateway=$(ip -4 route show default dev $interface "
            "| awk 'NR == 1 {print $3}'); "
            "dns=$(resolvectl dns $interface | awk 'NR == 1 {print $NF}'); "
            "printf '%s\\n%s\\n%s\\n%s\\n' $interface $address $gateway $dns"
        ).splitlines()
        if len(network) != 4 or re.fullmatch(r"[A-Za-z0-9_.-]+", network[0]) is None:
            raise RuntimeError("guest did not expose one safe default network interface")
        try:
            ipaddress.ip_interface(network[1])
            ipaddress.ip_address(network[2])
            ipaddress.ip_address(network[3])
        except ValueError as error:
            raise RuntimeError("guest DHCP state is not a valid static configuration") from error
        interface, address, gateway, dns = network

        host_one = self.work / "runtime-one.nix"
        host_two = self.work / "runtime-two.nix"
        base = self.host_config.read_text(encoding="utf-8").rsplit("}", 1)[0]
        service = '''  aos.apm.desiredPackages = [
    "cryptsetup"
    "curl"
    "iproute2"
    "nginx"
  ];
  aos.users.groups.qualification = {
    gid = 2000;
    members = [ "qualification" ];
  };
  aos.users.users.qualification = {
    uid = 2000;
    group = "qualification";
    home = "/var/lib/qualification-user";
    shell = "${pkgs.bash}/bin/bash";
    description = "Qualification operator";
    extraGroups = [];
  };
  environment.etc."ssh/authorized_keys/qualification" = {
    text = "__PUBLIC_KEY__";
    mode = "0600";
  };
  systemd.services.qualification-nginx = {
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "/bin/nginx -c /var/lib/qualification/nginx.conf -g 'daemon off;'";
      ExecReload = "/bin/nginx -c /var/lib/qualification/nginx.conf -s reload";
      Restart = "on-failure";
    };
  };
'''.replace(
            "__PUBLIC_KEY__",
            self.key.with_suffix(".pub").read_text(encoding="ascii").strip(),
        )
        dhcp_policy = '''  aos.networking = {
    hostName = "qualification-one";
    useDHCP = true;
  };
'''
        static_policy = f'''  aos.networking = {{
    hostName = "qualification-two";
    useDHCP = false;
    nameservers = [ "{dns}" ];
    interfaces.{json.dumps(interface)} = {{
      address = "{address}";
      gateway = "{gateway}";
      dns = "{dns}";
    }};
  }};
'''
        host_one.write_text(
            base
            + service
            + dhcp_policy
            + '  environment.etc."qualification-generation".text = "one\\n";\n}\n'
        )
        host_two.write_text(
            base
            + service
            + static_policy
            + '  environment.etc."qualification-generation".text = "two\\n";\n}\n'
        )
        machine.copy_to(host_one, "/run/runtime-one.nix")
        machine.copy_to(host_two, "/run/runtime-two.nix")
        machine.ssh(
            "apm switch --from /run/runtime-one.nix "
            "--eval-root /run/qualification-switch-one",
            timeout=600,
        )
        generation_one = read_remote_json(
            machine,
            "/var/lib/profiles/system/state.json",
        )["current"]
        if not isinstance(generation_one, int) or generation_one < 1:
            raise RuntimeError("first configuration activation lacks a valid generation")
        machine.ssh("test $(hostname) = qualification-one")
        operator_uid = machine.ssh("id -u", user="qualification").strip()
        if operator_uid != "2000":
            raise RuntimeError("named qualification user could not authenticate over SSH")
        self._assert_persistent_workload(machine)

        machine.ssh(
            "set -eu; "
            "cp /var/lib/qualification/nginx.conf /var/lib/qualification/nginx.good; "
            "printf 'invalid;\\n' >>/var/lib/qualification/nginx.conf; "
            "! nginx -t -c /var/lib/qualification/nginx.conf"
        )
        self._assert_persistent_workload(machine)
        machine.ssh(
            "set -eu; "
            "mv /var/lib/qualification/nginx.good /var/lib/qualification/nginx.conf; "
            "sed -i 's/X-AOS-Qualification initial/X-AOS-Qualification changed/' "
            "/var/lib/qualification/nginx.conf; "
            "nginx -t -c /var/lib/qualification/nginx.conf; "
            "systemctl reload qualification-nginx.service"
        )
        machine.ssh(
            "curl --fail --silent --dump-header - --output /dev/null "
            "http://localhost:8080/state | grep -Fi 'X-AOS-Qualification: changed'"
        )

        machine.ssh(
            "set -eu; printf '{ invalid = ; }\\n' >/run/invalid.nix; "
            "! apm switch --from /run/invalid.nix "
            "--eval-root /run/qualification-switch-invalid"
        )
        self._assert_persistent_workload(machine)
        machine.ssh(
            "apm switch --from /run/runtime-two.nix "
            "--eval-root /run/qualification-switch-two",
            timeout=600,
        )
        machine.wait_for_ssh(180)
        machine.ssh("grep -Fx two /etc/qualification-generation")
        machine.ssh(
            f"set -eu; test $(hostname) = qualification-two; "
            f"ip -4 -o address show dev {shlex.quote(interface)} "
            f"| grep -F ' {address} '; "
            f"ip -4 route show default dev {shlex.quote(interface)} "
            f"| grep -F 'via {gateway}'; "
            f"resolvectl dns {shlex.quote(interface)} | grep -F {shlex.quote(dns)}"
        )
        machine.ssh(f"apm rollback --system --generation {generation_one}", timeout=600)
        machine.wait_for_ssh(180)
        machine.ssh("grep -Fx one /etc/qualification-generation")
        machine.ssh("test $(hostname) = qualification-one")

        machine.ssh(
            "set -eu; printf 'packages = []\\n' >/run/desired.toml; "
            "apm install --system --from /run/desired.toml --yes",
            timeout=600,
        )
        machine.ssh("test ! -x /bin/nginx")
        machine.ssh(
            "set -eu; "
            "printf 'packages = [\"cryptsetup\", \"curl\", \"iproute2\", "
            "\"nginx\"]\\n' >/run/desired.toml; "
            "apm install --system --from /run/desired.toml --yes",
            timeout=1200,
        )
        machine.ssh("systemctl restart qualification-nginx.service")
        self._assert_persistent_workload(machine)

    def _assert_persistent_workload(self, machine: VirtualMachine) -> None:
        machine.ssh("systemctl is-active --quiet qualification-nginx.service")
        machine.ssh(
            "curl --fail --silent --show-error "
            "http://localhost:8080/state | grep -Fx acknowledged-payload"
        )
        machine.ssh(
            "curl --fail --silent --show-error "
            "--cacert /var/lib/qualification/cert.pem "
            "https://localhost:8443/state | grep -Fx acknowledged-payload"
        )
        machine.ssh("! curl --fail --silent https://localhost:8443/state")
        machine.ssh(
            "set -eu; ledger=/var/lib/qualification/operations; touch $ledger; "
            "expected=1; while read -r number observed; do "
            "test $number -eq $expected; "
            "wanted=$(printf 'acknowledged-payload:%s\\n' $number "
            "| sha256sum | cut -d ' ' -f1); test $observed = $wanted; "
            "expected=$((expected + 1)); done < $ledger; "
            "digest=$(printf 'acknowledged-payload:%s\\n' $expected "
            "| sha256sum | cut -d ' ' -f1); "
            "printf '%s %s\\n' $expected $digest >>$ledger; sync $ledger"
        )
        self.counts.workload_operations += 1

    @staticmethod
    def _exercise_verity_rejection(machine: VirtualMachine) -> None:
        machine.ssh(
            "set -eu; "
            "root_hash=$(sed -n 's/.* roothash=\\([^ ]*\\).*/\\1/p' /proc/cmdline); "
            "data=$(sed -n 's/.* systemd.verity_root_data=\\([^ ]*\\).*/\\1/p' "
            "/proc/cmdline); "
            "hash=$(sed -n 's/.* systemd.verity_root_hash=\\([^ ]*\\).*/\\1/p' "
            "/proc/cmdline); "
            "test -n \"$root_hash\"; test -b \"$data\"; test -b \"$hash\"; "
            "dd if=$data of=/var/tmp/qualification-root.img bs=4M status=none; "
            "dd if=$hash of=/var/tmp/qualification-root.verity bs=4M status=none; "
            "veritysetup verify /var/tmp/qualification-root.img "
            "/var/tmp/qualification-root.verity $root_hash; "
            "original=$(od -An -tu1 -j1024 -N1 /var/tmp/qualification-root.img); "
            "set -- $original; if test $1 -eq 0; then changed='\\001'; "
            "else changed='\\000'; fi; "
            "printf $changed | dd of=/var/tmp/qualification-root.img "
            "bs=1 seek=1024 conv=notrunc status=none; "
            "! veritysetup verify /var/tmp/qualification-root.img "
            "/var/tmp/qualification-root.verity $root_hash; "
            "rm /var/tmp/qualification-root.img /var/tmp/qualification-root.verity",
            timeout=600,
        )

    @staticmethod
    def _exercise_pressure(machine: VirtualMachine) -> None:
        machine.ssh(
            "set -eu; mkdir -p /var/lib/qualification/pressure; "
            "while test $(df -Pm /var | awk 'NR == 2 {print $4}') -gt 96; do "
            "dd if=/dev/zero "
            "of=/var/lib/qualification/pressure/$(date +%s%N) "
            "bs=1M count=64 status=none || break; done; "
            "! dd if=/dev/zero "
            "of=/var/lib/qualification/pressure/exhaust "
            "bs=1M count=256 status=none; "
            "rm -rf /var/lib/qualification/pressure; sync",
            timeout=1200,
        )
        machine.ssh(
            "set -eu; ! systemd-run --quiet --wait --collect -p MemoryMax=32M "
            "bash -c 'dd if=/dev/zero of=/dev/shm/qualification-memory "
            "bs=1M count=128 status=none; sleep 2'; "
            "rm -f /dev/shm/qualification-memory",
            timeout=180,
        )

    def build_recovery_media(self) -> pathlib.Path:
        _, bundle = object_with_suffix(self.objects, "recovery-bundle")
        archive = self.work / "recovery.tar"
        tree = self.work / "recovery-tree"
        tree.mkdir()
        run([ZSTD, "-q", "-d", "-f", str(bundle), "-o", str(archive)])
        run(["tar", "-xf", str(archive), "-C", str(tree)])
        if not (tree / "aos/recovery/recovery-bundle.json").is_file():
            raise RuntimeError("published recovery bundle lacks its fixed layout")
        size = sum(path.stat().st_size for path in tree.rglob("*") if path.is_file())
        media = self.work / "recovery-media.img"
        with media.open("wb") as output:
            output.truncate(max(512 * 1024 * 1024, size * 2 + 128 * 1024 * 1024))
        run([MKE2FS, "-q", "-F", "-t", "ext4", "-L", "AOS-RECOVERY", "-d", str(tree), str(media)])
        return media

    def exercise_transition(self) -> None:
        _, predecessor = object_with_suffix(self.predecessor_objects, "qcow2")
        recovery_media = self.build_recovery_media()
        machine = VirtualMachine(
            "transition",
            predecessor,
            self.host_config,
            self.key,
            self.counts,
            recovery_media,
        )
        self.current = machine
        recovery_key = self.enroll(machine)
        self._assert_release(machine, self.predecessor_version, "predecessor")
        machine.ssh(
            "set -eu; mkdir -p /var/lib/qualification; "
            "printf 'committed-transition-data\\n' "
            ">/var/lib/qualification/transition-state; "
            "cd /var/lib/qualification; "
            "sha256sum transition-state >transition-state.sha256; "
            "sync transition-state transition-state.sha256"
        )
        self._stage_registry(machine)

        machine.ssh(
            "set -eu; "
            "before=$(dd if=/dev/disk/by-partlabel/root-b bs=4M count=1 status=none | sha256sum); "
            "nohup bash -c 'exec apm upgrade --system --yes' "
            ">/var/lib/qualification/interrupted.log 2>&1 & pid=$!; "
            "echo $pid >/var/lib/qualification/interrupted.pid; changed=0; "
            "for attempt in $(seq 1 900); do "
            "kill -0 $pid; "
            "now=$(dd if=/dev/disk/by-partlabel/root-b bs=4M count=1 status=none | sha256sum); "
            "if test \"$now\" != \"$before\"; then changed=1; break; fi; sleep 1; done; "
            "test $changed -eq 1; kill -KILL $pid; wait $pid 2>/dev/null || true",
            timeout=1200,
        )
        machine.reboot()
        interrupted = read_remote_json(
            machine,
            "/var/lib/profiles/image/state.json",
        )
        if (
            interrupted["running"] != interrupted["default"]
            or interrupted.get("pending") is not None
        ):
            raise RuntimeError("interrupted image staging did not recover atomically")
        self._assert_release(machine, self.predecessor_version, "predecessor")
        self._assert_transition_data(machine)

        predecessor_generation: int | None = None
        candidate_generation: int | None = None
        for _ in range(3):
            machine.ssh("apm upgrade --system --yes", timeout=1800)
            staged = read_remote_json(machine, "/var/lib/profiles/image/state.json")
            if staged.get("pending") != staged.get("default"):
                raise RuntimeError("candidate staging did not publish one pending default")
            if predecessor_generation is None:
                predecessor_generation = staged["running"]
            elif staged["running"] != predecessor_generation:
                raise RuntimeError("repeated update did not begin from the retained predecessor")
            candidate_generation = staged["pending"]
            if (
                not isinstance(predecessor_generation, int)
                or not isinstance(candidate_generation, int)
                or predecessor_generation < 1
                or candidate_generation < 1
                or predecessor_generation == candidate_generation
            ):
                raise RuntimeError("image staging published invalid generation identities")
            candidate = next(
                row
                for row in staged["generations"]
                if row["number"] == candidate_generation
            )
            self._verify_staged_candidate(machine, candidate)
            machine.reboot()
            self._assert_release(machine, self.candidate_version, "candidate")
            committed = read_remote_json(machine, "/var/lib/profiles/image/state.json")
            if (
                committed["running"] != candidate_generation
                or committed["default"] != candidate_generation
                or committed.get("pending") is not None
            ):
                raise RuntimeError("candidate boot was not durably blessed")
            self._assert_transition_data(machine)
            system_state = read_remote_json(machine, "/var/lib/profiles/system/state.json")
            current_system = next(
                row for row in system_state["generations"]
                if row["number"] == system_state["current"]
            )
            if current_system["image_gen_parent"] != candidate_generation:
                raise RuntimeError("configuration was not rebound to the running candidate")
            machine.ssh(f"apm rollback --system --image --generation {predecessor_generation}")
            machine.reboot()
            self._assert_release(machine, self.predecessor_version, "predecessor")
            rolled_back = read_remote_json(machine, "/var/lib/profiles/image/state.json")
            if (
                rolled_back["running"] != predecessor_generation
                or rolled_back["default"] != predecessor_generation
                or rolled_back.get("pending") is not None
            ):
                raise RuntimeError("explicit image rollback did not commit")
            self._assert_transition_data(machine)
            self.counts.update_rollback_cycles += 1

        machine.ssh("apm upgrade --system --yes", timeout=1800)
        staged = read_remote_json(machine, "/var/lib/profiles/image/state.json")
        candidate_generation = staged["pending"]
        candidate = next(
            row for row in staged["generations"]
            if row["number"] == candidate_generation
        )
        self._verify_staged_candidate(machine, candidate)
        candidate_path = candidate["uki_path"]
        machine.ssh(
            "set -eu; mount -o remount,rw /boot; printf '\\000' | dd of="
            + shlex.quote("/boot/" + candidate_path)
            + " bs=1 seek=0 conv=notrunc status=none; sync /boot; mount -o remount,ro /boot"
        )
        for _ in range(4):
            machine.reboot()
        fallback = read_remote_json(machine, "/var/lib/profiles/image/state.json")
        if (
            fallback["running"] != predecessor_generation
            or fallback["default"] != predecessor_generation
            or fallback.get("pending") is not None
        ):
            raise RuntimeError("Secure Boot rejection did not converge to the known-good image")
        self._assert_transition_data(machine)

        mark = machine.serial_mark()
        machine.ssh("set -eu; bootctl set-oneshot recovery-a.conf; sync")
        machine.ssh("systemctl reboot", check=False)
        machine.serial_wait("AOS recovery> ", mark)
        machine.serial_send("6")
        machine.serial_wait("type RESTORE SLOT B to continue: ", mark)
        machine.serial_send("RESTORE SLOT B")
        machine.serial_wait("AOS /var recovery key:", mark)
        machine.serial_send(recovery_key)
        machine.serial_wait("slot B restored", mark, 1800)
        machine.serial_send("2")
        machine.serial_wait("slot A: verified", mark)
        machine.serial_send("4")
        machine.wait_for_ssh(720)
        self._assert_release(machine, self.predecessor_version, "predecessor")
        mark = machine.serial_mark()
        machine.ssh("set -eu; bootctl set-oneshot recovery-b.conf; sync")
        machine.ssh("systemctl reboot", check=False)
        machine.serial_wait("AOS recovery> ", mark)
        machine.serial_send("3")
        machine.serial_wait("slot B: verified", mark)
        machine.serial_send("5")
        machine.wait_for_ssh(720)
        self._assert_release(machine, self.candidate_version, "candidate")
        self._assert_transition_data(machine)

        state = read_remote_json(machine, "/var/lib/profiles/image/state.json")
        if state["running"] != candidate_generation:
            raise RuntimeError("offline-restored candidate did not boot")
        machine.ssh(f"apm rollback --system --image --generation {predecessor_generation}")
        machine.reboot()
        self._stage_registry(machine)
        machine.ssh("apm upgrade --system --yes", timeout=1800)
        staged = read_remote_json(machine, "/var/lib/profiles/image/state.json")
        final_candidate = next(
            row
            for row in staged["generations"]
            if row["number"] == staged["pending"]
        )
        self._verify_staged_candidate(machine, final_candidate)
        machine.reboot()
        self._assert_release(machine, self.candidate_version, "candidate")
        final_state = read_remote_json(machine, "/var/lib/profiles/image/state.json")
        final_generation = final_candidate["number"]
        if (
            final_state["running"] != final_generation
            or final_state["default"] != final_generation
            or final_state.get("pending") is not None
        ):
            raise RuntimeError("post-recovery candidate was not durably blessed")
        self._assert_transition_data(machine)

    @staticmethod
    def _verify_staged_candidate(
        machine: VirtualMachine,
        candidate: dict[str, Any],
    ) -> None:
        uki_path = candidate.get("uki_path")
        if (
            candidate.get("slot") != "B"
            or not isinstance(uki_path, str)
            or re.fullmatch(r"EFI/Linux/[A-Za-z0-9+._-]+[.]efi", uki_path) is None
        ):
            raise RuntimeError("staged candidate does not occupy canonical slot B")

        expected_roothash = candidate.get("root_verity_roothash")
        if not isinstance(expected_roothash, str) or re.fullmatch(
            r"[0-9a-f]{64}", expected_roothash
        ) is None:
            raise RuntimeError("staged candidate omits its canonical verity root")

        media = "/run/qualification-recovery/aos/recovery"
        installed_uki = "/boot/" + uki_path
        machine.ssh(
            "set -eu; "
            "mkdir -p /run/qualification-recovery; "
            "mount -t ext4 -o ro /dev/disk/by-label/AOS-RECOVERY "
            "/run/qualification-recovery; "
            f"test \"$(cat {media}/root.roothash)\" = "
            f"{shlex.quote(expected_roothash)}; "
            f"root_size=$(stat -c %s {media}/root.img); "
            f"verity_size=$(stat -c %s {media}/root.verity); "
            f"test \"$(head -c $root_size /dev/disk/by-partlabel/root-b "
            f"| sha256sum | cut -d ' ' -f1)\" = "
            f"\"$(sha256sum {media}/root.img | cut -d ' ' -f1)\"; "
            f"test \"$(head -c $verity_size "
            f"/dev/disk/by-partlabel/root-b-hash "
            f"| sha256sum | cut -d ' ' -f1)\" = "
            f"\"$(sha256sum {media}/root.verity | cut -d ' ' -f1)\"; "
            f"test \"$(sha256sum {shlex.quote(installed_uki)} "
            f"| cut -d ' ' -f1)\" = "
            f"\"$(sha256sum {media}/uki-b.efi | cut -d ' ' -f1)\"; "
            f"test \"$(sha256sum /boot/EFI/AOS/recovery-b.efi "
            f"| cut -d ' ' -f1)\" = "
            f"\"$(sha256sum {media}/recovery-b.efi | cut -d ' ' -f1)\"; "
            "umount /run/qualification-recovery",
            timeout=1200,
        )

    @staticmethod
    def _assert_transition_data(machine: VirtualMachine) -> None:
        machine.ssh(
            "set -eu; cd /var/lib/qualification; "
            "sha256sum -c transition-state.sha256; "
            "grep -Fx committed-transition-data transition-state"
        )

    @staticmethod
    def _assert_release(machine: VirtualMachine, expected: str, role: str) -> None:
        actual = machine.ssh(
            'set -eu; . /etc/os-release; printf %s "$AOS_RELEASE_ID"'
        ).strip()
        if actual != expected:
            raise RuntimeError(
                f"booted {role} identity {actual!r} differs from {expected!r}"
            )

    def write_report(self) -> None:
        metadata_id, metadata_path = object_with_suffix(self.objects, "metadata")
        metadata = read_json(metadata_path)
        capabilities_digest = digest("aos.image.capabilities/v1", metadata["capabilities"])
        if self.current is None:
            raise RuntimeError("image scenario has no executed guest for its inventory")
        guest = self.current
        guest_kernel = guest.ssh("uname -r").strip()
        if guest_kernel != metadata["capabilities"]["kernel_release"]:
            raise RuntimeError("executed kernel differs from image capability metadata")
        qemu_version = run([QEMU, "--version"]).stdout.splitlines()[0]
        host_kernel = os.uname().release
        host_machine = os.uname().machine
        expected_machine = "x86_64" if PLATFORM == "x86_64-linux" else "aarch64"
        if host_machine != expected_machine:
            raise RuntimeError("executor host architecture differs from the qualification platform")
        host_board = first_identity(
            ["/sys/class/dmi/id/product_name", "/proc/device-tree/model"],
            os.uname().nodename,
        )
        host_chipset = first_identity(
            ["/sys/class/dmi/id/board_name", "/sys/class/dmi/id/sys_vendor"],
            host_board,
        )
        host_cpu = cpu_identity(pathlib.Path("/proc/cpuinfo"))
        guest_cpu = cpu_identity_text(guest.ssh("cat /proc/cpuinfo"))
        machine_name = "q35" if PLATFORM == "x86_64-linux" else "virt"
        machine_version = qemu_machine_version(machine_name)
        acceleration = "kvm" if PLATFORM == "x86_64-linux" else "tcg"
        cpu_model = "host" if PLATFORM == "x86_64-linux" else "max"
        firmware_vendor = guest.ssh(
            "cat /sys/firmware/efi/fw_vendor"
        ).strip()
        if not firmware_vendor:
            raise RuntimeError("guest did not expose its UEFI firmware vendor")
        firmware_build = pathlib.Path(FIRMWARE_CODE).parents[1].name
        firmware = f"{firmware_vendor} ({firmware_build})"
        block_address = guest.ssh(
            "basename $(readlink -f /sys/class/block/vda/device)"
        ).strip()
        block_driver = guest.ssh(
            "basename $(readlink -f /sys/class/block/vda/device/driver)"
        ).strip()
        network_identity = guest.ssh(
            "for interface in /sys/class/net/*; do "
            "test $(basename $interface) = lo || { "
            "basename $(readlink -f $interface/device); "
            "basename $(readlink -f $interface/device/driver); break; }; done"
        ).splitlines()
        if (
            block_driver != "virtio_blk"
            or len(network_identity) != 2
            or network_identity[1] != "virtio_net"
        ):
            raise RuntimeError("guest virtio devices do not have the required bound drivers")
        devices = [
            {
                "address": block_address,
                "bus": "virtio",
                "vendor": None,
                "product": None,
                "revision": None,
                "driver": block_driver,
                "firmware_revision": None,
            },
            {
                "address": network_identity[0],
                "bus": "virtio",
                "vendor": None,
                "product": None,
                "revision": None,
                "driver": network_identity[1],
                "firmware_revision": None,
            },
        ]
        environment = {
            "schema_version": "aos.release.environment-inventory/v1",
            "layers": [
                {
                    "platform": PLATFORM,
                    "backend": {"kind": "physical", "board": host_board, "chipset": host_chipset},
                    "cpu": host_cpu,
                    "kernel_release": host_kernel,
                },
                {
                    "platform": PLATFORM,
                    "backend": {
                        "kind": "qemu",
                        "machine": machine_name,
                        "machine_version": machine_version,
                        "version": qemu_version,
                        "accelerator": acceleration,
                        "cpu_model": cpu_model,
                    },
                    "cpu": guest_cpu,
                    "kernel_release": guest_kernel,
                },
            ],
            "boot": "systemd-boot-uki",
            "firmware": firmware,
            "security": {
                "secure_boot": True,
                "measured_boot": True,
                "verity": True,
                "encrypted_state": True,
                "persistent_firmware": True,
            },
            "resources": {"cpus": 2, "memory_mib": 8192, "disk_mib": 32768},
            "devices": devices,
            "image_capabilities_digest": capabilities_digest,
        }
        details = {
            check: {"passed": True, "detail": CHECK_DETAILS[check]}
            for check in self.case["checks"]
        }
        finished = time.time()
        report = {
            "schema_version": "aos.release.qualification-scenario-report/v1",
            "registry": self.request["registry"],
            "release_id": self.request["release_id"],
            "staging_receipt_digest": self.request["staging_receipt_digest"],
            "manifest_digest": self.request["manifest_digest"],
            "case_digest": digest("aos.release.qualification-case/v2", self.case),
            "started_at": self.started_at,
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished)),
            "observed_seconds": int(finished - self.started),
            "checks": details,
            "operations": {
                "reboot_cycles": self.counts.reboot_cycles,
                "cold_boot_cycles": self.counts.cold_boot_cycles,
                "update_rollback_cycles": self.counts.update_rollback_cycles,
                "workload_operations": self.counts.workload_operations,
                "data_integrity_failures": 0,
            },
            "environment": environment,
            "assessment": self.assessment,
            "capabilities": {"metadata_artifact": metadata_id, "metadata": metadata},
        }
        if (
            self.counts.reboot_cycles < 10
            or self.counts.cold_boot_cycles < 3
            or self.counts.update_rollback_cycles < 3
        ):
            raise RuntimeError("image operation floors were not reached")
        REPORT.write_bytes(canonical(report))

    def run(self) -> None:
        try:
            self.validate_inputs()
            self.verify_formats()
            self.exercise_candidate()
            self.exercise_transition()
            self.write_report()
        finally:
            if self.current is not None:
                self.current.stop_processes()


def read_remote_json(machine: VirtualMachine, path: str) -> Any:
    return json.loads(machine.ssh(f"cat {path}"))


def cpu_identity(path: pathlib.Path) -> dict[str, Any]:
    return cpu_identity_text(path.read_text(encoding="utf-8", errors="replace"))


def first_identity(paths: list[str], fallback: str) -> str:
    for name in paths:
        path = pathlib.Path(name)
        try:
            value = path.read_text(encoding="utf-8", errors="replace").rstrip("\x00\n ")
        except OSError:
            continue
        if value:
            return value
    return fallback


def qemu_machine_version(machine: str) -> str:
    output = run([QEMU, "-machine", "help"]).stdout
    line = None
    for candidate in output.splitlines():
        fields = candidate.split(maxsplit=1)
        if fields and fields[0] == machine:
            line = candidate
            break
    if line is None:
        raise RuntimeError(f"QEMU does not advertise the selected {machine!r} machine")
    alias = re.search(r"\(alias of ([^)]+)\)", line)
    return alias.group(1) if alias is not None else machine


def cpu_identity_text(text: str) -> dict[str, Any]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields.setdefault(key.strip(), value.strip())
    features = fields.get("flags", fields.get("Features", "")).split()
    vendor = fields.get("vendor_id", fields.get("CPU implementer", "unknown"))
    model = fields.get("model name", fields.get("CPU part", os.uname().machine))
    return {
        "vendor": vendor,
        "model": model,
        "sku": None,
        "revision": fields.get("stepping", fields.get("CPU revision")),
        "microcode": fields.get("microcode"),
        "features": sorted(set(features)),
    }


CHECK_DETAILS = {
    "anonymous-download-and-resume": (
        "The candidate graph was downloaded anonymously and its largest object "
        "completed through two exact HTTP ranges."
    ),
    "disk-format-equivalence": (
        "Raw, QCOW2, VMDK, and VHD decoded to the exact published logical disk."
    ),
    "uefi-boot": (
        "The exact published disk booted through the target UEFI and "
        "systemd-boot UKI path."
    ),
    "repeated-warm-and-cold-boot": (
        "Ten warm boots and three complete QEMU, firmware, and TPM power "
        "cycles completed."
    ),
    "provisioning": (
        "First boot committed the platform host configuration and durable "
        "provisioning audit."
    ),
    "host-configuration": (
        "The platform-authenticated host module enabled the qualification "
        "SSH and network policy."
    ),
    "ssh-dns-time-network": (
        "SSH control, DNS resolution, HTTPS reachability, DHCP networking, "
        "and synchronized time passed."
    ),
    "boot-integrity-and-encrypted-state": (
        "Secure Boot enforced, TPM state persisted, dm-verity supplied the "
        "read-only root, and /var used LUKS."
    ),
    "no-fixture-authorities": (
        "The published image exposed no fleet test agent or fixture authority marker."
    ),
    "configuration-activation-and-rollback": (
        "Two host generations activated, malformed input was rejected, and "
        "explicit configuration rollback restored the first."
    ),
    "package-install-change-remove-recover": (
        "The signed nginx root installed, its configuration changed, removal "
        "withdrew it, and reconciliation restored it."
    ),
    "nginx-http-tls": (
        "The installed nginx served the committed payload over HTTP and "
        "certificate-verified TLS."
    ),
    "persistent-workload": (
        "The nginx state and operation journal remained on persistent /var storage."
    ),
    "reboot-persistence": (
        "Every warm, cold, update, rollback, fallback, and recovery boot "
        "retained acknowledged state."
    ),
    "bounded-generation-retention": (
        "System generation cleanup retained the active generation within the "
        "configured keep bound."
    ),
    "disk-and-memory-pressure": (
        "Bounded disk exhaustion and a memory-capped transient unit failed "
        "without losing the workload state."
    ),
    "preceding-image-identity": (
        "The booted predecessor release ID matched the frozen verified "
        "predecessor manifest."
    ),
    "upgrade": "APM authenticated and staged the public candidate into the inactive A/B slot.",
    "configuration-rebind": (
        "Candidate boots rebound the active configuration generation to the "
        "running image generation."
    ),
    "boot-blessing": (
        "Successful candidate boots cleared pending state and published the "
        "candidate as the durable default."
    ),
    "interrupted-writes-and-reboots": (
        "A killed live staging operation followed by reboot converged to a "
        "committed image with intact data."
    ),
    "automatic-fallback": (
        "A corrupted candidate UKI was rejected under Secure Boot and the "
        "known-good predecessor resumed."
    ),
    "explicit-rollback": (
        "APM selected and booted the retained predecessor as the durable image default."
    ),
    "repeated-update-and-rollback": (
        "Three predecessor-to-candidate updates and explicit rollbacks completed."
    ),
    "committed-data-preserved": (
        "The fsynced transition marker survived every update, rollback, "
        "fallback, and offline recovery operation."
    ),
    "offline-recovery": (
        "Recovery A authenticated removable signed media, restored slot B, "
        "and Recovery B verified it before one-shot boot."
    ),
    "update-after-recovery": (
        "After offline restoration the host rolled back and completed another "
        "signed public candidate update."
    ),
}


if __name__ == "__main__":
    Scenario().run()
