"""Executes local image boot checks with the existing platform-aware transport.

The release Scenario and its signed/encrypted admission requirements remain
unchanged. This module supplies native host tools to its VirtualMachine class
and checks only the explicitly declared image capabilities and local lifecycle.
"""

from __future__ import annotations

import base64
import importlib
import os
from pathlib import Path
import re
import shlex
import struct
from typing import Any

from image_matrix import digest, hash_file, require, run, validate_security


EFI_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


def transport(manifest: dict[str, Any]) -> Any:
    """Loads the VM helper with native tools, without creating a release Scenario."""

    tools = manifest["tools"]
    environment = {
        "PLATFORM": manifest["platform"],
        "QEMU": tools["qemu"],
        "QEMU_IMG": tools["qemuImg"],
        "FIRMWARE_CODE": manifest["firmwareCode"],
        "FIRMWARE_VARS": manifest["firmwareVars"],
        "SWTPM": tools["swtpm"],
        "SGDISK": tools["sgdisk"],
        "ZSTD": tools["zstd"],
        "SSH": tools["ssh"],
        "SCP": tools["scp"],
        "SSH_KEYGEN": tools["sshKeygen"],
        "OBJCOPY": tools["objcopy"],
        # These globals belong exclusively to the release Scenario. Empty
        # values prevent accidentally borrowing a release assessment or tool.
        "ASSESSMENTS": "",
        "STAGING_HUB_URL": "",
        "MKE2FS": "",
        "OPENSSL": "",
        "NIX_STORE": "",
    }
    os.environ.update({f"AOS_QUALIFICATION_{name}": value for name, value in environment.items()})
    return importlib.import_module("qualification_image")


def pe_command_line(path: Path) -> str:
    """Reads the bounded PE command-line section without a target objcopy."""

    size = path.stat().st_size
    with path.open("rb") as source:
        header = source.read(64)
        require(len(header) == 64 and header[:2] == b"MZ", "UKI has no DOS header")
        pe_offset = struct.unpack_from("<I", header, 60)[0]
        require(pe_offset + 24 <= size, "UKI PE header exceeds file")
        source.seek(pe_offset)
        coff = source.read(24)
        require(coff[:4] == b"PE\0\0", "UKI has no PE signature")
        sections = struct.unpack_from("<H", coff, 6)[0]
        optional_size = struct.unpack_from("<H", coff, 20)[0]
        table = pe_offset + 24 + optional_size
        require(0 < sections <= 128 and table + 40 * sections <= size, "invalid UKI section table")
        matches = []
        for index in range(sections):
            source.seek(table + 40 * index)
            section = source.read(40)
            if section[:8].rstrip(b"\0") != b".cmdline":
                continue
            virtual_size, _, raw_size, raw_offset = struct.unpack_from("<IIII", section, 8)
            require(0 < virtual_size <= raw_size <= 1024 * 1024, "unbounded UKI command line")
            require(raw_offset + raw_size <= size, "UKI command line exceeds file")
            source.seek(raw_offset)
            matches.append(source.read(virtual_size).rstrip(b"\0").decode("ascii"))
        require(len(matches) == 1, "UKI must contain one command-line section")
        return matches[0]


def root_hash_from_uki(system: dict[str, Any], metadata: dict[str, Any]) -> str | None:
    """Binds the observed dm-verity root to the exact image's UKI."""

    uki = Path(system["images"]["raw"]) / "uki-a.efi"
    require(hash_file(uki) == metadata["uki"]["sha256"], "sidecar UKI differs from image metadata")
    matches = re.findall(r"(?:^| )roothash=([0-9a-f]{64})(?= |$)", pe_command_line(uki))
    if system["expected"]["security"]["verity"]:
        require(len(matches) == 1, "verity image lacks one UKI root hash")
        return matches[0]
    require(not matches, "non-verity image unexpectedly declares a root hash")
    return None


def guest(machine: Any, command: str, **options: Any) -> str:
    """Stops multi-command guest checks at their first failed assertion."""

    return machine.ssh("set -eu; " + command, **options)


def guest_write(machine: Any, path: str, contents: str) -> None:
    """Writes a test input through SSH without shell-interpreting its contents."""

    encoded = base64.b64encode(contents.encode()).decode("ascii")
    guest(machine, f"printf '%s' {shlex.quote(encoded)} | base64 -d > {shlex.quote(path)}")


def efivar(machine: Any, name: str) -> int:
    """Reads the byte value following an EFI variable's attributes."""

    return int(guest(machine, f"od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/{name}-{EFI_GUID}").strip())


def enroll(machine: Any, system: dict[str, Any]) -> None:
    """Enters enforcing Secure Boot using the image's declared enrollment inputs."""

    require(efivar(machine, "SetupMode") == 1, "firmware did not begin in Setup Mode")
    require(efivar(machine, "SecureBoot") == 0, "fresh firmware unexpectedly enforces Secure Boot")
    tools = system["guestTools"]
    require(
        bool(tools.get("enroll") and tools.get("enrollAuthDir")),
        "signed image lacks enrollment inputs",
    )
    # There is no host-store mount: these paths must be in the image itself.
    guest(machine, f"test -x {shlex.quote(tools['enroll'])}")
    for variable in ("db", "KEK", "PK"):
        blob = tools["enrollAuthDir"] + "/" + variable + ".auth"
        guest(machine, f"test -s {shlex.quote(blob)}")
    guest(machine, shlex.quote(tools["enroll"]), timeout=300)
    require(efivar(machine, "SetupMode") == 0, "PK enrollment did not exit Setup Mode")
    machine.reboot()
    require(efivar(machine, "SecureBoot") == 1, "signed image did not boot enforcing")


def observed_security(machine: Any, expected: dict[str, Any], root_hash: str | None) -> dict[str, Any]:
    """Observes mounts and enforcement, including a denied lockdown operation."""

    root_filesystem = guest(machine, "findmnt -n -o FSTYPE /").strip()
    root_options = guest(machine, "findmnt -n -o OPTIONS /").strip().split(",")
    # Mapper nodes need not be symlinks into /dev/dm-*. Use the mounted kernel
    # device number, with raw output to exclude findmnt's column padding.
    root_uuid = guest(
        machine,
        'device=$(findmnt -n -r -o MAJ:MIN /); '
        'cat "/sys/dev/block/$device/dm/uuid" 2>/dev/null || true'
    ).strip()
    observed_hashes = re.findall(
        r"(?:^| )roothash=([0-9a-f]{64})(?= |$)", guest(machine, "cat /proc/cmdline").strip(),
    )
    verity = root_uuid.startswith(("CRYPT-VERITY", "verity-"))
    if expected["verity"]:
        require(
            observed_hashes == [root_hash] and verity,
            f"running dm-verity root differs from the exact image UKI: "
            f"expected hash={root_hash!r}, observed hashes={observed_hashes!r}, "
            f"root device UUID={root_uuid!r}",
        )
    else:
        require(not observed_hashes and not verity, "unexpected dm-verity root")

    var_uuid = guest(
        machine,
        'device=$(findmnt -n -r -o MAJ:MIN /var); '
        'cat "/sys/dev/block/$device/dm/uuid" 2>/dev/null || true'
    ).strip()
    guest(machine, "findmnt -n -o OPTIONS /var | grep -Eq '(^|,)rw(,|$)'")
    lockdown_text = guest(machine, "cat /sys/kernel/security/lockdown 2>/dev/null || true").strip()
    lockdown_modes = re.findall(r"\[([^]]+)\]", lockdown_text)
    require(len(lockdown_modes) <= 1, "ambiguous lockdown state")
    lockdown = lockdown_modes[0] if lockdown_modes else "none"
    rejected = False
    if expected["lockdown"] != "none":
        guest(
            machine,
            "test -c /dev/mem; "
            "if dd if=/dev/mem of=/dev/null bs=1 count=1 >/run/image-matrix-lockdown.log 2>&1; "
            "then cat /run/image-matrix-lockdown.log; exit 1; fi"
        )
        rejected = True

    def succeeds(command: str) -> bool:
        return guest(machine, f"if {command}; then printf yes; else printf no; fi").strip() == "yes"

    observation = {
        "rootFilesystem": root_filesystem,
        "readOnlyRoot": "ro" in root_options and "rw" not in root_options,
        "verity": verity,
        "secureBoot": efivar(machine, "SecureBoot") == 1,
        "measuredBoot": succeeds("test -s /run/systemd/tpm2-pcr-signature.json"),
        "encryptedState": var_uuid.startswith("CRYPT-LUKS2-"),
        "tpm": succeeds("test -c /dev/tpm0 && test -d /sys/class/tpm/tpm0"),
        "measurementIndexActive": succeeds("systemctl is-active --quiet aos-image-measurement-index.service"),
        "lockdown": lockdown,
        "lockdownRejection": rejected,
    }
    validate_security(expected, observation)
    return observation


def observe(machine: Any, system: dict[str, Any], phase: str, root_hash: str | None) -> dict[str, Any]:
    """Captures the immutable image identity and current security state."""

    guest(
        machine,
        "test -d /sys/firmware/efi; "
        "systemctl is-active --quiet multi-user.target sshd.service aos-config.target",
    )
    identity = guest(
        machine,
        '. /etc/os-release; printf "%s\\n%s\\n" "$VERSION_ID" "$AOS_MODULE_ABI"',
    ).splitlines()
    require(len(identity) == 2, "guest os-release identity is incomplete")
    return {
        "phase": phase,
        "machine": guest(machine, "uname -m").strip(),
        "kernel": guest(machine, "uname -r").strip(),
        "version": identity[0],
        "moduleAbi": int(identity[1]),
        "toplevel": guest(machine, "readlink /aos-toplevel").strip(),
        "security": observed_security(machine, system["expected"]["security"], root_hash),
        "configuration": configuration_identity(machine, require_runtime=phase != "initial"),
    }


def configuration_checks(machine: Any, system: dict[str, Any]) -> dict[str, Any]:
    """Applies valid host configuration and proves an invalid replacement is inert."""

    apm = shlex.quote(system["guestTools"]["apm"])
    prefix = "XDG_CACHE_HOME=/var/cache/aos-image-matrix " + apm
    guest(machine, "mkdir -p /run/image-matrix /var/cache/aos-image-matrix /var/lib/image-matrix")
    module = '{ environment.etc."image-matrix-active".text = "matrix-active\\n"; }\n'
    guest_write(machine, "/run/image-matrix/10-proof.nix", module)
    initial = read_guest_generation(machine)
    guest(machine, f"{prefix} config add /run/image-matrix/10-proof.nix")
    guest(machine, f"{prefix} config apply --eval-root /run/image-matrix/apply", timeout=1800)
    configured = read_guest_generation(machine)
    require(configured != initial, "valid configuration did not create a new generation")
    guest(machine, "grep -Fx matrix-active /etc/image-matrix-active; systemctl is-active --quiet sshd.service")

    guest_write(machine, "/run/image-matrix/invalid.nix", "{ aos.networking.hostName = []; }\n")
    guest(machine, f"{prefix} config replace 10-proof.nix /run/image-matrix/invalid.nix")
    guest(
        machine,
        f"if {prefix} config apply --eval-root /run/image-matrix/invalid "
        ">/run/image-matrix/rejection.log 2>&1; then "
        "cat /run/image-matrix/rejection.log; "
        "echo 'invalid configuration was accepted' >&2; exit 1; fi; "
        "cat /run/image-matrix/rejection.log; "
        "grep -F 'config eval failed:' /run/image-matrix/rejection.log; "
        "grep -F 'cannot coerce a list to a string' /run/image-matrix/rejection.log",
        timeout=1800,
    )
    require(read_guest_generation(machine) == configured, "rejected configuration changed the active generation")
    guest(machine, "grep -Fx matrix-active /etc/image-matrix-active; systemctl is-active --quiet sshd.service")
    guest(machine, f"{prefix} config discard")
    guest(machine, "printf 'matrix-persistent\\n' > /var/lib/image-matrix/proof; sync /var/lib/image-matrix/proof")
    return configuration_identity(machine)


def read_guest_generation(machine: Any) -> int:
    """Reads the active host-configuration generation without guest JSON tools."""

    import json

    generation = json.loads(guest(machine, "cat /var/lib/profiles/system/state.json"))["current"]
    require(type(generation) is int, "active configuration generation is not an integer")
    return generation


def configuration_identity(machine: Any, *, require_runtime: bool = True) -> dict[str, Any]:
    """Identifies the committed runtime module set and platform host input."""

    import json

    generation = read_guest_generation(machine)
    manifest = json.loads(guest(machine, f"cat /var/lib/profiles/system/gen-{generation}/manifest.json"))
    inputs = manifest["inputs"]
    if require_runtime:
        require("runtime_modules" in inputs, "configured generation lacks runtime-module binding")
    return {
        "generation": generation,
        "runtimeModulesDigest": digest(inputs.get("runtime_modules")),
        "hostNixDigest": digest(inputs["host_nix"]),
    }


def persistent_state(machine: Any, configured: dict[str, Any]) -> None:
    """Checks data and inputs while allowing normal boot-time reevaluation."""

    guest(
        machine,
        "grep -Fx matrix-persistent /var/lib/image-matrix/proof; "
        "grep -Fx matrix-active /etc/image-matrix-active",
    )
    current = configuration_identity(machine)
    require(current["generation"] >= configured["generation"], "reboot reverted the committed configuration")
    for field in ("runtimeModulesDigest", "hostNixDigest"):
        require(current[field] == configured[field], f"reboot changed committed configuration input: {field}")


def boot_system(
    manifest: dict[str, Any], system: dict[str, Any], logical: Path,
    metadata: dict[str, Any], work: Path,
) -> dict[str, Any]:
    """Boots one exact logical image and exercises its declared capabilities."""

    module = transport(manifest)
    root_hash = root_hash_from_uki(system, metadata)
    key = work / "ssh-key"
    run([manifest["tools"]["sshKeygen"], "-q", "-t", "ed25519", "-N", "", "-C", "image-matrix", "-f", str(key)])
    public_key = key.with_suffix(".pub").read_text().strip()
    role = system["expected"]["role"]
    require(role in {None, "edge", "server"}, "unsupported host role")
    host_config = work / "host.nix"
    role_config = "" if role is None else f"  aos.roles.{role}.enable = true;\n"
    host_config.write_text(
        "{\n" + role_config +
        '  aos.services.ssh.enable = true;\n'
        '  aos.services.ssh.permitRootLogin = "prohibit-password";\n'
        '  aos.networking.hostName = "image-matrix";\n'
        f'  environment.etc."ssh/authorized_keys/root".text = "{public_key}";\n'
        "}\n"
    )
    counts = module.Counts()
    machine = module.VirtualMachine("image-guest", logical, host_config, key, counts)
    try:
        machine.start()
        guest(machine, f"test -x {shlex.quote(system['guestTools']['apm'])}")
        if system["expected"]["security"]["secureBoot"]:
            enroll(machine, system)
        observations = [observe(machine, system, "initial", root_hash)]
        guest(
            machine,
            'test -s /var/lib/aos-provisioning/audit.json; '
            'test "$(cat /proc/sys/kernel/hostname)" = image-matrix',
        )
        configured = configuration_checks(machine, system)
        machine.reboot()
        persistent_state(machine, configured)
        observations.append(observe(machine, system, "warm", root_hash))
        machine.power_cycle()
        persistent_state(machine, configured)
        observations.append(observe(machine, system, "cold", root_hash))
        return {
            "logicalDiskSha256": metadata["logicalDiskSha256"],
            "formatBinding": "decoded-logical-disk",
            "warmBoots": counts.reboot_cycles,
            "coldBoots": counts.cold_boot_cycles,
            "checks": {
                "uefi": True,
                "provisioning": True,
                "configurationActivation": True,
                "configurationRejection": True,
                "persistentState": True,
            },
            "observations": observations,
            "configuration": configured,
            "imageUpdateClaims": False,
        }
    finally:
        machine.stop_processes()
