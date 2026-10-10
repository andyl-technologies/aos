# SPDX-License-Identifier: MIT
"""Audits the finite ARM process-image mechanism without granting admission.

The selected policy admits only the three private immutable source-owned guest
asset roles. It does not admit external shared RAM, device descriptors, arbitrary
asset paths, or a public full-system capability. Installed model qualification
remains a separate source-authenticated contract.
"""

import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


spec = importlib.util.spec_from_file_location(
    "crucible_process_image_core", Path(__file__).with_name("process-image-audit-core.py")
)
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
asset_spec = importlib.util.spec_from_file_location(
    "crucible_model_asset_custody", Path(__file__).with_name("native-model-assets.py")
)
asset_custody = importlib.util.module_from_spec(asset_spec)
asset_spec.loader.exec_module(asset_custody)


class ArmFunctionalAssetPolicy:
    """Selects exact finite model asset roles for the stopped ARM mechanism."""

    profile_id = "arm-linux-vexpress-atomic-closed-ninep-functional-v1"
    guest_isa = "aarch64"
    maximum_asset_bytes = 1024 * 1024 * 1024

    def __init__(self, request):
        root = Path(request["modeled_root"])
        metadata = root.lstat()
        if (not root.is_absolute() or root.resolve() != root
                or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
                or not core._inside(str(root), os.path.realpath(request["owned_root"]))):
            raise ValueError("modeled asset root is not canonically privately owned")
        self.paths = {str(root / name) for name in ("kernel.elf", "initrd.img", "boot_v2.arm64")}
        scope = request["model_scope"]
        if (not isinstance(scope, dict) or scope.get("schema") != "crucible.gem5.model-scope.v1"
                or scope.get("model_id") != self.profile_id or scope.get("full_system") is not True
                or scope.get("complete_process_closure_qualified") is not False
                or scope.get("cpu_timing_qualified") is not False
                or scope.get("guest_readiness_qualified") is not False):
            raise ValueError("full-system mechanism scope is absent or overclaims qualification")
        if (scope.get('device_parity_qualified') is not False
                or scope.get('closed_terminal_monitor') is not True
                or scope.get('external_serial_route') is not False
                or scope.get('native_device_execution_parent') != '17'
                or scope.get('native_terminal_parent') != '0'
                or scope.get('device_slots') != ['ninep:0x1c130000', 'block:0x1c140000']
                or scope.get('diagnostic_scope') != 'native-event-device-terminal-and-closed-ninep-block-metadata-v1'
                or scope.get('diagnostic_maximum_object_bytes') != '4194304'
                or scope.get('maximum_terminal_rows') != '32768'
                or scope.get('maximum_native_callbacks') != '16000000'
                or scope.get('maximum_native_tick') != '1000000000000'):
            raise ValueError('device mechanism scope differs from source-owned finite closed model')
        expected_backend = {
            'schema': 'crucible.gem5.closed-block-backend-policy.v1',
            'backing_bytes': '1048576', 'initial_bytes': 'zero',
            'maximum_original_commands': '128', 'maximum_payload_bytes': '4096',
            'reaction_delay_ps': '10000', 'completion_delay_ps': '1',
            'execution_parent': '17', 'backend_parent': '23',
            'diagnostic_maximum_bytes': '65536', 'external_inputs_admitted': False,
        }
        if scope.get('closed_block_backend') != expected_backend:
            raise ValueError('closed disk model differs from exact owned backend policy')
        expected_ninep = {
            'schema': 'crucible.gem5.closed-ninep-backend-policy.v1',
            'mount_tag': 'crucible', 'protocol': '9P2000.L',
            'maximum_original_commands': '128', 'maximum_message_bytes': '4096',
            'maximum_file_bytes': '65536', 'maximum_fids': '64',
            'reaction_delay_ps': '10000', 'completion_delay_ps': '1',
            'execution_parent': '17', 'backend_parent': '23',
            'diagnostic_maximum_bytes': '65536', 'external_inputs_admitted': False,
        }
        if scope.get('closed_ninep_backend') != expected_ninep:
            raise ValueError('closed server model differs from the exact owned tree policy')
        bindings = scope.get("guest_assets")
        if not isinstance(bindings, dict) or set(bindings) != {"kernel", "initramfs", "firmware"}:
            raise ValueError("model guest asset roles are incomplete")
        if not isinstance(request["assets"], list) or len(request["assets"]) > 4096:
            raise ValueError("model asset role census exceeds finite credit")
        records = {}
        for record in request["assets"]:
            if (not isinstance(record, dict) or set(record) != {"path", "sha256"}
                    or record["path"] in records):
                raise ValueError("model asset role is duplicate or has unknown fields")
            records[record["path"]] = record["sha256"]
        for role, name in (("kernel", "kernel.elf"), ("initramfs", "initrd.img"),
                           ("firmware", "boot_v2.arm64")):
            body = bindings[role]
            if (not isinstance(body, dict) or set(body) != {"bytes", "sha256"}
                    or not isinstance(body["sha256"], str)
                    or core.DIGEST.fullmatch(body["sha256"]) is None
                    or not 0 < core.integer(body["bytes"]) <= self.maximum_asset_bytes
                    or records.get(str(root / name)) != body["sha256"]):
                raise ValueError("model asset binding differs from its measured closure role")
            metadata = (root / name).lstat()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
                    or metadata.st_size != core.integer(body["bytes"])):
                raise ValueError("model asset extent or private custody differs from its role")
        if asset_custody.configuration_tree(root / "configs") != scope.get("configuration_tree"):
            raise ValueError("model configuration tree differs from its captured scope")

    def accepts_map(self, mapping, assets, root):
        """Checks one exact read-only private guest asset mapping and extent."""
        name = mapping["name"]
        if (mapping["permissions"] != "r--s" or name not in self.paths
                or name not in assets or not core._inside(name, root)):
            return False
        size = core.integer(assets[name]["bytes"])
        offset = mapping["offset"]
        extent = mapping["end"] - mapping["start"]
        page = os.sysconf("SC_PAGE_SIZE")
        if (not 0 < size <= self.maximum_asset_bytes or not 0 <= offset < size
                or offset % page or not 0 < extent <= self.maximum_asset_bytes):
            return False
        return extent <= ((size - offset + page - 1) // page) * page


def main():
    raw = sys.stdin.buffer.read(core.MAX_REQUEST + 1)
    if len(raw) > core.MAX_REQUEST:
        raise ValueError("full-system closure request exceeds finite credit")
    request = json.loads(raw)
    policy = ArmFunctionalAssetPolicy(request)
    result = core.audit(request, policy)
    result["full_system_admission_qualified"] = False
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
