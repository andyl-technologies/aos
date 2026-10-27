# SPDX-License-Identifier: MIT
"""Audits current x86 root process bytes under a closed guest-asset policy.

The common image auditor checks genuine image/task/FD/map custody. This policy
admits only the two original private Linux files and fixed source-bound loader.
No portable scope flag, successful boot or audit creates general device parity.
"""

import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    if name in sys.modules:
        raise ValueError("x86 closure helper was already loaded")
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


core = load("crucible_x86_root_image_core", "process-image-audit-core.py")
assets = load("crucible_x86_root_asset_custody", "native-model-assets.py")
loader = load("crucible_x86_root_loader", "x86-linux-loader.py")


class X86RootAssetPolicy:
    """Admits only the selected original x86 kernel and initramfs mappings."""

    profile_id = "x86-linux-pc-atomic-root-functional-v1"
    guest_isa = "x86_64"
    maximum_asset_bytes = 1024 * 1024 * 1024

    def __init__(self, request):
        root = Path(request["modeled_root"])
        metadata = root.lstat()
        if (not root.is_absolute() or root.resolve() != root
                or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
                or not core._inside(str(root), os.path.realpath(request["owned_root"]))):
            raise ValueError("x86 modeled assets lack canonical private ownership")
        self.paths = {str(root / name) for name in ("kernel.elf", "initrd.img")}
        scope = request["model_scope"]
        if (type(scope) is not dict or set(scope) != {
                "schema", "model_id", "full_system", "complete_process_closure_qualified",
                "cpu_timing_qualified", "guest_readiness_qualified", "device_parity_qualified",
                "guest_assets", "configuration_tree", "loader"}
                or scope["schema"] != "crucible.gem5.model-scope.v1"
                or scope["model_id"] != self.profile_id or scope["full_system"] is not True
                or any(scope[field] is not False for field in (
                    "complete_process_closure_qualified", "cpu_timing_qualified",
                    "guest_readiness_qualified", "device_parity_qualified"))):
            raise ValueError("x86 root scope is absent, foreign or overclaims qualification")
        bindings = scope["guest_assets"]
        if type(bindings) is not dict or set(bindings) != {"kernel", "initramfs"}:
            raise ValueError("x86 guest asset roles differ")
        if type(request["assets"]) is not list or len(request["assets"]) > 4096:
            raise ValueError("x86 asset role census exceeds finite credit")
        records = {}
        for record in request["assets"]:
            if (type(record) is not dict or set(record) != {"path", "sha256"}
                    or record["path"] in records):
                raise ValueError("x86 asset is duplicate or has unknown fields")
            records[record["path"]] = record["sha256"]
        for role, name in (("kernel", "kernel.elf"), ("initramfs", "initrd.img")):
            binding = bindings[role]
            if (type(binding) is not dict or set(binding) != {"bytes", "sha256"}
                    or type(binding["sha256"]) is not str
                    or core.DIGEST.fullmatch(binding["sha256"]) is None
                    or not 0 < core.integer(binding["bytes"]) <= self.maximum_asset_bytes
                    or records.get(str(root / name)) != binding["sha256"]):
                raise ValueError("x86 guest asset differs from measured closure role")
            metadata = (root / name).lstat()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
                    or metadata.st_size != core.integer(binding["bytes"])):
                raise ValueError("x86 guest asset extent or private custody differs")
        if assets.configuration_tree(root / "configs") != scope["configuration_tree"]:
            raise ValueError("x86 configuration differs from captured source scope")
        plan = loader.validate_loader(root / "kernel.elf", root / "initrd.img")
        if plan.describe() != scope["loader"]:
            raise ValueError("x86 loader geometry differs from the actual private guest files")

    def accepts_map(self, mapping, assets, root):
        """Checks the same finite read-only private file-map policy as the image core."""
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
        raise ValueError("x86 root closure request exceeds finite credit")
    request = json.loads(raw)
    policy = X86RootAssetPolicy(request)
    result = core.audit(request, policy)
    result["full_system_admission_qualified"] = False
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
