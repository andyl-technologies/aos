"""Co-retains source-built x86 firmware without replacing legacy QEMU data."""

from pathlib import Path
import hashlib
import json
import shutil
import sys


PRODUCTS = (
    "multiboot_dma.bin", "linuxboot_dma.bin", "kvmvapic.bin", "pvh.bin",
    "bios.bin", "bios-256k.bin", "bios-microvm.bin", "vgabios.bin",
    "vgabios-stdvga.bin", "vgabios-cirrus.bin", "vgabios-vmware.bin",
    "vgabios-qxl.bin", "vgabios-virtio.bin", "vgabios-bochs-display.bin",
    "vgabios-ramfb.bin", "vgabios-ati.bin",
)
BUILTINS = {
    "linuxboot_dma.bin": (1536, "eb55c0942c43e0a4b6615b22ae3ea1dd2fcd1b1868255f65a1018fe63cc865e3"),
    "kvmvapic.bin": (9216, "6cec4aeb2119374152fa0ffdb76a30ff4f44fea12cc77ed0d3948335a7b5a7a3"),
}


def main():
    provider, corresponding_source, output = map(Path, sys.argv[1:])
    data = provider / "share/qemu"
    source = corresponding_source / "share/qemu-firmware-source"
    destination = output / "share/qemu/crucible-source-built-x86"

    actual_names = {entry.name for entry in data.iterdir()}
    if actual_names != set(PRODUCTS) or not source.is_dir():
        raise ValueError("The complete source-built provider roster is unavailable")
    for required in ("qemu-11.1.1.tar.xz", "qemu-firmware-x86.nix", "COPYING", "LICENSE"):
        if not (source / required).is_file():
            raise ValueError("Required firmware corresponding source is unavailable: " + required)

    # Authenticate every input before publishing any selected-profile copy.
    records = []
    for name in PRODUCTS:
        original = data / name
        if original.is_symlink() or not original.is_file():
            raise ValueError("Unexpected firmware product type: " + name)
        body = original.read_bytes()
        identity = (len(body), hashlib.sha256(body).hexdigest())
        if not body or name in BUILTINS and identity != BUILTINS[name]:
            raise ValueError("Selected builtin differs from its compiled source pin: " + name)
        records.append({"name": name, "bytes": identity[0], "sha256": identity[1]})

    destination.mkdir(parents=True, exist_ok=False)
    for record in records:
        target = destination / record["name"]
        shutil.copyfile(data / record["name"], target)
        target.chmod(0o644)
        body = target.read_bytes()
        if (len(body), hashlib.sha256(body).hexdigest()) != (record["bytes"], record["sha256"]):
            raise ValueError("Installed selected firmware differs from its original product")

    (destination / "corresponding-source").symlink_to(corresponding_source)
    (destination / "provider").symlink_to(provider)
    (destination / "SOURCE-MANIFEST.json").write_text(json.dumps({
        "schema": "aos.qemu.source-built-x86-firmware.v1",
        "provider": str(provider),
        "corresponding_source": str(corresponding_source),
        "products": records,
        "native_ready": False,
        "complete_qemu_firmware_roster_qualified": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
