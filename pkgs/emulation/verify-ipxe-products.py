"""Checks original PCI image chains and retains actual compiler product identities."""

from pathlib import Path
import hashlib
import json


BINDINGS = {
    "e1000": (0x8086, 0x100e),
    "e1000e": (0x8086, 0x10d3),
    "eepro100": (0x8086, 0x1209),
    "ne2k_pci": (0x1050, 0x0940),
    "pcnet": (0x1022, 0x2000),
    "rtl8139": (0x10ec, 0x8139),
    "virtio": (0x1af4, 0x1000),
    "vmxnet3": (0x15ad, 0x07b0),
}


def u16(body, offset):
    if offset < 0 or offset + 2 > len(body):
        raise ValueError("Truncated PCI ROM field")
    return int.from_bytes(body[offset:offset + 2], "little")


def images(body, identity):
    offset = 0
    types = []
    while offset < len(body):
        if len(types) >= 2 or body[offset:offset + 2] != b"\x55\xaa":
            raise ValueError("Invalid PCI image chain")
        pcir = offset + u16(body, offset + 0x18)
        if pcir < offset + 0x1a or pcir + 0x18 > len(body):
            raise ValueError("Invalid PCI data structure offset")
        if body[pcir:pcir + 4] != b"PCIR":
            raise ValueError("Missing PCI data structure")
        if (u16(body, pcir + 4), u16(body, pcir + 6)) != identity:
            raise ValueError("PCI vendor/device differs from original target")
        length = u16(body, pcir + 0x10) * 512
        end = offset + length
        if not length or end > len(body) or pcir + 0x18 > end:
            raise ValueError("Invalid PCI image extent")
        code = body[pcir + 0x14]
        # EfiRom recalculates legacy checksums. EFI images use their PE/COFF
        # format and are not subject to the legacy byte-sum checksum rule.
        if code == 0 and sum(body[offset:end]) & 0xff:
            raise ValueError("Legacy PCI ROM checksum differs")
        types.append(code)
        last = bool(body[pcir + 0x15] & 0x80)
        offset = end
        if last:
            if offset != len(body):
                raise ValueError("Trailing bytes after final PCI image")
            return types
    raise ValueError("PCI image chain has no terminal indicator")


def pin(path):
    body = path.read_bytes()
    return {"path": str(path), "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest()}


def main():
    products = []
    for name, identity in BINDINGS.items():
        for prefix, expected in (("pxe", [0]), ("efi", [0, 3])):
            path = Path("firmware-products") / (prefix + "-" + name + ".rom")
            if images(path.read_bytes(), identity) != expected:
                raise ValueError("Missing original BIOS or x86-64 EFI image")
            products.append(pin(path))
    backing = []
    for root in (Path("roms/ipxe/src"), Path("roms/edk2/BaseTools/Source/C")):
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix in (".o", ".d", ".map", ".efidrv"):
                backing.append(pin(path))
    if not backing or not any(row["path"].endswith("EfiRom.o") for row in backing):
        raise ValueError("Missing actual firmware/tool compiler products")
    Path("firmware-products/products.json").write_text(json.dumps({
        "products": products, "compiler_products": backing,
        "expected_pci_images": "Eight BIOS plus eight BIOS/x86-64 EFI chains",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
