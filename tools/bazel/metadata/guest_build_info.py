"""Exports guest package metadata from the shared instruction ABI source."""

import argparse
import os
from pathlib import Path
import re


def build_info(source, system):
    """Rejects an unknown target or an ambiguous canonical instruction ABI."""
    triples = {"x86_64-linux": "x86_64-unknown-linux-gnu", "aarch64-linux": "aarch64-unknown-linux-gnu"}
    versions = re.findall(r"^pub const WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION: u16 = ([0-9]+);$", source, re.MULTILINE)
    architectures = re.findall(r"pub const WHITEBOX_DOORBELL_ABIS: &\[WhiteboxDoorbellAbi\] =\s*&\[([^\]]+)\];", source)
    if system not in triples or len(versions) != 1 or not 0 < int(versions[0]) <= 65535:
        raise ValueError("guest metadata requires a supported target and one u16 ABI version")
    expected = ["WHITEBOX_DOORBELL_X86_64_ABI", "WHITEBOX_DOORBELL_AARCH64_ABI"]
    if len(architectures) != 1 or [item.strip() for item in architectures[0].split(",") if item.strip()] != expected:
        raise ValueError("canonical guest instruction architectures changed")
    fields = {
        "package": "crucible-guest",
        "build_system": "Bazel",
        "dependency_sources": "Nix-pinned-source-archives",
        "rustflags": "-C target-feature=+crt-static -C relocation-model=static",
        "rust_build_target": triples[system],
        "packaged_guest_system": system,
        "doorbell_instruction_abi_version": versions[0],
        "instruction_abi_architectures": "x86_64,aarch64",
        "abi_source": "crucible-protocol::doorbell_abi::WHITEBOX_DOORBELL_ABIS",
        "frame_source": "crucible-protocol::doorbell_frame",
        "marker_source": "crucible-protocol::doorbell_marker",
    }
    return "".join(f"{name}={value}\n" for name, value in fields.items())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", nargs=1, type=Path, required=True)
    parser.add_argument("--outputs", nargs=1, type=Path, required=True)
    options = parser.parse_args()
    contents = build_info(options.inputs[0].read_text(), os.environ["AOS_GUEST_SYSTEM"])
    options.outputs[0].write_text(contents)
