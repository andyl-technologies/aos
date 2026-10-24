"""Installs the checked QEMU plugin identity and its existing license scope."""

import argparse
import json
from pathlib import Path


def install(output, abi, qemu, qemu_shmem_abi, gpl, mit):
    """Rejects mismatched compiler identities before writing installed metadata."""
    identity = json.loads((abi / "identity.json").read_text())
    if identity["schema_version"] != 1 or identity["qemu"] != str(qemu):
        raise ValueError("plugin ABI bundle belongs to another QEMU package")
    if qemu_shmem_abi != f"crucible-shmem-abi-v{identity['shmem_abi_version']}":
        raise ValueError("plugin ABI bundle disagrees with the QEMU shared-memory ABI")

    library = output / "lib/libcrucible_qemu_plugin.so"
    contents = library.read_bytes()
    if not contents.startswith(b"\x7fELF"):
        raise ValueError("installed plugin is not an ELF artifact")
    for key in ["qemu_build_id", "atomic_patch_sha256", "shmem_header_sha256"]:
        if identity[key].encode() not in contents:
            raise ValueError("installed plugin omitted its checked identity: " + key)

    plugins = output / "lib/qemu/plugins"
    plugins.mkdir(parents=True)
    (plugins / "crucible-qemu-plugin.so").symlink_to("../../libcrucible_qemu_plugin.so")
    api, shmem = identity["qemu_plugin_api_version"], identity["shmem_abi_version"]
    metadata = {
        "package": "crucible-qemu-plugin",
        "build_system": "mkAosBazelBuild",
        "rust_dependencies": "locked-bazel-source-repositories",
        "qemu_package": "qemu-crucible",
        "qemu_build_id": identity["qemu_build_id"],
        "qemu_sim_capability_marker": str(qemu / "share/aos/crucible/qemu-build-identity.env"),
        "qemu_plugin_header": str(qemu / "include/qemu/qemu-plugin.h"),
        "qemu_plugin_api_version": api,
        "qemu_plugin_abi": f"qemu-plugin-api-v{api}",
        "shmem_abi_version": shmem,
        "shmem_abi": f"crucible-shmem-abi-v{shmem}",
        "qemu_shmem_abi": qemu_shmem_abi,
        "shmem_generated_header": str(qemu / "include/aos/crucible/crucible_shmem_abi.h"),
        "shmem_generated_header_hash": identity["shmem_header_sha256"],
        "plugin_abi": f"crucible-shmem-abi-v{shmem}",
        "component": "qemu-in-process-adapter",
        "component_license": "GPL-2.0-only",
    }
    support = output / "nix-support"
    support.mkdir(exist_ok=True)
    (support / "crucible-qemu-plugin-build-info").write_text(
        "".join(f"{key}={value}\n" for key, value in metadata.items()),
    )

    licenses = output / "share/licenses/crucible-qemu-plugin"
    licenses.mkdir(parents=True)
    (licenses / "GPL-2.0.txt").write_bytes(gpl.read_bytes())
    (licenses / "MIT.txt").write_bytes(mit.read_bytes())
    (licenses / "COMPONENT").write_text(
        "crucible-qemu-plugin is an in-process QEMU adapter.\n"
        "SPDX-License-Identifier: GPL-2.0-only\n"
        "crucible-qemu-protocol and crucible-qemu-shmem are used under their MIT option.\n",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["output", "abi", "qemu", "gpl", "mit"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--qemu-shmem-abi", required=True)
    options = parser.parse_args()
    install(options.output, options.abi, options.qemu, options.qemu_shmem_abi, options.gpl, options.mit)


if __name__ == "__main__":
    main()
