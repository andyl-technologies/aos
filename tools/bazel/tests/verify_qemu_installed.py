"""Checks GPL package layouts and runtime dependencies after ordinary AOS fixup."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from verify_qemu_gpl import elf


def reject_metadata_drift(options, plugin, identity):
    """Exercises real installer rejection before any incompatible metadata is published."""
    rejected = []
    for kind in ["qemu-package", "shmem-version", "embedded-identity"]:
        with tempfile.TemporaryDirectory(prefix="qemu-installed-negative-") as directory:
            temporary = Path(directory)
            output, abi = temporary / "output", temporary / "abi"
            (output / "lib").mkdir(parents=True)
            (output / "lib/libcrucible_qemu_plugin.so").symlink_to(plugin)
            abi.mkdir()
            altered = dict(identity)
            if kind == "embedded-identity":
                altered["qemu_build_id"] = "0" * 64
            (abi / "identity.json").write_text(json.dumps(altered))
            result = subprocess.run([
                sys.executable, str(options.metadata_installer), "--output", str(output),
                "--abi", str(abi), "--qemu", str(options.qemu) + ("-other" if kind == "qemu-package" else ""),
                "--qemu-shmem-abi", "crucible-shmem-abi-v0" if kind == "shmem-version" else options.qemu_shmem_abi,
                "--gpl", str(options.gpl), "--mit", str(options.mit),
            ], capture_output=True, text=True, timeout=10)
            diagnostics = {
                "qemu-package": "plugin ABI bundle belongs to another QEMU package",
                "shmem-version": "plugin ABI bundle disagrees with the QEMU shared-memory ABI",
                "embedded-identity": "installed plugin omitted its checked identity: qemu_build_id",
            }
            if result.returncode == 0 or "ValueError: " + diagnostics[kind] not in result.stderr:
                raise ValueError("plugin metadata installer did not reject " + kind)
            if (output / "nix-support").exists() or (output / "lib/qemu").exists():
                raise ValueError("plugin metadata installer published an incompatible identity")
            rejected.append(kind)
    return rejected


def verify(options):
    """Checks installed identities, licenses, ELF properties, and rejected drift."""
    identity = json.loads((options.abi / "identity.json").read_text())
    artifacts = {
        "plugin": options.plugin / "lib/libcrucible_qemu_plugin.so",
        "gateway": options.gateway / "bin/crucible-debug-gateway",
    }
    reference = {
        "plugin": options.cargo / "artifacts/libcrucible_qemu_plugin.so",
        "gateway": options.cargo / "artifacts/crucible-debug-gateway",
    }
    observations = {}
    for name, path in artifacts.items():
        actual, expected = elf(path, options.readelf), elf(reference[name], options.readelf)
        for field in ["identity", "needed", "interpreter"]:
            if actual[field] != expected[field]:
                raise ValueError(f"installed {name} ELF {field} differs from Cargo")
        if name == "plugin":
            actual_exports = [(item["name"], item["kind"]) for item in actual["exports"]]
            expected_exports = [(item["name"], item["kind"]) for item in expected["exports"]]
            if actual_exports != expected_exports:
                raise ValueError("installed plugin exports differ from Cargo")
            version = next(item for item in actual["exports"] if item["name"] == "qemu_plugin_version")
            if version["kind"] != "OBJECT" or version["size"] != 4:
                raise ValueError("installed plugin QEMU version object has an invalid layout")
            contents = path.read_bytes()
            for key in ["qemu_build_id", "atomic_patch_sha256", "shmem_header_sha256"]:
                if identity[key].encode() not in contents:
                    raise ValueError("installed plugin lost its admission identity: " + key)
        loaded = subprocess.run(
            [str(options.loader), "--list", str(path)], capture_output=True, text=True, timeout=15,
        )
        libraries = sorted(line.split(" => ", 1)[1].split()[0]
                           for line in loaded.stdout.splitlines() if " => /" in line)
        if loaded.returncode or not libraries or any(Path(p).parent != options.loader.parent for p in libraries):
            raise ValueError(f"installed {name} does not resolve only its AOS glibc runtime")
        observations[name] = {k: value for k, value in actual.items() if k != "raw"}
        observations[name]["resolved_libraries"] = libraries

    link = options.plugin / "lib/qemu/plugins/crucible-qemu-plugin.so"
    if link.readlink() != Path("../../libcrucible_qemu_plugin.so") or link.resolve() != artifacts["plugin"]:
        raise ValueError("installed QEMU plugin symlink differs from its package layout")
    for package, root in [("crucible-qemu-plugin", options.plugin), ("crucible-debug-gateway", options.gateway)]:
        licenses = root / "share/licenses" / package
        for name, source in [("GPL-2.0.txt", options.gpl), ("MIT.txt", options.mit)]:
            if (licenses / name).read_bytes() != source.read_bytes():
                raise ValueError("installed license differs from its reviewed source: " + name)
        component = (licenses / "COMPONENT").read_text()
        if "SPDX-License-Identifier: GPL-2.0-only\n" not in component or "MIT option." not in component:
            raise ValueError("installed component omitted its GPL and permissive protocol scope")

    metadata = {}
    for line in (options.plugin / "nix-support/crucible-qemu-plugin-build-info").read_text().splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in metadata:
            raise ValueError("installed plugin metadata contains an invalid or duplicate field")
        metadata[key] = value
    expected = {
        "package": "crucible-qemu-plugin", "build_system": "mkAosBazelBuild",
        "rust_dependencies": "locked-bazel-source-repositories", "qemu_package": "qemu-crucible",
        "qemu_build_id": identity["qemu_build_id"],
        "qemu_sim_capability_marker": str(options.qemu / "share/aos/crucible/qemu-build-identity.env"),
        "qemu_plugin_header": str(options.qemu / "include/qemu/qemu-plugin.h"),
        "qemu_plugin_api_version": str(identity["qemu_plugin_api_version"]),
        "qemu_plugin_abi": f"qemu-plugin-api-v{identity['qemu_plugin_api_version']}",
        "shmem_abi_version": str(identity["shmem_abi_version"]),
        "shmem_abi": options.qemu_shmem_abi, "qemu_shmem_abi": options.qemu_shmem_abi,
        "shmem_generated_header": str(options.qemu / "include/aos/crucible/crucible_shmem_abi.h"),
        "shmem_generated_header_hash": identity["shmem_header_sha256"],
        "plugin_abi": options.qemu_shmem_abi,
        "component": "qemu-in-process-adapter", "component_license": "GPL-2.0-only",
    }
    if metadata != expected:
        raise ValueError("installed plugin build metadata differs from its checked inputs")

    gateway_cases = []
    for args in [[], ["--help"], ["--control-socket", "relative"],
                 ["--control-socket", "/unused-control", "--owner-gdb-socket", "relative"]]:
        results = [subprocess.run(["crucible-debug-gateway", *args], executable=str(p),
                                  capture_output=True, text=True, timeout=10)
                   for p in [artifacts["gateway"], reference["gateway"]]]
        values = [(result.returncode, result.stdout, result.stderr) for result in results]
        if values[0] != values[1] or values[0][0] == 0:
            raise ValueError("installed gateway argument rejection differs from Cargo")
        gateway_cases.append({"arguments": args, "exit_code": values[0][0],
                              "stdout": values[0][1], "stderr": values[0][2]})

    rejected = reject_metadata_drift(options, artifacts["plugin"], identity)
    return {
        "schema_version": 1,
        "status": "PASS",
        "plugin": str(options.plugin),
        "gateway": str(options.gateway),
        "cargo": str(options.cargo),
        "artifacts": observations,
        "plugin_build_info": metadata,
        "gateway_cases": gateway_cases,
        "rejected_drift": rejected,
        "limits": [
            "This checks installed layout and native resolution; live QEMU loading, "
            "complete Cargo closure equivalence, and suite release/source retention "
            "remain separate gates.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in [
        "plugin", "gateway", "cargo", "abi", "qemu", "readelf", "loader",
        "gpl", "mit", "metadata-installer", "output",
    ]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--qemu-shmem-abi", required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
