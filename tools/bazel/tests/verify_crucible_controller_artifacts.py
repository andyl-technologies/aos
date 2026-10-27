"""Qualifies the controller's three independent production compilation graphs.

This gate covers exported executables and their fixture-generator behavior.
The installed suite, mandatory tests, documentation, and live QEMU gates remain
separate requirements for a public controller cutover.
"""

import argparse
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import tempfile

from installed_package import elf_contract
from verify_cache import execution_events
from verify_compiler_options import audit
from verify_package_evaluation_driver import production_profiles
from verify_protocol import compare_features
from verify_qemu_gpl import elf


CONTEXTS = {
    "cli": ("crucible-cli", "crucible"),
    "debugger": ("crucible-engine", "crucible-debugger-live-fixture"),
    "scenario": ("crucible-daemon", "crucible-e2e-determinism-scenario"),
}


def digest(path):
    """Hashes actual exported bytes rather than a declared input identity."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(build, package, executable):
    """Requires exactly one checked Apache controller executable export."""
    label = f"//crates/crucible/{package}:controller_artifact"
    identifier = hashlib.sha256(label.encode()).hexdigest()
    if json.loads((build / "packages/index.json").read_text()) != {label: identifier}:
        raise ValueError("controller build has an unexpected package inventory")
    directory = build / "packages" / identifier
    manifest = json.loads((directory / "manifest.json").read_text())
    if tuple(manifest[key] for key in ["schema_version", "label", "name", "version", "license", "license_domain"]) != (
        1, label, package, "0.1.0", "Apache-2.0", "apache-host",
    ):
        raise ValueError("controller artifact changed its package or license identity")
    entries = manifest["artifacts"]
    destination = "bin/" + executable
    if len(entries) != 1 or entries[0]["destination"] != destination or entries[0]["mode"] != "0755":
        raise ValueError("controller artifact changed its executable destination")
    path = directory / "files" / destination
    # Nix canonicalizes completed store files to read-only executable mode.
    if digest(path) != entries[0]["sha256"] or stat.S_IMODE(path.stat().st_mode) != 0o555:
        raise ValueError("controller export differs from its manifest")
    return path, manifest


def fresh_actions(build):
    """Requires actual successful Linux sandbox execution for both source layouts."""
    actions = execution_events(build)
    if not actions or any(
        event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
        for event in actions
    ):
        raise ValueError("controller qualification requires fresh sandbox actions")
    return len(actions)


def run_pair(programs, executable, arguments, expected_status):
    """Compares exact exit status and streams with a common command name."""
    results = [subprocess.run(
        [executable, *map(str, arguments)], executable=str(path),
        capture_output=True, timeout=30,
    ) for path in programs]
    observed = [(result.returncode, result.stdout, result.stderr) for result in results]
    if observed[0] != observed[1] or observed[0][0] != expected_status:
        raise ValueError(f"controller command differs: {executable} {arguments!r}")
    return {
        "arguments": list(map(str, arguments)), "exit_code": observed[0][0],
        "stdout_sha256": hashlib.sha256(observed[0][1]).hexdigest(),
        "stderr_sha256": hashlib.sha256(observed[0][2]).hexdigest(),
    }, observed[0][1]


def fixture_parity(programs):
    """Checks canonical scenario bytes and the actual immutable store objects."""
    cases = {}
    cli = programs["cli"]
    cases["cli"] = []
    for arguments, status in [(["--help"], 0), (["selftest", "--help"], 0), (["--invalid-controller-option"], 2)]:
        record, output = run_pair(cli, "crucible", arguments, status)
        if arguments == ["selftest", "--help"] and b"--with-qemu" in output:
            raise ValueError("production controller exposes the test-double backend")
        cases["cli"].append(record)

    cases["scenario"] = []
    for arguments, status in [(["--emit-scenario"], 0), ([], 1), (["--unknown"], 1)]:
        record, _ = run_pair(programs["scenario"], CONTEXTS["scenario"][1], arguments, status)
        cases["scenario"].append(record)

    with tempfile.TemporaryDirectory(prefix="controller-artifact-parity-") as temporary:
        root = Path(temporary)
        kernel, image = root / "kernel", root / "image"
        # The generator hashes assets; these bytes exercise that contract and
        # do not stand in for a bootable kernel or a live debugger qualification.
        kernel.write_bytes(b"controller fixture kernel hash input\n")
        image.write_bytes(b"controller fixture image hash input\n")
        cases["debugger"] = []
        for architecture in ["x86_64", "aarch64"]:
            output = root / "scenario.toml"
            arguments = [architecture, kernel, image, "console=ttyS0", output]
            documents = []
            for program in programs["debugger"]:
                subprocess.run([str(program), *map(str, arguments)], check=True, capture_output=True, timeout=30)
                documents.append(output.read_bytes())
                output.unlink()
            if not documents[0] or documents[0] != documents[1]:
                raise ValueError("debugger canonical scenario differs")
            cases["debugger"].append({"architecture": architecture, "scenario_sha256": hashlib.sha256(documents[0]).hexdigest()})
        record, _ = run_pair(programs["debugger"], CONTEXTS["debugger"][1], [], 1)
        cases["debugger"].append(record)

        store = root / "store"
        objects, streams = [], []
        for index, program in enumerate(programs["scenario"]):
            destination = store / str(index)
            result = subprocess.run([str(program), "--populate-store", str(destination)],
                                    check=True, capture_output=True, timeout=30)
            streams.append((result.stdout, result.stderr))
            objects.append({str(path.relative_to(destination)): digest(path)
                            for path in destination.rglob("*") if path.is_file()})
        if not objects[0] or objects[0] != objects[1] or streams[0] != streams[1]:
            raise ValueError("scenario immutable store population differs")
        cases["store_objects"] = objects[0]
        cases["store_population_stdout_sha256"] = hashlib.sha256(streams[0][0]).hexdigest()
    return cases


def verify(options):
    """Binds separate feature/profile comparisons to both completed build layouts."""
    contexts = json.loads(options.contexts.read_text())
    if set(contexts) != set(CONTEXTS):
        raise ValueError("controller qualification requires three independent contexts")
    package_paths = json.loads(options.package_paths.read_text())
    programs, reports = {}, {}
    for name, (package, executable) in CONTEXTS.items():
        context = contexts[name]
        build, broad = [Path(context[key]) for key in ["build", "broad_build"]]
        workspace, inventory = [Path(context[key]) for key in ["workspace", "source_inventory"]]
        actual, manifest = artifact(build, package, executable)
        conservative, broad_manifest = artifact(broad, package, executable)
        if manifest != broad_manifest or actual.read_bytes() != conservative.read_bytes():
            raise ValueError("strict controller source selection changed the exported executable")
        if json.loads((build / "inventory.json").read_text()) != json.loads(inventory.read_text()):
            raise ValueError("controller configured inventory changed")
        if json.loads((broad / "inventory.json").read_text()) != json.loads(inventory.read_text()):
            raise ValueError("broad controller configured inventory differs")
        if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in workspace.rglob("Cargo.*")):
            raise ValueError("controller Bazel source selection retains Cargo metadata")
        cargo = options.cargo / name
        baseline = cargo / "artifacts" / executable
        observed = {"bazel": elf(actual, options.readelf), "cargo": elf(baseline, options.readelf)}
        for field in ["identity", "needed", "interpreter"]:
            if observed["bazel"][field] != observed["cargo"][field]:
                raise ValueError(f"controller {name} ELF {field} differs")
        runtime = {driver: elf_contract(path, options.readelf, options.loader)
                   for driver, path in [("bazel", actual), ("cargo", baseline)]}
        if runtime["bazel"]["resolved_libraries"] != runtime["cargo"]["resolved_libraries"]:
            raise ValueError("controller resolves different runtime libraries")
        messages = cargo / "cargo-messages.jsonl"
        reports[name] = {
            "manifest": manifest, "elf": observed, "runtime": runtime,
            "build": str(build), "broad_build": str(broad), "workspace": str(workspace),
            "fresh_linux_sandbox_actions": {"strict": fresh_actions(build), "broad": fresh_actions(broad)},
            "features": compare_features(build / "inventory.json", messages, package_paths, required_packages=[package]),
            "production_profiles": production_profiles(build, messages, package_paths),
            "compiler_arguments": audit(build, cargo),
        }
        programs[name] = [actual, baseline]
    return {
        "schema_version": 1, "status": "PASS", "contexts": reports,
        "fixture_behavior": fixture_parity(programs),
        "public_controller_cutover_qualified": False,
        "limits": [
            "Executable compilation and generator behavior do not qualify the installed public controller package.",
            "Mandatory suite tests, Clippy, rustdoc, doctests, license/ABI gates and live QEMU remain separate qualifications.",
            "AArch64 scenario serialization here is native generator behavior, not foreign executable qualification.",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["contexts", "package-paths", "cargo", "readelf", "loader", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")
