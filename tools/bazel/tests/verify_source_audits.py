"""Qualifies source audits against declared, Cargo-free package ownership."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from verify_pilot import cases, verify


ROOT_CASE = "crucible_crate_roots_carry_declared_unsafe_fence"
AUDITS = {"crate_unsafe_fence": 5, "concurrency_abi_oracle_standards": 2, "harness_lint_annotations": 4}


def oracle_binary(oracle, target="crate_unsafe_fence"):
    """Requires one retained executable for the selected integration target."""
    binaries = []
    for line in (oracle / "cargo-messages.jsonl").read_text().splitlines():
        message = json.loads(line)
        if (message.get("reason") == "compiler-artifact"
                and message.get("target", {}).get("name") == target
                and message.get("profile", {}).get("test") and message.get("executable")):
            binaries.append(Path(message["executable"]))
    if len(binaries) != 1 or not binaries[0].is_file():
        raise ValueError("source audit Cargo oracle has no unique retained executable: " + target)
    return binaries[0]


def executed_cases(output):
    """Extracts successful libtest cases and rejects any failed or ignored cases."""
    if re.search(r"^test .* \.\.\. (?:FAILED|ignored)", output, re.MULTILINE):
        raise ValueError("source audit failed or ignored a case")
    return sorted(re.findall(r"^test (\S+) \.\.\. ok$", output, re.MULTILINE))


def run_audit(binary, catalog, exact=None):
    environment = dict(os.environ, AOS_SOURCE_CATALOG=str(catalog))
    command = [str(binary), "--test-threads=1"]
    if exact:
        command += ["--exact", exact]
    return subprocess.run(command, env=environment, capture_output=True, text=True, timeout=120)


def qualify(options):
    binaries = {name: oracle_binary(options.oracle, name) for name in AUDITS}
    package_index = json.loads((options.build / "packages/index.json").read_text())
    package = options.build / "packages" / package_index[
        "//crates/crucible/crucible-test-support:source_audit_binaries"] / "files/bin"
    bazel_binaries = {name: package / name for name in AUDITS}
    expected = {name: cases(binary) for name, binary in binaries.items()}
    for name, binary in binaries.items():
        if len(expected[name]) != AUDITS[name] or cases(binary, ignored=True):
            raise ValueError("source audit case coverage changed: " + name)
        if cases(bazel_binaries[name]) != expected[name]:
            raise ValueError("exported Bazel audit binary case coverage changed: " + name)
        if b"/build/bazel/sandbox/" in bazel_binaries[name].read_bytes():
            raise ValueError("source audit embeds a private compiler sandbox directory: " + name)
    cargo_executed = executed_cases((options.oracle / "cargo-tests.log").read_text())
    if cargo_executed != sorted(case for selected in expected.values() for case in selected):
        raise ValueError("Cargo source-ownership oracle did not execute every audit case")
    parity = verify(options.build / "evidence/tests", {
        "//crates/crucible/crucible-test-support:" + name: binary for name, binary in binaries.items()
    })

    source = options.workspace / "crates"
    manifests = sorted(str(path.relative_to(options.workspace)) for path in source.rglob("Cargo.*")
                       if path.name in {"Cargo.toml", "Cargo.lock"})
    if options.precise and manifests:
        raise ValueError("precise source audit still depends on first-party Cargo metadata")
    catalog = json.loads(options.catalog.read_text())
    package_sources = {
        package["name"]: len(package["sources"])
        for package in catalog["packages"] if package["name"].startswith("crucible-")
    }
    if len(package_sources) != 19 or any(count == 0 for count in package_sources.values()):
        raise ValueError("source audit does not cover all nineteen Crucible packages")

    rejected = []
    with tempfile.TemporaryDirectory(prefix="aos-source-audit-") as temporary:
        root = Path(temporary)
        shutil.copytree(source, root / "crates")
        (root / "crates").chmod(0o755)
        for directory in (root / "crates").rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        for manifest in (root / "crates").rglob("Cargo.*"):
            if manifest.name in {"Cargo.toml", "Cargo.lock"}:
                manifest.unlink()
        selected_catalog = root / "crates/source_catalog.json"
        selected_catalog.write_text(json.dumps(catalog))
        for compiler, selected in {"cargo": binaries, "bazel": bazel_binaries}.items():
            for name, binary in selected.items():
                result = run_audit(binary, selected_catalog)
                if result.returncode or executed_cases(result.stdout) != expected[name]:
                    raise ValueError("Compiled audit failed against Cargo-free catalog sources: "
                                     + compiler + ": " + name + ": " + result.stdout + result.stderr)

        fence_binaries = [selected["crate_unsafe_fence"] for selected in (binaries, bazel_binaries)]

        def reject(name, contents, diagnostic):
            selected_catalog.write_text(json.dumps(contents))
            for binary in fence_binaries:
                result = run_audit(binary, selected_catalog, ROOT_CASE)
                if result.returncode == 0 or diagnostic not in result.stdout + result.stderr:
                    raise ValueError("source audit accepted invalid ownership: " + name)
            rejected.append(name)

        reject("unsupported-schema", dict(catalog, schema_version=2), "invalid workspace source catalog")
        reject("empty-package-set", dict(catalog, packages=[]), "invalid workspace source catalog")
        duplicate = copy.deepcopy(catalog)
        duplicate["packages"].append(duplicate["packages"][0])
        reject("duplicate-ownership", duplicate, "invalid or duplicate source package ownership")
        escaping = copy.deepcopy(catalog)
        escaping["packages"][0]["directory"] = "crates/../outside"
        reject("escaping-ownership", escaping, "invalid or duplicate source package ownership")

        selected_catalog.write_text(json.dumps(catalog))
        selected_catalog.unlink()
        for binary in fence_binaries:
            result = run_audit(binary, selected_catalog, ROOT_CASE)
            if (result.returncode == 0
                    or "declared workspace source catalog is absent" not in result.stdout + result.stderr):
                raise ValueError("source audit silently fell back from an absent declared catalog")
        rejected.append("absent-declared-catalog")

        missing = copy.deepcopy(catalog)
        package = next(item for item in missing["packages"] if item["name"] == "crucible-engine")
        package["directory"] = "crates/absent-engine-package"
        reject("absent-owned-directory", missing, "declared workspace package directory is absent")

        selected_catalog.write_text(json.dumps(catalog))
        package = next(item for item in catalog["packages"] if item["name"] == "crucible-engine")
        crate_root = root / package["directory"] / "src/lib.rs"
        contents = crate_root.read_text()
        fence = "#![forbid(unsafe_code)]"
        if contents.count(fence) != 1:
            raise ValueError("unsafe-fence negative control cannot identify the active fence")
        crate_root.chmod(0o644)
        crate_root.write_text(contents.replace(fence, "// removed fence for qualification", 1))
        for binary in fence_binaries:
            result = run_audit(binary, selected_catalog, ROOT_CASE)
            if result.returncode == 0 or "missing required crate-root fence" not in result.stdout + result.stderr:
                raise ValueError("catalog-backed audit missed source fence drift")
        rejected.append("missing-active-unsafe-fence")

    return {
        "schema_version": 2,
        "test_parity": parity,
        "cargo_ownership_executed_cases": cargo_executed,
        "cargo_compiled_catalog_ownership_executed_cases": expected,
        "bazel_compiled_catalog_ownership_executed_cases": expected,
        "catalog_sha256": hashlib.sha256(options.catalog.read_bytes()).hexdigest(),
        "catalog_package_count": len(catalog["packages"]),
        "audited_package_sources": package_sources,
        "first_party_cargo_files": manifests,
        "negative_controls_rejected": rejected,
        "negative_control_compilers": ["cargo", "bazel"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["build", "oracle", "workspace", "catalog", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--precise", action="store_true")
    options = parser.parse_args()
    options.output.write_text(json.dumps(qualify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
