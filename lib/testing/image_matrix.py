"""Binds every published image encoding to one tested logical boot subject.

The report is local build/runtime evidence, not a release-admission report.
Each system contributes four format cells and one boot subject. Aggregation
rejects missing cells, mismatched identities, and incomplete security checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any


FORMATS = ("qcow2", "raw", "vhd", "vmdk")
QEMU_FORMATS = {"qcow2": "qcow2", "raw": "raw", "vhd": "vpc", "vmdk": "vmdk"}
REPORT_SCHEMA = "aos.image-matrix-report/v1"
REQUIRED_BOOT_CHECKS = {
    "uefi",
    "provisioning",
    "configurationActivation",
    "configurationRejection",
    "persistentState",
}
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
STORE_PATH = re.compile(r"/nix/store/[0-9a-z]{32}-[^/]+(?:/.*)?")


class MatrixError(RuntimeError):
    """Indicates that an image input or its runtime evidence violates the matrix."""


def require(condition: bool, message: str) -> None:
    """Rejects an unmet condition even when Python assertions are disabled."""

    if not condition:
        raise MatrixError(message)


def canonical(value: Any) -> bytes:
    """Serializes evidence deterministically."""

    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def digest(value: Any) -> str:
    """Identifies a structured input without relying on dictionary ordering."""

    return hashlib.sha256(canonical(value)).hexdigest()


def hash_file(path: Path) -> str:
    """Hashes the complete file, including any trailing bytes."""

    result = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(8 * 1024 * 1024):
            result.update(block)
    return result.hexdigest()


def is_sha256(value: Any) -> bool:
    """Recognizes a complete lowercase SHA-256 identity."""

    return isinstance(value, str) and HEX_SHA256.fullmatch(value) is not None


def read_json(path: Path) -> Any:
    """Reads JSON from an explicit matrix input or report."""

    return json.loads(path.read_bytes())


def run(arguments: list[str], *, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    """Runs a native tool and preserves its diagnostic on failure."""

    result = subprocess.run(
        arguments, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, check=False,
    )
    require(result.returncode == 0, f"command failed: {arguments!r}\n{result.stdout}")
    return result


def validate_manifest(manifest: dict[str, Any]) -> None:
    """Checks platform scope and exact per-system format/security declarations."""

    require(manifest.get("schema") == "aos.image-matrix-input/v1", "unknown input schema")
    require(manifest.get("platform") in {"x86_64-linux", "aarch64-linux"}, "unsupported guest platform")
    require(manifest.get("buildPlatform") == "x86_64-linux", "matrix requires the native x86 build tools")
    require(
        isinstance(manifest.get("sourceIdentity"), str)
        and STORE_PATH.fullmatch(manifest["sourceIdentity"]) is not None,
        "runtime evidence requires a final immutable Nix store source",
    )
    require(tuple(manifest.get("formats", ())) == FORMATS, "matrix format inventory differs")
    systems = manifest.get("systems")
    require(isinstance(systems, list) and bool(systems), "empty system inventory")
    names = [system["name"] for system in systems]
    require(len(names) == len(set(names)), "duplicate system subject")

    for system in systems:
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", system["name"]) is not None, "unsafe system name")
        require(set(system["images"]) == set(FORMATS), f"{system['name']}: incomplete formats")
        security = system["expected"]["security"]
        for field in ("readOnlyRoot", "verity", "secureBoot", "measuredBoot"):
            require(type(security.get(field)) is bool, f"{system['name']}: missing security expectation {field}")
        require(security.get("lockdown") in {"none", "integrity", "confidentiality"}, "invalid lockdown expectation")
        require(not security["measuredBoot"] or security["secureBoot"], "measured boot requires Secure Boot")
        require(security["lockdown"] == "none" or security["secureBoot"], "lockdown requires Secure Boot")


def subject_binding(manifest: dict[str, Any], system: dict[str, Any]) -> str:
    """Binds a report to its source, exact artifacts, host tools and expectations."""

    return digest({
        "sourceIdentity": manifest["sourceIdentity"],
        "platform": manifest["platform"],
        "buildPlatform": manifest["buildPlatform"],
        "tools": manifest["tools"],
        "firmwareCode": manifest["firmwareCode"],
        "firmwareVars": manifest["firmwareVars"],
        "system": system,
    })


def validate_metadata(
    manifest: dict[str, Any], system: dict[str, Any], image_format: str,
    metadata: dict[str, Any], path: Path,
) -> None:
    """Checks the actual artifact bytes against their declared format contract."""

    context = f"{system['name']}/{image_format}"
    require(metadata.get("schemaVersion") == 2, f"{context}: unknown image metadata")
    require(metadata.get("format") == image_format, f"{context}: metadata format differs")
    require(metadata.get("platform") == manifest["platform"], f"{context}: platform differs")
    require(metadata.get("version") == system["expected"]["version"], f"{context}: version differs")
    require(
        metadata.get("moduleAbi") == system["expected"]["moduleAbi"],
        f"{context}: module ABI differs",
    )
    compression = "zstd" if image_format == "raw" else "none"
    require(metadata.get("compression") == compression, f"{context}: compression differs")
    require(path.is_file(), f"{context}: artifact file is missing")
    require(type(metadata.get("byteSize")) is int and metadata["byteSize"] > 0, f"{context}: invalid size")
    require(path.stat().st_size == metadata["byteSize"], f"{context}: byte size differs")
    require(hash_file(path) == metadata.get("sha256"), f"{context}: artifact hash differs")
    require(
        is_sha256(metadata.get("logicalDiskSha256")),
        f"{context}: invalid logical disk hash",
    )
    require(
        type(metadata.get("virtualSizeBytes")) is int and metadata["virtualSizeBytes"] > 0,
        f"{context}: invalid virtual size",
    )
    budget = metadata.get("artifactBudgetsMiB", {}).get("download")
    require(type(budget) is int and budget > 0, f"{context}: missing artifact budget")
    require(metadata["byteSize"] <= budget * 1024 * 1024, f"{context}: artifact exceeds budget")
    security = system["expected"]["security"]
    require(
        metadata.get("uki", {}).get("signed") is security["secureBoot"],
        f"{context}: signing expectation differs",
    )
    require(
        metadata.get("uki", {}).get("measured") is security["measuredBoot"],
        f"{context}: measurement expectation differs",
    )


def verify_formats(
    manifest: dict[str, Any], system: dict[str, Any], work: Path,
) -> tuple[list[dict[str, Any]], Path, dict[str, Any]]:
    """Decodes all four artifacts and proves complete logical disk equality."""

    artifacts = {}
    for image_format in FORMATS:
        directory = Path(system["images"][image_format])
        metadata_path = directory / "image-info.json"
        metadata = read_json(metadata_path)
        filename = metadata.get("filename")
        require(
            isinstance(filename, str)
            and filename not in {"", ".", ".."}
            and Path(filename).name == filename,
            "unsafe artifact filename",
        )
        artifact = directory / filename
        validate_metadata(manifest, system, image_format, metadata, artifact)
        artifacts[image_format] = (metadata, artifact, metadata_path)

    raw, raw_path, _ = artifacts["raw"]
    logical = work / "logical.raw"
    run([manifest["tools"]["zstd"], "-q", "-d", "-f", str(raw_path), "-o", str(logical)])
    require(logical.stat().st_size == raw["virtualSizeBytes"], "decoded raw geometry differs")
    require(hash_file(logical) == raw["logicalDiskSha256"], "decoded raw hash differs")

    cells = []
    for image_format in FORMATS:
        metadata, artifact, metadata_path = artifacts[image_format]
        for field in ("logicalDiskSha256", "virtualSizeBytes", "rootfsSha256", "name", "uki"):
            require(
                metadata.get(field) == raw.get(field),
                f"{system['name']}/{image_format}: {field} differs from raw",
            )
        if image_format != "raw":
            information = json.loads(run([
                manifest["tools"]["qemuImg"], "info", "--output=json",
                "-f", QEMU_FORMATS[image_format], str(artifact),
            ]).stdout)
            require(
                information.get("virtual-size") == raw["virtualSizeBytes"],
                f"{image_format}: decoded geometry differs",
            )
            run([
                manifest["tools"]["qemuImg"], "compare", "-f", "raw",
                "-F", QEMU_FORMATS[image_format], str(logical), str(artifact),
            ])
        cells.append({
            "format": image_format,
            "artifact": str(artifact),
            "artifactSha256": metadata["sha256"],
            "metadataSha256": hash_file(metadata_path),
            "byteSize": metadata["byteSize"],
            "virtualSizeBytes": raw["virtualSizeBytes"],
            "logicalDiskSha256": raw["logicalDiskSha256"],
            "equivalent": True,
        })
    return cells, logical, raw


def validate_security(expected: dict[str, Any], observed: dict[str, Any]) -> None:
    """Requires positive observations for every enabled security capability."""

    fields = (
        "rootFilesystem", "readOnlyRoot", "verity", "secureBoot", "measuredBoot", "lockdown",
    )
    for field in fields:
        require(
            field in observed
            and type(observed[field]) is type(expected[field])
            and observed[field] == expected[field],
            f"security observation differs: {field}",
        )
    require(
        observed.get("encryptedState") is expected["measuredBoot"],
        "encrypted state differs from image capability",
    )
    if expected["measuredBoot"]:
        require(observed.get("tpm") is True, "measured image lacks an observed TPM")
        require(
            observed.get("measurementIndexActive") is True,
            "measured image lacks the active PCR measurement index",
        )
    if expected["lockdown"] != "none":
        require(observed.get("lockdownRejection") is True, "lockdown has no rejected forbidden operation")


def validate_subject_report(
    manifest: dict[str, Any], system: dict[str, Any], report: dict[str, Any],
) -> None:
    """Checks complete runtime evidence and its binding to every format cell."""

    require(report.get("name") == system["name"], "report has another system name")
    require(report.get("binding") == subject_binding(manifest, system), "report input binding differs")
    cells = report.get("formats", [])
    require(
        len(cells) == len(FORMATS)
        and {cell.get("format") for cell in cells} == set(FORMATS),
        "report has missing or duplicate format cells",
    )
    logical_hashes = {cell.get("logicalDiskSha256") for cell in cells}
    require(len(logical_hashes) == 1 and None not in logical_hashes, "format cells do not share one logical disk")
    logical_hash = next(iter(logical_hashes))
    require(is_sha256(logical_hash), "invalid report logical hash")
    for cell in cells:
        require(cell.get("equivalent") is True, "format equivalence was not observed")
        require(
            str(Path(cell["artifact"]).parent) == system["images"][cell["format"]],
            "format artifact belongs to another output",
        )
        require(type(cell.get("byteSize")) is int and cell["byteSize"] > 0, "format cell lacks byte size")
        for field in ("artifactSha256", "metadataSha256"):
            require(is_sha256(cell.get(field)), f"format cell lacks {field}")

    boot = report.get("boot", {})
    require(boot.get("logicalDiskSha256") == logical_hash, "boot did not use the format-equivalent logical disk")
    require(boot.get("formatBinding") == "decoded-logical-disk", "unsupported boot/format binding")
    require(
        all(type(boot.get(field)) is int and boot[field] >= 1 for field in ("warmBoots", "coldBoots")),
        "boot persistence cycles are incomplete",
    )
    checks = boot.get("checks", {})
    require(
        set(checks) == REQUIRED_BOOT_CHECKS
        and all(value is True for value in checks.values()),
        "boot checks are incomplete",
    )
    observations = boot.get("observations", [])
    require(
        len(observations) == 3
        and {item.get("phase") for item in observations} == {"initial", "warm", "cold"},
        "runtime observations are incomplete",
    )
    configured = boot.get("configuration", {})
    require(type(configured.get("generation")) is int, "committed configuration generation is missing")
    for field in ("runtimeModulesDigest", "hostNixDigest"):
        require(is_sha256(configured.get(field)), f"configuration input is missing: {field}")
    machine = "x86_64" if manifest["platform"] == "x86_64-linux" else "aarch64"
    for observation in observations:
        require(observation.get("machine") == machine, "guest architecture differs")
        for field in ("toplevel", "version", "kernel", "moduleAbi"):
            require(observation.get(field) == system["expected"][field], f"guest identity differs: {field}")
        validate_security(system["expected"]["security"], observation.get("security", {}))
        if observation["phase"] != "initial":
            current = observation.get("configuration", {})
            require(
                type(current.get("generation")) is int
                and current["generation"] >= configured["generation"],
                "reboot reverted configuration generation",
            )
            for field in ("runtimeModulesDigest", "hostNixDigest"):
                require(current.get(field) == configured[field], f"reboot changed configuration input: {field}")
    require(boot.get("imageUpdateClaims") is False, "boot evidence must not claim image transitions")


def merge_reports(manifest: dict[str, Any], reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregates only one complete, correctly bound report per system."""

    validate_manifest(manifest)
    subjects = []
    for report in reports:
        require(report.get("schema") == REPORT_SCHEMA, "unknown report schema")
        require(report.get("platform") == manifest["platform"], "report platform differs")
        require(report.get("sourceIdentity") == manifest["sourceIdentity"], "report source differs")
        subjects.extend(report.get("systems", []))
    by_name = {subject["name"]: subject for subject in subjects}
    expected_names = {system["name"] for system in manifest["systems"]}
    require(
        len(by_name) == len(subjects) and set(by_name) == expected_names,
        "matrix has missing, duplicate or unexpected systems",
    )
    for system in manifest["systems"]:
        validate_subject_report(manifest, system, by_name[system["name"]])
    return {
        "schema": REPORT_SCHEMA,
        "sourceIdentity": manifest["sourceIdentity"],
        "platform": manifest["platform"],
        "buildPlatform": manifest["buildPlatform"],
        "systems": [by_name[name] for name in sorted(by_name)],
        "formatCells": len(subjects) * len(FORMATS),
        "bootSubjects": len(subjects),
        "evidenceScope": "format-equivalence-and-boot-runtime",
    }


def qualify(manifest: dict[str, Any]) -> dict[str, Any]:
    """Verifies one immutable subject and boots its shared logical disk."""

    validate_manifest(manifest)
    require(len(manifest["systems"]) == 1, "individual runner requires one system")
    require(os.uname().machine == "x86_64", "runner is not executing on the declared native build host")
    system = manifest["systems"][0]
    work = Path.cwd() / "work"
    work.mkdir()
    cells, logical, metadata = verify_formats(manifest, system, work)

    # Import only after validation: the release transport reads its environment
    # at import time, but the signed release Scenario is never instantiated.
    from image_matrix_boot import boot_system

    boot = boot_system(manifest, system, logical, metadata, work)
    report = {
        "schema": REPORT_SCHEMA,
        "platform": manifest["platform"],
        "sourceIdentity": manifest["sourceIdentity"],
        "systems": [{
            "name": system["name"],
            "binding": subject_binding(manifest, system),
            "formats": cells,
            "boot": boot,
        }],
    }
    return merge_reports(manifest, [report])


def main() -> None:
    """Runs one subject or verifies the complete aggregate."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "merge"))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("reports", nargs="*", type=Path)
    arguments = parser.parse_args()
    manifest = read_json(arguments.manifest)
    if arguments.operation == "run":
        require(not arguments.reports, "individual run does not consume reports")
        report = qualify(manifest)
    else:
        report = merge_reports(manifest, [read_json(path) for path in arguments.reports])
    arguments.output.write_bytes(canonical(report))


if __name__ == "__main__":
    main()
