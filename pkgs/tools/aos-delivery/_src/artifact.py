"""Builds deterministic infra bundles from actual AOS OCI and scan evidence.

Normalization changes only the layout's source tag. Original index and build
provenance remain bound as build inputs, while the delivery wrapper binds the
resulting component index to exact GitHub source and workflow coordinates.
"""

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

from cargo_inventory import enrich_cargo_inventory
from transport import DeliveryError, encoded


COMPONENT = "aos-hub-native"
APPLICATION = "aos-hub-hybrid"
REPOSITORY = "andyl-technologies/aos"
REF = "refs/heads/dplecki/hub-hybrid-topology"
WORKFLOW = REPOSITORY + "/.github/workflows/delivery-hub-staging.yml@" + REF
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def digest(content):
    """Hashes the exact bytes subsequently packed or sent to the API."""
    return "sha256:" + hashlib.sha256(content).hexdigest()


def file_digest(path):
    """Hashes a regular file without loading image layers into memory."""
    value = hashlib.sha256()
    size = 0
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            value.update(block)
            size += len(block)
    return "sha256:" + value.hexdigest(), size


def read_json(path):
    """Reads bounded evidence documents; layers are handled separately."""
    with open(path, "rb") as source:
        value = source.read((16 << 20) + 1)
    if len(value) > 16 << 20:
        raise DeliveryError("evidence JSON exceeds its size boundary")
    try:
        return json.loads(value)
    except (UnicodeError, ValueError):
        raise DeliveryError("evidence JSON is invalid") from None


def declaration_content(path):
    """Removes presentation whitespace before hashing the exact declaration."""
    value = read_json(path)
    if not isinstance(value, dict):
        raise DeliveryError("application declaration must be an object")
    return encoded(value)


def prove_source(revision):
    """Requires an exact clean feature-branch checkout before local build use."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise DeliveryError("source revision must be a full Git SHA")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if head != revision or subprocess.check_output(["git", "status", "--porcelain"]):
        raise DeliveryError("artifact source must be the exact clean checked-out commit")
    values = {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": "1156711779",
        "GITHUB_REPOSITORY_OWNER_ID": "159484437",
        "GITHUB_REF": REF,
        "GITHUB_WORKFLOW_REF": WORKFLOW,
        "GITHUB_SHA": revision,
        "GITHUB_EVENT_NAME": "push",
    }
    if any(os.environ.get(name) != value for name, value in values.items()):
        raise DeliveryError("workflow source is outside the exact staging caller")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if not re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get(name, "")):
            raise DeliveryError("workflow run identity is invalid")


def archive_digest(revision, *paths):
    """Hashes the actual tracked source rather than a supplied digest string."""
    process = subprocess.Popen(
        ["git", "archive", "--format=tar", revision, *paths],
        stdout=subprocess.PIPE,
    )
    value = hashlib.sha256()
    for block in iter(lambda: process.stdout.read(1 << 20), b""):
        value.update(block)
    process.stdout.close()
    if process.wait() != 0:
        raise DeliveryError("source archive hashing failed")
    return "sha256:" + value.hexdigest()


def normalize_layout(source, destination):
    """Authenticates descriptor closure and gives the component one source tag."""
    source, destination = Path(source), Path(destination)
    entries = list(source.rglob("*"))
    if any(path.is_symlink() for path in entries):
        raise DeliveryError("OCI layout contains a symlink")
    files = {
        path.relative_to(source).as_posix(): path
        for path in entries
        if not path.is_dir()
    }
    if any(path.is_symlink() or not path.is_file() for path in files.values()):
        raise DeliveryError("OCI layout contains a nonregular file")
    allowed = {"index.json", "oci-layout"}
    if not allowed <= files.keys() or read_json(files["oci-layout"]) != {"imageLayoutVersion": "1.0.0"}:
        raise DeliveryError("OCI layout header is invalid")
    index = read_json(files["index.json"])
    if index.get("schemaVersion") != 2 or len(index.get("manifests", [])) != 1:
        raise DeliveryError("staging requires one hermetic platform image")
    visited = set()

    def visit(descriptor):
        if descriptor.get("urls") or descriptor.get("data") or descriptor.get("artifactType"):
            raise DeliveryError("OCI descriptor contains external or auxiliary content")
        value = descriptor.get("digest", "")
        if not DIGEST.fullmatch(value):
            raise DeliveryError("OCI descriptor digest is invalid")
        name = "blobs/sha256/" + value.removeprefix("sha256:")
        path = files.get(name)
        if path is None or file_digest(path) != (value, descriptor.get("size")):
            raise DeliveryError("OCI descriptor content or size differs")
        allowed.add(name)
        if name in visited:
            return
        visited.add(name)
        media = descriptor.get("mediaType")
        if media == "application/vnd.oci.image.index.v1+json":
            for child in read_json(path).get("manifests", []):
                visit(child)
        elif media == "application/vnd.oci.image.manifest.v1+json":
            manifest = read_json(path)
            visit(manifest["config"])
            for layer in manifest["layers"]:
                visit(layer)
        elif media not in (
            "application/vnd.oci.image.config.v1+json",
            "application/vnd.oci.image.layer.v1.tar+gzip",
            "application/vnd.oci.image.layer.v1.tar",
        ):
            raise DeliveryError("OCI descriptor media type is outside the image schema")

    visit(index["manifests"][0])
    if files.keys() != allowed:
        raise DeliveryError("OCI layout contains unreferenced or undeclared files")
    index["manifests"][0].setdefault("annotations", {})["org.opencontainers.image.ref.name"] = COMPONENT
    for name, path in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    (destination / "index.json").write_bytes(encoded(index))
    return digest(files["index.json"].read_bytes())


def validate_catalog(catalog):
    """Requires usable versioned package coverage before vulnerability scanning."""
    packages = catalog.get("artifacts", [])
    recognized = [
        value for value in packages
        if value.get("name") and value.get("version")
        and (value.get("purl") or value.get("cpes"))
    ]
    if not recognized:
        raise DeliveryError("artifact catalog has no recognized versioned package coverage")


def validate_scan(report):
    """Rejects malformed reports and critical findings after actual scanning."""
    if not isinstance(report.get("matches"), list) or not isinstance(report.get("descriptor"), dict):
        raise DeliveryError("scanner report is malformed")
    ignored = report.get("ignoredMatches", [])
    if not isinstance(ignored, list):
        raise DeliveryError("scanner ignored-match report is malformed")
    if any(
        value.get("vulnerability", {}).get("severity", "").lower() == "critical"
        for value in report["matches"] + ignored
    ):
        raise DeliveryError("scanner reported critical vulnerabilities")


def validate_database(status):
    """Checks actual Grype status against the admitted schema and age bounds."""
    if status.get("valid") is not True or status.get("error"):
        raise DeliveryError("vulnerability database failed integrity validation")
    if not re.fullmatch(r"v6\.[0-9]+\.[0-9]+", status.get("schemaVersion", "")):
        raise DeliveryError("vulnerability database schema is unsupported")
    try:
        built = datetime.datetime.fromisoformat(status["built"].replace("Z", "+00:00"))
        now = datetime.datetime.now(datetime.timezone.utc)
        age = (now - built).total_seconds()
    except (KeyError, ValueError, TypeError):
        raise DeliveryError("vulnerability database build time is invalid") from None
    if not -600 <= age <= 120 * 3600:
        raise DeliveryError("vulnerability database is stale or built in the future")


def pack(root, output):
    """Packs regular files in stable order without timestamps or ownership drift."""
    root = Path(root)
    with open(output, "xb") as destination:
        with tarfile.open(fileobj=destination, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            paths = sorted(
                (path for path in root.rglob("*") if path.is_file()),
                key=lambda path: path.relative_to(root).as_posix(),
            )
            for path in paths:
                if path.is_symlink():
                    raise DeliveryError("bundle cannot contain symlinks")
                header = tarfile.TarInfo(path.relative_to(root).as_posix())
                header.size, header.mode = path.stat().st_size, 0o600
                with path.open("rb") as source:
                    archive.addfile(header, source)


def build_bundle(args):
    """Produces a v2 application bundle only after actual scanning succeeds."""
    prove_source(args.source_sha)
    declaration = declaration_content(args.declaration)
    project = read_json(args.declaration)
    components = project.get("releaseGroups", {}).get("native", {}).get("components")
    if project.get("name") != APPLICATION or components != [COMPONENT]:
        raise DeliveryError("declaration does not identify the registered Native component")
    evidence = Path(args.evidence) / "evidence"
    sbom = read_json(evidence / "sbom.payload.json")
    if sbom.get("spdxVersion") != "SPDX-2.3" or not sbom.get("packages"):
        raise DeliveryError("AOS closure SPDX evidence is absent or malformed")
    build_provenance = read_json(evidence / "provenance.payload.json")
    database_status = read_json(args.database_status)
    validate_database(database_status)
    with tempfile.TemporaryDirectory(prefix="aos-delivery-") as temporary:
        root = Path(temporary)
        layout = root / "images" / COMPONENT
        original_digest = normalize_layout(Path(args.image) / "layout", layout)
        expected_subject = [{
            "name": "container-image-index",
            "digest": {"sha256": original_digest.removeprefix("sha256:")},
        }]
        if (
            build_provenance.get("_type") != "https://in-toto.io/Statement/v1"
            or build_provenance.get("predicateType") != "https://aos.dev/attestations/container-build/v1"
            or build_provenance.get("subject") != expected_subject
        ):
            raise DeliveryError("AOS build provenance does not bind the exact original index")
        attestations = root / "attestations" / COMPONENT
        attestations.mkdir(parents=True)
        catalog = root / "catalog.json"
        subprocess.run([
            args.cataloger, "oci-dir:" + str(layout),
            "--output", "syft-json=" + str(catalog),
            "--output", "spdx-json=" + str(attestations / "sbom.json"),
        ], check=True)
        catalog_value = read_json(catalog)
        spdx_path = attestations / "sbom.json"
        spdx = read_json(spdx_path)
        cargo_coverage = enrich_cargo_inventory(layout, catalog_value, spdx)
        catalog.write_bytes(encoded(catalog_value))
        spdx_path.write_bytes(encoded(spdx))
        validate_catalog(catalog_value)
        reports = {}
        inputs = {"artifact": catalog, "closure": evidence / "sbom.payload.json"}
        for scope, scanner_input in inputs.items():
            scan = root / (scope + "-scan.json")
            subprocess.run([
                args.scanner, "sbom:" + str(scanner_input),
                "--output", "json", "--file", str(scan), "--fail-on", "critical",
            ], check=True)
            reports[scope] = read_json(scan)
            validate_scan(reports[scope])
            scan.unlink()
        scan_evidence = {
            "apiVersion": "https://aos.dev/attestations/vulnerability-scan/v1",
            "artifactCatalogDigest": file_digest(catalog)[0],
            "closureSbomDigest": file_digest(evidence / "sbom.payload.json")[0],
            "artifactPackageCount": len(catalog_value["artifacts"]),
            "closurePackageCount": len(sbom["packages"]),
            "reports": reports,
            "database": database_status,
            "cargoCoverage": cargo_coverage,
            "coverage": (
                "Actual image catalog and Nix closure SPDX; static dependency "
                "recognition requires separate qualification."
            ),
        }
        (attestations / "vulnerability-scan.json").write_bytes(encoded(scan_evidence))
        index_digest = file_digest(layout / "index.json")[0]
        provenance = {
            "apiVersion": "slsa.dev/provenance/v1",
            "builder": "aos-delivery",
            "repository": REPOSITORY,
            "revision": args.source_sha,
            "component": COMPONENT,
            "workflowRef": WORKFLOW,
            "runId": os.environ["GITHUB_RUN_ID"],
            "imageIndexDigest": index_digest,
            "originalImageIndexDigest": original_digest,
            "aosBuildEvidence": build_provenance,
            "aosClosureSbom": sbom,
            "artifactCatalog": catalog_value,
            "normalization": "component source tag only",
        }
        (attestations / "slsa-provenance.json").write_bytes(encoded(provenance))
        media = {
            "sbom": "application/spdx+json",
            "slsa-provenance": "application/vnd.in-toto+json",
            "vulnerability-scan": "application/vnd.andyl.vulnerability-scan+json",
        }
        descriptors = {
            name: {
                "path": "attestations/" + COMPONENT + "/" + name + ".json",
                "digest": file_digest(attestations / (name + ".json"))[0],
                "mediaType": kind,
            }
            for name, kind in media.items()
        }
        image = {
            "path": "images/" + COMPONENT + "/index.json",
            "digest": index_digest,
            "mediaType": "application/vnd.oci.image.index.v1+json",
        }
        manifest = {
            "apiVersion": "delivery.andyl.com/artifact/v2",
            "kind": "ApplicationArtifactBundle",
            "application": APPLICATION,
            "components": [COMPONENT],
            "repository": REPOSITORY,
            "repositoryId": 1156711779,
            "ownerId": 159484437,
            "sourceRevision": args.source_sha,
            "sourceRef": REF,
            "declarationDigest": digest(declaration),
            "configurationDigest": archive_digest(args.source_sha),
            "apiSchemaDigest": archive_digest(args.source_sha, "crates/aos-proto/src/proto/aos/hub"),
            "images": {COMPONENT: {"image": image, "attestations": descriptors}},
        }
        (root / "manifest.json").write_bytes(encoded(manifest))
        catalog.unlink()
        pack(root, args.output)
