"""Adds compiled Cargo library candidates from authenticated image evidence.

Cargo compiler output proves that a library participated in the Native build;
it does not prove that all its code survived final linking. The inventory is
therefore conservative and explicitly includes that coverage limitation.
"""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from urllib.parse import quote

from transport import DeliveryError


HUB_ROOT = r"nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-aos-hub-[^/]+"
MESSAGES = re.compile(rf"({HUB_ROOT})/nix-support/cargo-build-messages\.jsonl\Z")
BINARY = re.compile(rf"({HUB_ROOT})/bin/aos-hub\Z")
REGISTRY = re.compile(
    r"registry\+https://(?:github\.com/rust-lang/crates\.io-index|index\.crates\.io/?)"
    r"#([A-Za-z0-9_-]+)@([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?)\Z"
)
MAX_METADATA_BYTES = 16 << 20
MAX_LAYER_BYTES = 1 << 30
MAX_LAYER_ENTRIES = 1_000_000


def file_digest(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
    return "sha256:" + digest.hexdigest(), size


def descriptor_file(layout, descriptor):
    """Rechecks descriptors before reading their source evidence."""
    digest = descriptor.get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise DeliveryError("Cargo inventory descriptor digest is invalid")
    path = layout / "blobs" / "sha256" / digest.removeprefix("sha256:")
    if path.is_symlink() or not path.is_file():
        raise DeliveryError("Cargo inventory descriptor is not a regular file")
    if file_digest(path) != (digest, descriptor.get("size")):
        raise DeliveryError("Cargo inventory descriptor differs from its image bytes")
    return path


def read_json(path):
    with path.open("rb") as source:
        payload = source.read(MAX_METADATA_BYTES + 1)
    if len(payload) > MAX_METADATA_BYTES:
        raise DeliveryError("Cargo inventory image metadata is too large")
    try:
        value = json.loads(payload)
    except (UnicodeError, ValueError):
        raise DeliveryError("Cargo inventory image metadata is invalid") from None
    if not isinstance(value, dict):
        raise DeliveryError("Cargo inventory image metadata must be an object")
    return value


def member_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise DeliveryError("Cargo inventory layer contains an unsafe member path")
    return path.as_posix().removeprefix("./")


def remove_tree(values, prefix):
    if not prefix:
        values.clear()
        return
    for path in list(values):
        if path == prefix or path.startswith(prefix + "/"):
            del values[path]


def source_messages(layout):
    """Reads final-image Native build evidence without extracting layer files."""
    layout = Path(layout)
    index = read_json(layout / "index.json")
    descriptors = index.get("manifests", [])
    if not isinstance(descriptors, list) or len(descriptors) != 1:
        raise DeliveryError("Cargo inventory requires exactly one Native platform image")
    descriptor = descriptors[0]
    if not isinstance(descriptor, dict):
        raise DeliveryError("Cargo inventory manifest descriptor is malformed")
    if descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        raise DeliveryError("Cargo inventory requires a normalized platform manifest")
    manifest = read_json(descriptor_file(layout, descriptor))
    messages = {}
    binaries = {}
    layers = manifest.get("layers", [])
    if not isinstance(layers, list) or len(layers) > 128:
        raise DeliveryError("Cargo inventory image layer count is invalid")

    for layer in layers:
        if not isinstance(layer, dict):
            raise DeliveryError("Cargo inventory layer descriptor is malformed")
        if layer.get("mediaType") not in {
            "application/vnd.oci.image.layer.v1.tar",
            "application/vnd.oci.image.layer.v1.tar+gzip",
        }:
            raise DeliveryError("Cargo inventory layer format is unsupported")
        layer_path = descriptor_file(layout, layer)
        layer_messages = {}
        layer_binaries = {}
        try:
            with tarfile.open(layer_path, mode="r|*") as archive:
                size = 0
                for count, member in enumerate(archive, 1):
                    size += member.size
                    if member.size < 0 or count > MAX_LAYER_ENTRIES or size > MAX_LAYER_BYTES:
                        raise DeliveryError("Cargo inventory layer exceeds its read bounds")
                    path = member_path(member.name)
                    parent, _, name = path.rpartition("/")
                    if name.startswith(".wh."):
                        removed = parent if name == ".wh..wh..opq" else (
                            (parent + "/" if parent else "") + name.removeprefix(".wh.")
                        )
                        remove_tree(messages, removed)
                        remove_tree(binaries, removed)
                        continue
                    if not member.isdir():
                        # Replacing an ancestor directory hides its old children.
                        for values in (messages, binaries, layer_messages, layer_binaries):
                            remove_tree(values, path)
                    if MESSAGES.fullmatch(path):
                        if not member.isfile() or member.size > MAX_METADATA_BYTES:
                            layer_messages[path] = None
                            continue
                        source = archive.extractfile(member)
                        if source is None:
                            raise DeliveryError("Cargo inventory build evidence is unreadable")
                        payload = source.read(MAX_METADATA_BYTES + 1)
                        if len(payload) != member.size:
                            raise DeliveryError("Cargo inventory build evidence is truncated")
                        layer_messages[path] = (payload, layer["digest"])
                    elif BINARY.fullmatch(path):
                        layer_binaries[path] = member.isfile()
        except (tarfile.TarError, OSError):
            raise DeliveryError("Cargo inventory layer archive is invalid") from None
        # Whiteouts apply to lower layers irrespective of their tar ordering.
        messages.update(layer_messages)
        binaries.update(layer_binaries)

    if len(messages) != 1:
        raise DeliveryError("Native image must contain exactly one Cargo build evidence file")
    path, evidence = next(iter(messages.items()))
    if evidence is None:
        raise DeliveryError("Native Cargo build evidence is not a bounded regular file")
    root = MESSAGES.fullmatch(path).group(1)
    if binaries.get(root + "/bin/aos-hub") is not True:
        raise DeliveryError("Cargo build evidence is not paired with its Native Hub binary")
    return path, root, evidence[0], evidence[1], descriptor["digest"]


def cargo_packages(payload):
    """Selects crates.io libraries and requires a real primary Hub build record."""
    packages = {}
    native_targets = set()
    skipped = {"nonLibrary": 0, "test": 0, "nonCratesIo": 0}
    try:
        records = [json.loads(line) for line in payload.splitlines() if line.strip()]
    except (UnicodeError, ValueError):
        raise DeliveryError("Native Cargo build messages are invalid JSON") from None
    if len(records) > 100_000:
        raise DeliveryError("Native Cargo build messages contain too many records")
    for record in records:
        if not isinstance(record, dict):
            raise DeliveryError("Native Cargo build message is not an object")
        if record.get("reason") != "compiler-artifact":
            continue
        target = record.get("target", {})
        profile = record.get("profile", {})
        if not isinstance(target, dict) or not isinstance(profile, dict):
            raise DeliveryError("Native Cargo artifact metadata is malformed")
        kinds = target.get("kind", [])
        package_id = record.get("package_id", "")
        filenames = record.get("filenames", [])
        if (
            not isinstance(kinds, list)
            or not isinstance(package_id, str)
            or not isinstance(filenames, list)
        ):
            raise DeliveryError("Native Cargo artifact identity is malformed")
        if profile.get("test") is not False:
            skipped["test"] += 1
            continue
        if kinds == ["bin"] and target.get("name") in {"aos-hub", "aos-hub-egress"}:
            if package_id.startswith("path+file://") and "/aos-hub#" in package_id:
                native_targets.add(target["name"])
        if kinds != ["lib"] or not any(
            isinstance(path, str) and path.endswith(".rlib")
            for path in filenames
        ):
            skipped["nonLibrary"] += 1
            continue
        identity = REGISTRY.fullmatch(package_id)
        if identity is None:
            skipped["nonCratesIo"] += 1
            continue
        name, version = identity.groups()
        purl = f"pkg:cargo/{quote(name, safe='')}@{quote(version, safe='')}"
        packages[purl] = (name, version)
    if "aos-hub" not in native_targets or not packages:
        raise DeliveryError("Cargo evidence lacks the Native Hub build or registry libraries")
    return packages, sorted(native_targets), skipped


def enrich_cargo_inventory(layout, catalog, spdx):
    """Adds exact Cargo identities and returns hash-bound, conservative coverage."""
    if not isinstance(catalog.get("artifacts"), list) or not isinstance(spdx.get("packages"), list):
        raise DeliveryError("Cargo enrichment requires genuine catalog and SPDX documents")
    path, root, payload, layer_digest, manifest_digest = source_messages(layout)
    packages, targets, skipped = cargo_packages(payload)
    existing = {package.get("purl") for package in catalog["artifacts"]}
    added = 0
    for purl, (name, version) in sorted(packages.items()):
        if purl in existing:
            continue
        identity = hashlib.sha256((path + "\0" + purl).encode()).hexdigest()
        catalog["artifacts"].append(
            {
                "id": identity,
                "name": name,
                "version": version,
                "type": "rust-crate",
                "foundBy": "aos-cargo-build-evidence",
                "locations": [{"path": "/" + path}],
                "licenses": [],
                "language": "rust",
                "cpes": [],
                "purl": purl,
            }
        )
        spdx["packages"].append(
            {
                "SPDXID": "SPDXRef-AosCargo-" + identity,
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "comment": "Compiled library candidate from " + "/" + path,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": purl,
                    }
                ],
            }
        )
        added += 1
    return {
        "schema": "aos.cargo-artifact-inventory/v1",
        "manifestDigest": manifest_digest,
        "layerDigest": layer_digest,
        "nativeOutputRoot": "/" + root,
        "buildMessagesPath": "/" + path,
        "buildMessagesDigest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "nativeBuildTargets": targets,
        "cratesIoLibraryCandidates": len(packages),
        "addedPackages": added,
        "skippedArtifacts": skipped,
        "coverage": (
            "Crates.io libraries recorded by this Native build; conservative candidates "
            "may include build-only libraries or code removed by linking. Local/git crates "
            "and native system libraries require separate coverage."
        ),
    }
