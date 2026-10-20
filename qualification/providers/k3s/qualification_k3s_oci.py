"""Assembles a native K3s workload archive from authenticated release objects.

The signed multi-platform index selects a platform manifest. Its descriptor
graph must resolve entirely to bound objects with matching sizes and hashes.
Only the archive's entry-point index is narrowed to that descriptor; every
published JSON document and blob is copied byte-for-byte.
"""

import hashlib
import json
import pathlib
import re
import shutil
import tarfile


def _read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("OCI document repeats a JSON member")
            result[key] = value
        return result

    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def _hash(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(8 * 1024 * 1024):
            result.update(block)
    return result.hexdigest()


def assemble_workload(payload, objects, bindings, platform, destination):
    """Verifies the native OCI graph and returns its archive and digest reference.

    The destination must not exist. Missing, substituted, duplicate, external,
    or unbound descriptors fail before an archive can reach a guest runtime.
    """

    architecture = {"x86_64-linux": "amd64", "aarch64-linux": "arm64"}.get(platform)
    if architecture is None:
        raise ValueError("OCI workload requires a supported Linux platform")
    artifacts = {entry["id"]: entry for entry in payload["artifacts"]}
    selected = [bindings.oci_index, bindings.oci_manifest, *bindings.oci_blobs]
    by_digest = {}
    paths = {}
    for identity in selected:
        artifact = artifacts[identity]
        source = pathlib.Path(objects[identity])
        expected = artifact["sha256"].removeprefix("sha256:")
        if (
            re.fullmatch(r"[0-9a-f]{64}", expected) is None
            or artifact["path"] != "oci/blobs/sha256/" + expected
            or source.is_symlink()
            or not source.is_file()
            or source.stat().st_size != artifact["size_bytes"]
            or _hash(source) != expected
        ):
            raise ValueError("OCI object differs from its bound artifact identity")
        digest = "sha256:" + expected
        if digest in by_digest:
            raise ValueError("OCI workload repeats a content identity")
        by_digest[digest] = artifact
        paths[identity] = source

    def descriptor(value, expected_kind):
        if not isinstance(value, dict) or value.get("urls") or value.get("data"):
            raise ValueError("OCI workload descriptor is malformed or external")
        artifact = by_digest.get(value.get("digest"))
        if (
            artifact is None
            or artifact["kind"] != expected_kind
            or value.get("size") != artifact["size_bytes"]
        ):
            raise ValueError("OCI workload descriptor does not name a bound object")
        return artifact["id"]

    index = _read_json(paths[bindings.oci_index])
    if index.get("schemaVersion") != 2:
        raise ValueError("OCI workload index has an unsupported schema")
    native = [
        entry for entry in index.get("manifests", [])
        if entry.get("platform", {}).get("os") == "linux"
        and entry.get("platform", {}).get("architecture") == architecture
    ]
    if len(native) != 1 or descriptor(native[0], "oci-manifest") != bindings.oci_manifest:
        raise ValueError("OCI index does not uniquely select the bound native manifest")

    manifest = _read_json(paths[bindings.oci_manifest])
    if manifest.get("schemaVersion") != 2 or not manifest.get("layers"):
        raise ValueError("OCI workload manifest has no supported layer graph")
    config_id = descriptor(manifest.get("config"), "oci-blob")
    used = {config_id}
    used.update(descriptor(layer, "oci-blob") for layer in manifest["layers"])
    if used != set(bindings.oci_blobs):
        raise ValueError("OCI workload contains unreferenced or missing bound blobs")
    config = _read_json(paths[config_id])
    if config.get("os") != "linux" or config.get("architecture") != architecture:
        raise ValueError("OCI configuration differs from the native platform")

    destination.mkdir()
    layout = destination / "layout"
    blobs = layout / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    for content_digest, artifact in by_digest.items():
        shutil.copyfile(paths[artifact["id"]], blobs / content_digest.removeprefix("sha256:"))
    (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}\n')
    (layout / "index.json").write_text(json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": native,
    }, sort_keys=True, separators=(",", ":")) + "\n")

    archive = destination / "workload.oci.tar"
    with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as output:
        for path in sorted(layout.rglob("*")):
            info = output.gettarinfo(str(path), arcname=path.relative_to(layout).as_posix())
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            if path.is_file():
                with path.open("rb") as source:
                    output.addfile(info, source)
            else:
                output.addfile(info)
    return archive, "aos.invalid/qualification@" + native[0]["digest"]
