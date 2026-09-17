"""Binds K3s's embedded addon defaults to the source-built OCI manifests.

The installed inventory has schema ``aos.k3s.addon-images/v1`` and an ``images``
array. Each entry records its name, repository, manifest digest, and immutable
archive path. The package also retains those archives for air-gap import.
"""

import hashlib
import json
from pathlib import Path
import sys


ADDON_NAMES = {
    "coredns",
    "metrics-server",
    "local-path-provisioner",
    "local-path-helper",
    "traefik",
    "helm-job",
    "service-lb",
}
REGISTRY_PREFIX = "%{SYSTEM_DEFAULT_REGISTRY}%"


def replace_exact(path, before, after, count=1):
    """Rejects upstream drift instead of leaving an unbound default image."""

    content = path.read_text()
    actual = content.count(before)
    if actual != count:
        raise ValueError(f"{path}: expected {count} occurrences of {before!r}, got {actual}")
    path.write_text(content.replace(before, after))


def bind_images(inputs):
    if set(inputs) != ADDON_NAMES:
        raise ValueError("K3s must bind every default addon image")

    images = []
    for name, image in sorted(inputs.items()):
        manifest_path = Path(image["manifest"])
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        if (
            manifest.get("schemaVersion") != 2
            or manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
        ):
            raise ValueError(f"{name}: expected an OCI image manifest")

        digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
        archive = manifest_path.parent / "image.oci.tar"
        if not archive.is_file():
            raise ValueError(f"{name}: image archive is absent")
        images.append(
            {
                "name": name,
                "repository": image["reference"],
                "digest": digest,
                "archive": str(archive),
            }
        )
    return images


def main():
    source = Path(sys.argv[1])
    inputs = json.loads(Path(sys.argv[2]).read_text())
    shell = sys.argv[3]
    images = bind_images(inputs)
    references = {
        image["name"]: image["repository"] + "@" + image["digest"] for image in images
    }

    defaults = [
        ("coredns.yaml", "coredns", "rancher/mirrored-coredns-coredns:1.14.1"),
        (
            "metrics-server/metrics-server-deployment.yaml",
            "metrics-server",
            "rancher/mirrored-metrics-server:v0.8.1",
        ),
        (
            "local-storage.yaml",
            "local-path-provisioner",
            "rancher/local-path-provisioner:v0.0.34",
        ),
        (
            "local-storage.yaml",
            "local-path-helper",
            "rancher/mirrored-library-busybox:1.37.0",
        ),
    ]
    for filename, name, original in defaults:
        replace_exact(
            source / "manifests" / filename,
            REGISTRY_PREFIX + original,
            REGISTRY_PREFIX + references[name],
        )

    replace_exact(source / "manifests/local-storage.yaml", "#!/bin/sh", "#!" + shell, count=2)

    # The chart supports tag@digest and strips the digest when comparing the
    # Traefik version for capability-dependent template branches.
    traefik = next(image for image in images if image["name"] == "traefik")
    replace_exact(
        source / "manifests/traefik.yaml",
        'repository: "rancher/mirrored-library-traefik"',
        f'repository: "{traefik["repository"]}"',
    )
    replace_exact(
        source / "manifests/traefik.yaml",
        'tag: "3.6.7"',
        f'tag: "3.6.7@{traefik["digest"]}"',
    )

    for name in ["helm-job", "service-lb"]:
        (source / f"aos-{name}-reference").write_text(references[name] + "\n")
    inventory = {"schema": "aos.k3s.addon-images/v1", "images": images}
    (source / "aos-addon-images.json").write_text(json.dumps(inventory, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
