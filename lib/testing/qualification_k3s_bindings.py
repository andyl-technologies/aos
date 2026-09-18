"""Binds K3s fleet inputs to exact artifacts in a staged release manifest.

The Rust case expander and this independent executor check must select the same
service packages, boot image, and published OCI workload. Neither accepts a
registry tag or an unlisted companion package as a substitute.
"""

from dataclasses import dataclass
import re


K3S_TOPOLOGIES = {
    "combined-worker": ("k3s", "k3s-combined", "k3s-worker"),
    "control-plane-worker": ("k3s", "k3s-control-plane", "k3s-worker"),
}


@dataclass(frozen=True)
class K3sFleetBindings:
    """Carries the exact package outputs and artifact subjects for one fleet."""

    subjects: list[str]
    package_outputs: dict[str, dict[str, str]]
    image_artifacts: list[str]
    oci_index: str
    oci_manifest: str
    oci_blobs: list[str]


def _unique(values, label):
    if len(values) != 1:
        raise ValueError(f"K3s fleet requires exactly one {label}")
    return values[0]


def _cell_artifacts(cells, platform, label):
    cell = _unique([cell for cell in cells if cell["platform"] == platform], label)
    decision = cell["decision"]
    if decision.get("state") != "artifact":
        raise ValueError(f"K3s fleet {label} is not an artifact")
    artifacts = decision["artifact"]["artifact_ids"]
    if not artifacts or len(artifacts) != len(set(artifacts)):
        raise ValueError(f"K3s fleet {label} has empty or duplicate artifacts")
    return artifacts


def configuration_output_names(configuration, artifact_ids, artifacts):
    """Names separate configuration inputs without replacing the runtime out."""

    if configuration is None:
        return {}
    module = configuration["module_artifact"]
    base = configuration["evaluation_base_artifact"]
    if module == base or module not in artifact_ids or base not in artifact_ids:
        raise ValueError("package configuration lacks distinct bound companion artifacts")
    if artifacts[module].get("output") != "config" or artifacts[base].get("output") != "out":
        raise ValueError("package configuration companions have the wrong Nix outputs")
    dependencies = configuration["dependency_outputs"]
    if not isinstance(dependencies, dict):
        raise ValueError("package configuration dependencies must be named outputs")
    for name, path in dependencies.items():
        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name) is None
            or not isinstance(path, str)
            or re.fullmatch(r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+", path) is None
        ):
            raise ValueError("package configuration dependency lacks an exact output identity")
    return {module: "config", base: "configuration-base"}


def verify_role_configuration_binding(manifest, bindings, role, registry, release_tag):
    """Requires activation to consume the candidate's exact registry module."""

    modules = manifest["inputs"]["config_modules"]
    names = modules["package_names"]
    paths = modules["store_paths"]
    origins = modules["origins"]
    if (
        modules["count"] != len(names)
        or len(names) != len(paths)
        or len(names) != len(origins)
        or names.count(role) != 1
        or modules["registry"] != registry
        or modules["release_tag"] != release_tag
    ):
        raise ValueError("K3s activation lacks the exact candidate configuration identity")
    selected = names.index(role)
    expected = bindings.package_outputs[role]["config"]
    if paths[selected] != expected or origins[selected] != "registry":
        raise ValueError("K3s activation consumed a substituted role configuration module")
    return expected


def bind_k3s_fleet(payload, platform, package, system_variant, topology):
    """Resolves a supported fleet and rejects missing or ambiguous inputs."""

    if platform not in {"x86_64-linux", "aarch64-linux"}:
        raise ValueError("K3s fleet requires a Linux platform")
    packages = K3S_TOPOLOGIES.get(topology)
    if packages is None or package not in packages:
        raise ValueError("K3s fleet topology does not exercise the selected package")
    if not isinstance(system_variant, str) or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]*", system_variant
    ) is None:
        raise ValueError("K3s fleet requires an exact system image variant")

    artifacts = {artifact["id"]: artifact for artifact in payload["artifacts"]}
    if len(artifacts) != len(payload["artifacts"]):
        raise ValueError("K3s fleet manifest repeats artifact identities")
    subjects = []
    package_outputs = {}
    for name in packages:
        entry = _unique(
            [entry for entry in payload["packages"] if entry["name"] == name],
            f"{name} package entry",
        )
        package_artifacts = _cell_artifacts(entry["platforms"], platform, name)
        cell = next(cell for cell in entry["platforms"] if cell["platform"] == platform)
        configuration = cell["decision"]["artifact"].get("configuration")
        if name != "k3s" and configuration is None:
            raise ValueError(f"K3s fleet {name} lacks its configuration module binding")
        companion_names = configuration_output_names(configuration, package_artifacts, artifacts)
        outputs = {}
        for artifact_id in package_artifacts:
            artifact = artifacts[artifact_id]
            output = companion_names.get(artifact_id, artifact.get("output"))
            store_path = artifact.get("store_path")
            if (
                artifact["kind"] != "package-nar"
                or artifact.get("platform") != platform
                or not isinstance(output, str)
                or not output
                or output in outputs
                or not isinstance(store_path, str)
                or re.fullmatch(
                    r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+", store_path
                ) is None
            ):
                raise ValueError(f"K3s fleet {name} lacks a unique package output identity")
            outputs[output] = store_path
        if "out" not in outputs:
            raise ValueError(f"K3s fleet {name} lacks its primary output")
        package_outputs[name] = outputs
        subjects.extend(package_artifacts)

    image = _unique(
        [entry for entry in payload["images"] if entry["system_variant"] == system_variant],
        "system image variant",
    )
    image_artifacts = _cell_artifacts(image["platforms"], platform, "system image")
    for artifact_id in image_artifacts:
        if artifacts[artifact_id].get("platform") != platform:
            raise ValueError("K3s fleet image artifact belongs to another platform")
    subjects.extend(image_artifacts)

    index = _unique(
        [entry for entry in artifacts.values() if entry["kind"] == "oci-index"],
        "published OCI index",
    )
    manifest = _unique(
        [
            entry for entry in artifacts.values()
            if entry["kind"] == "oci-manifest" and entry.get("platform") == platform
        ],
        "published OCI platform manifest",
    )
    blobs = sorted(
        entry["id"] for entry in artifacts.values()
        if entry["kind"] == "oci-blob" and entry.get("platform") == platform
    )
    subjects.extend([index["id"], manifest["id"], *blobs])

    return K3sFleetBindings(
        subjects=sorted(set(subjects)),
        package_outputs=package_outputs,
        image_artifacts=image_artifacts,
        oci_index=index["id"],
        oci_manifest=manifest["id"],
        oci_blobs=blobs,
    )
