"""Binds K3s fleet inputs to exact artifacts in a staged release manifest.

The Rust case expander and this independent executor check must select the same
service packages, native package contracts, boot image, and published OCI
workload. Neither accepts a registry tag or an unlisted package as a substitute.
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


def _package_contract_outputs(decision, artifacts, package):
    """Returns logical outputs and source subjects from one native contract."""

    artifact_ids = decision["artifact_ids"]
    contract = decision.get("package_contract")
    if contract is None:
        return {}, []
    if contract["document_artifact"] not in artifact_ids:
        raise ValueError(f"K3s fleet {package} contract document is not retained")

    package_module = contract["package_module"]
    if package_module is not None:
        if (
            package_module.get("package") not in ("self", package)
            or package_module.get("output") != "module"
            or package_module not in contract["selectors"]
        ):
            raise ValueError(f"K3s fleet {package} has an invalid native package module")

    outputs = {}
    subjects = []
    for selector in contract["selectors"]:
        selected_package = package if selector["package"] == "self" else selector["package"]
        if selected_package != package:
            continue
        output = selector["output"]
        path = selector["store_path"]
        if output in outputs or re.fullmatch(
            r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+", path
        ) is None:
            raise ValueError(f"K3s fleet {package} contract has an invalid selector")
        outputs[output] = path

        matching_ids = [
            artifact_id
            for artifact_id, artifact in artifacts.items()
            if artifact.get("store_path") == path
        ]
        selected_artifact = _unique(
            matching_ids, f"{package} {output} selector artifact"
        )
        if selected_artifact not in artifact_ids:
            if artifacts[selected_artifact].get("kind") != "source":
                raise ValueError(
                    f"K3s fleet {package} {output} selector is not retained as source"
                )
            subjects.append(selected_artifact)
    return outputs, subjects


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
    expected = bindings.package_outputs[role]["module"]
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
        outputs = {}
        for artifact_id in package_artifacts:
            artifact = artifacts[artifact_id]
            output = artifact_id.rsplit("/", 1)[-1]
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
        contract_outputs, contract_subjects = _package_contract_outputs(
            cell["decision"]["artifact"], artifacts, name
        )
        for output, path in contract_outputs.items():
            if output in outputs and outputs[output] != path:
                raise ValueError(f"K3s fleet {name} repeats logical output {output}")
            outputs[output] = path
        if "out" not in outputs:
            raise ValueError(f"K3s fleet {name} lacks its primary output")
        package_outputs[name] = outputs
        subjects.extend(package_artifacts)
        subjects.extend(contract_subjects)

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
