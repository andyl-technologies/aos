"""Provider-specific ownership injection and live-resource observations.

Every oracle reads state from the provider's external substrate. Durable
execution journals and boundary transcripts are deliberately unavailable here.
"""

from __future__ import annotations

import hashlib
import base64
import json
import shlex
from pathlib import PurePosixPath
from typing import Any


PROVIDER_ORACLES = {
    "credential-delivery": {
        "roots": ["/var/lib/aos/ability-runtime/credentials"],
        "live": "filesystem",
    },
    "host-network-policy": {
        "roots": ["/var/lib/aos/ability-runtime/network-policy"],
        "live": "network",
    },
    "host-storage": {
        "roots": ["/var/lib/aos/ability-runtime/storage"],
        "live": "filesystem",
    },
    "managed-configuration": {
        "roots": ["/var/lib/aos/ability-runtime/managed-configuration"],
        "live": "filesystem",
    },
    "network-endpoint": {
        "roots": [
            "/var/lib/aos/ability-runtime/endpoints",
            "/run/aos-ability-postgresql",
        ],
        "live": "network",
    },
    "nginx-validation": {
        "roots": ["/var/lib/aos/ability-runtime/nginx/associations"],
        "live": "filesystem",
    },
    "postgresql": {
        "roots": [
            "/var/lib/aos/ability-runtime/postgresql",
            "/run/aos-ability-postgresql",
        ],
        "live": "postgresql",
    },
    "systemd-bootstrap": {
        "roots": ["/etc/aos/ability-revisions"],
        "live": "systemd",
    },
    "systemd-manager": {
        "roots": ["/etc/aos/ability-revisions"],
        "live": "systemd",
    },
    "systemd-service-legacy": {
        "roots": ["/etc/aos/ability-revisions"],
        "live": "systemd",
    },
    "kubernetes-object": {"roots": [], "live": "kubernetes"},
    "image-rollout": {
        "roots": [
            "/var/lib/profiles/image/ability-rollouts",
            "/boot/loader/entries",
        ],
        "live": "rollout",
    },
}
INJECTED_MARKERS: dict[bytes, dict[str, Any]] = {}


def canonical(value: Any) -> bytes:
    """Encodes one exact provider document canonically."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def _resource_key(resource: dict[str, Any]) -> bytes:
    return canonical(resource)


def exact_mapping(
    resource_map: dict[str, Any], resource: dict[str, Any]
) -> dict[str, Any]:
    """Selects the one authenticated native mapping for a logical resource."""

    matches = [
        mapping
        for mapping in resource_map["entries"]
        if mapping["resource"] == resource
    ]
    if len(matches) != 1:
        raise RuntimeError(f"resource has no unique native mapping: {resource!r}")
    return matches[0]


def observe_exact(
    adapter: str, operation: dict[str, Any], resource_map: dict[str, Any]
) -> dict[str, Any]:
    """Reads one exact provider resource through its independent substrate."""

    resource = operation["target"]["resource"]
    injected = INJECTED_MARKERS.get(_resource_key(resource))
    documents = resource_documents(adapter, resource)
    if injected is not None and adapter not in {
        "systemd-bootstrap",
        "systemd-manager",
        "systemd-service-legacy",
    }:
        path = injected["path"]
        payload = runtime.succeed(f"{COREUTILS}/cat {shlex.quote(path)}")
        documents = [(path, json.loads(payload))]
    mapping = exact_mapping(resource_map, resource)
    live = live_observation_with_documents(adapter, operation, documents, mapping)
    owner_count = len(documents)
    if adapter == "kubernetes-object":
        owner_count = int(live["api-document"] is not None)
    if adapter == "image-rollout":
        owner_count = 1
    if adapter in {"systemd-bootstrap", "systemd-manager", "systemd-service-legacy"}:
        owner_count = int(bool(live["units"]))
    return {
        "resource": resource,
        "owner-count": owner_count,
        "live": live,
    }


def observe_operation(
    operation: dict[str, Any], resource_map: dict[str, Any]
) -> dict[str, Any]:
    """Resolves an operation to its provider adapter and observes it."""

    interface = operation["interface"]["name"]
    matches = [
        adapter
        for adapter, expected in INTERFACES.items()
        if expected == interface
    ]
    if len(matches) != 1:
        raise RuntimeError(f"no unique provider oracle for interface {interface!r}")
    return observe_exact(matches[0], operation, resource_map)


INTERFACES = {
    "credential-delivery": "aos.credential-delivery-effects",
    "host-network-policy": "aos.host-network-policy-effects",
    "host-storage": "aos.host-storage-effects",
    "image-rollout": "aos.ab-image-rollout-effects",
    "kubernetes-object": "aos.kubernetes-object-effects",
    "managed-configuration": "aos.managed-configuration-effects",
    "network-endpoint": "aos.network-endpoint-effects",
    "nginx-validation": "aos.nginx-validation",
    "postgresql": "aos.postgresql-effects",
    "systemd-bootstrap": "aos.systemd-provider-bootstrap",
    "systemd-manager": "aos.systemd-manager",
    "systemd-service-legacy": "aos.systemd-service-effects",
}


def inject_foreign_owner(
    adapter: str, operation: dict[str, Any], resource_map: dict[str, Any]
) -> None:
    """Replaces the exact live provider owner with a foreign identity."""

    if adapter == "kubernetes-object":
        inject_foreign_kubernetes_owner(operation, exact_mapping(resource_map, operation["resource"]))
        return
    if adapter == "image-rollout":
        inject_foreign_rollout_authority(
            operation, exact_mapping(resource_map, operation["resource"])
        )
        return

    resource = operation["target"]["resource"]
    mapping = exact_mapping(resource_map, resource)
    if mapping.get("resource") != resource:
        raise RuntimeError("provider mapping does not bind the interrupted resource")
    if adapter in {"systemd-bootstrap", "systemd-manager", "systemd-service-legacy"}:
        install_foreign_systemd_authority(operation, mapping)
        return
    documents = resource_documents(adapter, resource)
    if not documents and adapter in {
        "credential-delivery",
        "host-network-policy",
        "host-storage",
        "network-endpoint",
    }:
        install_absent_foreign_host_resource(adapter, operation, mapping)
        return
    if len(documents) != 1:
        raise RuntimeError(
            f"{adapter} does not expose one exact live owner for {resource!r}"
        )
    path, document = documents[0]
    original = runtime.succeed(f"{COREUTILS}/cat {shlex.quote(path)}").encode()
    foreign = dict(resource)
    foreign["key"] = f"foreign-{resource['key']}"
    replaced, count = replace_exact_resource(document, resource, foreign)
    if count != 1:
        raise RuntimeError(f"{adapter} marker does not bind one resource identity")
    write_canonical_provider_file(path, replaced)
    INJECTED_MARKERS[_resource_key(resource)] = {
        "path": path,
        "original": original,
        "cleanup": [],
    }


def install_foreign_systemd_authority(
    operation: dict[str, Any], mapping: dict[str, Any]
) -> None:
    """Changes the selected loaded unit revision without replacing its D-Bus object."""

    resource = operation["resource"]
    unit = mapping["qualification"]["unit"]
    drop_in = f"/run/systemd/system/{unit}.d/90-foreign-authority.conf"
    payload = "[Unit]\nDocumentation=file:/etc/aos/ability-revisions/foreign-authority\n"
    encoded = base64.b64encode(payload.encode()).decode()
    runtime.succeed(
        f"{COREUTILS}/mkdir -p {shlex.quote(str(PurePosixPath(drop_in).parent))}; "
        f"{COREUTILS}/printf '%s' {shlex.quote(encoded)} | "
        f"{COREUTILS}/base64 -d > {shlex.quote(drop_in)}; "
        f"{SYSTEMCTL} daemon-reload"
    )
    INJECTED_MARKERS[_resource_key(resource)] = {
        "path": drop_in,
        "original": None,
        "cleanup": [
            f"{SYSTEMCTL} daemon-reload",
            f"{COREUTILS}/rmdir {shlex.quote(str(PurePosixPath(drop_in).parent))} 2>/dev/null || true",
        ],
    }


def restore_foreign_owner(
    adapter: str, operation: dict[str, Any], resource_map: dict[str, Any]
) -> None:
    """Restores the exact provider ownership document after evidence capture."""

    if adapter == "kubernetes-object":
        restore_kubernetes_owner(operation, exact_mapping(resource_map, operation["resource"]))
        return
    injected = INJECTED_MARKERS.pop(_resource_key(operation["resource"]))
    original = injected["original"]
    if original is None:
        runtime.succeed(f"{COREUTILS}/rm -f {shlex.quote(injected['path'])}")
    else:
        encoded = base64.b64encode(original).decode()
        runtime.succeed(
            f"{COREUTILS}/printf '%s' {shlex.quote(encoded)} | "
            f"{COREUTILS}/base64 -d > {shlex.quote(injected['path'])}"
        )
    for command in reversed(injected["cleanup"]):
        runtime.succeed(command)


def inject_foreign_rollout_authority(
    operation: dict[str, Any], mapping: dict[str, Any]
) -> None:
    """Changes the authenticated candidate image identity after durable intent."""

    resource = operation["resource"]
    request = mapping["qualification"]["request"]
    state_path = "/var/lib/profiles/image/state.json"
    original = runtime.succeed(f"{COREUTILS}/cat {state_path}").encode()
    state = json.loads(original)
    matches = [
        generation
        for generation in state["generations"]
        if generation["toplevel"] == request["candidate"]["toplevel"]
    ]
    if len(matches) != 1:
        raise RuntimeError("rollout candidate does not select one physical image generation")
    matches[0]["toplevel"] = "/nix/store/00000000000000000000000000000000-foreign-image"
    write_canonical_provider_file(state_path, state)
    INJECTED_MARKERS[_resource_key(resource)] = {
        "path": state_path,
        "original": original,
        "cleanup": [],
    }


def domain_digest(domain: str, value: Any) -> str:
    """Computes one canonical AOS domain-separated digest."""

    return hashlib.sha256(domain.encode() + b"\0" + canonical(value)).hexdigest()


def install_absent_foreign_host_resource(
    adapter: str, operation: dict[str, Any], mapping: dict[str, Any]
) -> None:
    """Creates a real foreign target after the candidate acquired absence."""

    resource = operation["resource"]
    qualification = mapping["qualification"]
    resource_digest = domain_digest("aos.ability.native-host-resource/v1", resource)
    cleanup = []
    if adapter == "credential-delivery":
        marker_path = f"/var/lib/aos/ability-runtime/credentials/.{resource_digest}.json"
        version = operation["inputs"]["version"]
        version_digest = domain_digest(
            "aos.ability.credential-view-key/v1",
            {"resource": resource, "version": version},
        )
        physical = (
            "/var/lib/aos/ability-runtime/credentials/"
            f"{resource_digest}-{version_digest}.view"
        )
        runtime.succeed(
            f"{COREUTILS}/printf '%s' foreign-credential > {shlex.quote(physical)}; "
            f"{COREUTILS}/chmod 600 {shlex.quote(physical)}"
        )
        cleanup.append(f"{COREUTILS}/rm -f {shlex.quote(physical)}")
    elif adapter == "host-storage":
        marker_path = f"/var/lib/aos/ability-runtime/storage/.{resource_digest}.json"
        if qualification["owner"] == "postgresql-slot":
            physical = f"/var/lib/aos/ability-runtime/storage/{resource_digest}"
        else:
            physical = (
                "/var/lib/aos/ability-runtime/storage/"
                f"{qualification['cluster']}-{qualification['purpose']}"
            )
        runtime.succeed(
            f"{COREUTILS}/mkdir -p {shlex.quote(physical)}; "
            f"{COREUTILS}/chmod 700 {shlex.quote(physical)}"
        )
        cleanup.append(f"{COREUTILS}/rm -rf {shlex.quote(physical)}")
    elif adapter == "network-endpoint":
        marker_path = f"/var/lib/aos/ability-runtime/endpoints/{resource_digest}.json"
        port = qualification["port"]
        unit = f"aos-provider-negative-endpoint-{port}.service"
        runtime.succeed(
            f"{SYSTEMD_RUN} --quiet --unit={shlex.quote(unit)} "
            f"{SOCAT} TCP-LISTEN:{port},bind=127.0.0.1,reuseaddr,fork EXEC:{COREUTILS}/cat"
        )
        runtime.wait_until_succeeds(f"{SS} -H -lnt | {GREP} -q ':{port} '")
        cleanup.append(f"{SYSTEMCTL} stop {shlex.quote(unit)} 2>/dev/null || true")
    elif adapter == "host-network-policy":
        marker_path = f"/var/lib/aos/ability-runtime/network-policy/{resource_digest}.json"
        table = f"aos_p_{resource_digest[:24]}"
        runtime.succeed(f"{NFT} add table inet {shlex.quote(table)}")
        cleanup.append(f"{NFT} delete table inet {shlex.quote(table)} 2>/dev/null || true")
    else:
        raise RuntimeError(f"no absent-target installer for {adapter!r}")

    foreign = dict(resource)
    foreign["key"] = f"foreign-{resource['key']}"
    state = {
        "schema": "aos.ability.native-host-resource-state/v1",
        "resource": foreign,
        "revision": mapping["revision"],
        "qualification": qualification,
        "details": {"foreign-sentinel": adapter},
    }
    write_canonical_provider_file(marker_path, state)
    INJECTED_MARKERS[_resource_key(resource)] = {
        "path": marker_path,
        "original": None,
        "cleanup": cleanup,
    }


def write_canonical_provider_file(path: str, value: Any) -> None:
    """Atomically replaces one exact provider marker as the fleet root."""

    encoded = base64.b64encode(canonical(value)).decode()
    runtime.succeed(
        f"{COREUTILS}/printf '%s' {shlex.quote(encoded)} | "
        f"{COREUTILS}/base64 -d > {shlex.quote(path)}"
    )


def replace_exact_resource(
    value: Any, resource: dict[str, Any], foreign: dict[str, Any]
) -> tuple[Any, int]:
    """Replaces exact resource objects without rewriting unrelated strings."""

    if value == resource:
        return foreign, 1
    if isinstance(value, list):
        replaced = [replace_exact_resource(child, resource, foreign) for child in value]
        return [child for child, _ in replaced], sum(count for _, count in replaced)
    if isinstance(value, dict):
        replaced = {
            key: replace_exact_resource(child, resource, foreign)
            for key, child in value.items()
        }
        return (
            {key: child for key, (child, _) in replaced.items()},
            sum(count for _, count in replaced.values()),
        )
    return value, 0


def inject_foreign_kubernetes_owner(
    operation: dict[str, Any], mapping: dict[str, Any]
) -> None:
    """Changes the exact live Kubernetes ownership annotation."""

    qualification = mapping["qualification"]
    namespace = qualification.get("namespace")
    namespace_argument = "" if namespace is None else f" -n {shlex.quote(namespace)}"
    runtime.succeed(
        f"{KUBECTL} annotate {shlex.quote(qualification['object_kind'])} "
        f"{shlex.quote(qualification['name'])}{namespace_argument} "
        "aos.andyl.com/resource-owner=foreign-matrix-owner --overwrite"
    )


def restore_kubernetes_owner(
    operation: dict[str, Any], mapping: dict[str, Any]
) -> None:
    """Restores the authenticated Kubernetes owner derived from the resource."""

    resource = operation["resource"]
    owner_input = b"aos.ability.kubernetes-object-owner/v1\0" + canonical(resource)
    owner = "sha256:" + hashlib.sha256(owner_input).hexdigest()
    qualification = mapping["qualification"]
    namespace = qualification.get("namespace")
    namespace_argument = "" if namespace is None else f" -n {shlex.quote(namespace)}"
    runtime.succeed(
        f"{KUBECTL} annotate {shlex.quote(qualification['object_kind'])} "
        f"{shlex.quote(qualification['name'])}{namespace_argument} "
        f"aos.andyl.com/resource-owner={shlex.quote(owner)} --overwrite"
    )


def adapter_from_cell(cell_id: str) -> str:
    """Returns the adapter component of one canonical matrix cell ID."""

    adapter = cell_id.split("/", 1)[0]
    if adapter not in PROVIDER_ORACLES:
        raise RuntimeError(f"no live-resource oracle for adapter {adapter!r}")
    return adapter


def observe_resource(
    cell_id: str,
    operation: dict[str, Any],
    foreign_operation: dict[str, Any],
    resource_map: dict[str, Any],
) -> dict[str, Any]:
    """Reads exact ownership, provider state, and a distinct live resource."""

    adapter = adapter_from_cell(cell_id)
    foreign_adapter = foreign_operation["adapter"]
    if foreign_adapter not in PROVIDER_ORACLES:
        raise RuntimeError(f"no foreign oracle for adapter {foreign_adapter!r}")
    target = operation["target"]["resource"]
    foreign_target = foreign_operation["operation"]["target"]["resource"]
    if target == foreign_target:
        raise RuntimeError("foreign observation names the interrupted resource")

    return {
        "owner": ownership_inventory(adapter, target),
        "live": live_observation(adapter, operation, resource_map),
        "foreign": {
            "adapter": foreign_adapter,
            "resource": foreign_target,
            "observation": live_observation(
                foreign_adapter, foreign_operation["operation"], resource_map
            ),
        },
    }


def ownership_inventory(adapter: str, resource: dict[str, Any]) -> dict[str, Any]:
    """Finds at most one provider marker carrying the exact resource identity."""

    identities = []
    for path, document in provider_documents(PROVIDER_ORACLES[adapter]["roots"]):
        if _contains_resource(document, resource):
            identities.append({"path": path, "resource": resource})
    identities.sort(key=lambda identity: identity["path"])
    if len(identities) > 1:
        raise RuntimeError(f"provider exposes duplicate owners for {resource!r}")
    return {"count": len(identities), "identities": identities}


def resource_documents(
    adapter: str, resource: dict[str, Any]
) -> list[tuple[str, Any]]:
    """Returns only provider markers bound to the selected resource."""

    return [
        (path, document)
        for path, document in provider_documents(PROVIDER_ORACLES[adapter]["roots"])
        if _contains_resource(document, resource)
    ]


def provider_documents(roots: list[str]) -> list[tuple[str, Any]]:
    """Loads bounded JSON provider markers from exact substrate roots."""

    documents = []
    for root in roots:
        paths = runtime.succeed(
            f"if test -d {shlex.quote(root)}; then "
            f"{FIND} {shlex.quote(root)} -xdev -type f -print; fi"
        ).splitlines()
        if len(paths) > 256:
            raise RuntimeError(f"provider marker inventory under {root} is unbounded")
        for path in paths:
            payload = runtime.succeed(f"{COREUTILS}/cat {shlex.quote(path)}")
            try:
                document = json.loads(payload)
            except json.JSONDecodeError:
                continue
            documents.append((path, document))
    return documents


def live_observation(
    adapter: str, operation: dict[str, Any], resource_map: dict[str, Any]
) -> dict[str, Any]:
    """Dispatches to an independent provider substrate observation."""

    resource = operation["target"]["resource"]
    documents = resource_documents(adapter, resource)
    mapping = exact_mapping(resource_map, resource)
    return live_observation_with_documents(adapter, operation, documents, mapping)


def live_observation_with_documents(
    adapter: str,
    operation: dict[str, Any],
    documents: list[tuple[str, Any]],
    mapping: dict[str, Any],
) -> dict[str, Any]:
    """Reads live state using an already selected exact marker set."""

    kind = PROVIDER_ORACLES[adapter]["live"]
    if kind == "filesystem":
        return exact_filesystem_snapshot(operation, documents)
    if kind == "network":
        return network_snapshot(operation, documents)
    if kind == "systemd":
        return systemd_snapshot(operation, documents, mapping)
    if kind == "kubernetes":
        return kubernetes_snapshot(operation, mapping)
    if kind == "postgresql":
        return postgresql_snapshot(operation, documents)
    if kind == "rollout":
        return rollout_snapshot(operation, documents)
    raise RuntimeError(f"unknown provider oracle {kind!r}")


def filesystem_snapshot(roots: list[str]) -> dict[str, Any]:
    """Hashes physical files and records their ownership and mode."""

    entries = []
    for root in roots:
        paths = runtime.succeed(
            f"if test -e {shlex.quote(root)}; then "
            f"{FIND} {shlex.quote(root)} -xdev -maxdepth 3 -print; fi"
        ).splitlines()
        if len(paths) > 512:
            raise RuntimeError(f"filesystem oracle under {root} is unbounded")
        for path in paths:
            fields = runtime.succeed(
                f"{COREUTILS}/stat -c '%F|%u|%g|%a|%s' {shlex.quote(path)}"
            ).strip()
            digest = None
            if fields.startswith("regular file|"):
                digest = runtime.succeed(
                    f"{COREUTILS}/sha256sum {shlex.quote(path)}"
                ).split()[0]
            entries.append({"path": path, "metadata": fields, "digest": digest})
    entries.sort(key=lambda entry: entry["path"])
    return {"kind": "filesystem", "entries": entries}


def exact_filesystem_snapshot(
    operation: dict[str, Any], documents: list[tuple[str, Any]]
) -> dict[str, Any]:
    """Snapshots markers and physical paths named by one exact resource."""

    paths = [path for path, _ in documents]
    values = [operation["inputs"], *[document for _, document in documents]]
    for value in values:
        paths.extend(
            literal
            for literal in string_literals(value)
            if literal.startswith("/") and ".." not in PurePosixPath(literal).parts
        )
    return filesystem_snapshot(paths)


def network_snapshot(
    operation: dict[str, Any], documents: list[tuple[str, Any]]
) -> dict[str, Any]:
    """Reads endpoint files, kernel addresses, listeners, and nftables policy."""

    values = [operation["inputs"], *[document for _, document in documents]]
    literals = [
        literal for value in values for literal in string_literals(value)
    ]
    ports = sorted({
        value
        for value in integer_literals(values)
        if 0 < value <= 65535
    })
    listener_lines = runtime.succeed(
        f"{SS} -H -lntup 2>/dev/null || true"
    ).splitlines()
    listeners = [
        line
        for line in listener_lines
        if any(f":{port} " in line for port in ports)
    ]
    tables = sorted({literal for literal in literals if literal.startswith("aos_p_")})
    return {
        "kind": "network",
        "filesystem": exact_filesystem_snapshot(operation, documents),
        "addresses": runtime.succeed(f"{IP} -json address show dev lo"),
        "listeners": listeners,
        "nftables": [
            runtime.succeed(
                f"{NFT} -j list table inet {shlex.quote(table)} 2>/dev/null || true"
            )
            for table in tables
        ],
    }


def systemd_snapshot(
    operation: dict[str, Any],
    documents: list[tuple[str, Any]],
    mapping: dict[str, Any],
) -> dict[str, Any]:
    """Reads the exact live unit when present plus provider revision receipts."""

    units = sorted(
        {mapping["qualification"]["unit"]}
        | {
            value
            for source in [operation["inputs"], *[document for _, document in documents]]
            for value in string_literals(source)
            if value.endswith(".service")
        }
    )
    observations = []
    for unit in units:
        result = runtime.succeed(
            f"{SYSTEMCTL} show {shlex.quote(unit)} "
            "-p Id -p LoadState -p ActiveState -p SubState -p FragmentPath "
            "-p InvocationID 2>/dev/null || true"
        )
        observations.append({"unit": unit, "properties": result})
    return {
        "kind": "systemd",
        "units": observations,
        "receipts": exact_filesystem_snapshot(operation, documents),
    }


def kubernetes_snapshot(
    operation: dict[str, Any], mapping: dict[str, Any]
) -> dict[str, Any]:
    """Reads the concrete Kubernetes object directly from the API server."""

    qualification = mapping["qualification"]
    name = qualification["name"]
    namespace = qualification.get("namespace")
    namespace_argument = "" if namespace is None else f" -n {shlex.quote(namespace)}"
    output = runtime.succeed(
        f"{KUBECTL} get {shlex.quote(qualification['object_kind'])} {shlex.quote(name)}"
        f"{namespace_argument} -o json 2>/dev/null || true"
    )
    return {
        "kind": "kubernetes",
        "identity": {
            "api-version": qualification["api_version"],
            "kind": qualification["object_kind"],
            "namespace": namespace,
            "name": name,
        },
        "api-document-digest": hashlib.sha256(output.encode()).hexdigest(),
        "api-document": json.loads(output) if output.strip() else None,
    }


def postgresql_snapshot(
    operation: dict[str, Any], documents: list[tuple[str, Any]]
) -> dict[str, Any]:
    """Reads owned cluster files and asks the live PostgreSQL servers for status."""

    sockets = runtime.succeed(
        f"{FIND} /run/aos-ability-postgresql -maxdepth 2 -type s "
        "-name '.s.PGSQL.*' -print 2>/dev/null || true"
    ).splitlines()
    readiness = []
    for socket in sockets:
        path = str(PurePosixPath(socket).parent)
        port = PurePosixPath(socket).name.rsplit(".", 1)[-1]
        readiness.append(
            {
                "socket": socket,
                "status": runtime.succeed(
                    f"{PG_ISREADY} -h {shlex.quote(path)} -p {shlex.quote(port)} "
                    "2>&1 || true"
                ).strip(),
            }
        )
    return {
        "kind": "postgresql",
        "filesystem": exact_filesystem_snapshot(operation, documents),
        "readiness": readiness,
        "input-digest": hashlib.sha256(canonical(operation["inputs"])).hexdigest(),
    }


def rollout_snapshot(
    operation: dict[str, Any], documents: list[tuple[str, Any]]
) -> dict[str, Any]:
    """Reads durable rollout state, boot entries, and the running kernel command line."""

    return {
        "kind": "image-rollout",
        "filesystem": filesystem_snapshot([
            "/var/lib/profiles/image/state.json",
            "/var/lib/profiles/image/ability-rollouts",
            "/boot/loader/entries",
            "/boot/EFI/.aos-rollout-retention",
        ]),
        "kernel-command-line": runtime.succeed(f"{COREUTILS}/cat /proc/cmdline").strip(),
    }


def string_literals(value: Any) -> list[str]:
    """Collects bounded string literals from a typed operation input tree."""

    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [literal for child in value for literal in string_literals(child)]
    if isinstance(value, dict):
        return [literal for child in value.values() for literal in string_literals(child)]
    return []


def integer_literals(value: Any) -> list[int]:
    """Collects integer fields from provider requests and state markers."""

    if isinstance(value, bool):
        return []
    if isinstance(value, int):
        return [value]
    if isinstance(value, list):
        return [literal for child in value for literal in integer_literals(child)]
    if isinstance(value, dict):
        return [literal for child in value.values() for literal in integer_literals(child)]
    return []


def kubernetes_objects(value: Any) -> list[dict[str, Any]]:
    """Finds exact Kubernetes object documents inside typed input values."""

    if isinstance(value, str) and value.startswith("{"):
        try:
            return kubernetes_objects(json.loads(value))
        except json.JSONDecodeError:
            return []
    if isinstance(value, list):
        return [candidate for child in value for candidate in kubernetes_objects(child)]
    if isinstance(value, dict):
        if (
            isinstance(value.get("apiVersion"), str)
            and isinstance(value.get("kind"), str)
            and isinstance(value.get("metadata"), dict)
            and _kubernetes_name(value["metadata"].get("name", ""))
        ):
            return [value]
        return [
            candidate
            for child in value.values()
            for candidate in kubernetes_objects(child)
        ]
    return []


def _contains_resource(value: Any, resource: dict[str, Any]) -> bool:
    if value == resource:
        return True
    if isinstance(value, list):
        return any(_contains_resource(child, resource) for child in value)
    if isinstance(value, dict):
        return any(_contains_resource(child, resource) for child in value.values())
    return False


def _kubernetes_name(value: str) -> bool:
    return (
        0 < len(value) <= 253
        and all(character.isalnum() or character in ".-" for character in value)
    )
