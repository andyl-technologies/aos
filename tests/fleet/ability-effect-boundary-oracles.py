"""Provider-specific live-resource observations for matrix crash flights.

Every oracle reads state from the provider's external substrate. Durable
execution journals and boundary transcripts are deliberately unavailable here.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from pathlib import PurePosixPath
from typing import Any


PROVIDER_ORACLES = {
    "credential-delivery": {
        "roots": ["/var/lib/aos/ability-runtime/credentials"],
        "live": "filesystem",
    },
    "foreground-process": {
        "roots": ["/var/lib/aos/ability-runtime/foreground-process"],
        "live": "foreground-process",
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
        "roots": ["/var/lib/aos/ability-runtime/nginx"],
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


def canonical(value: Any) -> bytes:
    """Encodes one provider observation with stable JSON ordering."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


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
        "live": live_observation(adapter, operation),
        "foreign": {
            "adapter": foreign_adapter,
            "resource": foreign_target,
            "observation": live_observation(
                foreign_adapter, foreign_operation["operation"]
            ),
        },
    }


def ownership_inventory(adapter: str, resource: dict[str, Any]) -> dict[str, Any]:
    """Reads exact owner rows from the authoritative native resource ledger."""

    if adapter not in PROVIDER_ORACLES:
        raise RuntimeError(f"no ownership oracle for adapter {adapter!r}")
    ledger = native_resource_ledger()
    owners = ledger["owners"]

    identities = [owner for owner in owners if owner.get("resource") == resource]
    identities.sort(key=canonical)
    if len(identities) > 1:
        raise RuntimeError(f"native ledger exposes duplicate owners for {resource!r}")
    return {"count": len(identities), "identities": identities}


def native_resource_ledger() -> dict[str, Any]:
    """Returns the bounded authoritative owner and consumer ledger."""

    ledger_path = (
        "/var/lib/profiles/system/current/.ability-native-resources.json"
    )
    payload = runtime.succeed(
        f"if test -f {shlex.quote(ledger_path)}; then "
        f"{COREUTILS}/cat {shlex.quote(ledger_path)}; "
        "else printf '%s' '{\"schema\":\"aos.ability.native-resource-ledger/v1\","
        "\"owners\":[],\"consumers\":[]}'; fi"
    )
    ledger = json.loads(payload)
    if ledger.get("schema") != "aos.ability.native-resource-ledger/v1":
        raise RuntimeError("native ownership ledger has an unexpected schema")
    owners = ledger.get("owners")
    consumers = ledger.get("consumers")
    if (
        not isinstance(owners, list)
        or len(owners) > 4096
        or not isinstance(consumers, list)
        or len(consumers) > 4096
    ):
        raise RuntimeError("native ownership ledger inventory is malformed")
    return ledger


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
            f"{FIND} {shlex.quote(root)} -xdev -type f -name '*.json' -print; fi"
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


def live_observation(adapter: str, operation: dict[str, Any]) -> dict[str, Any]:
    """Dispatches to an independent provider substrate observation."""

    oracle = PROVIDER_ORACLES[adapter]
    kind = oracle["live"]
    resource = operation["target"]["resource"]
    documents = resource_documents(adapter, resource)
    if kind == "filesystem":
        return exact_filesystem_snapshot(operation, documents)
    if kind == "network":
        return network_snapshot(operation, documents)
    if kind == "systemd":
        return systemd_snapshot(operation, documents)
    if kind == "kubernetes":
        return kubernetes_snapshot(operation)
    if kind == "postgresql":
        return postgresql_snapshot(operation, documents)
    if kind == "rollout":
        return rollout_snapshot(operation, documents)
    if kind == "foreground-process":
        return foreground_process_snapshot(operation, documents)
    raise RuntimeError(f"unknown provider oracle {kind!r}")


def filesystem_snapshot(roots: list[str]) -> dict[str, Any]:
    """Hashes bounded physical files and records ownership and mode."""

    entries = []
    for root in sorted(set(roots)):
        paths = runtime.succeed(
            f"if test -e {shlex.quote(root)}; then "
            f"{FIND} {shlex.quote(root)} -xdev -maxdepth 1 -print; fi"
        ).splitlines()
        if len(paths) > 512:
            raise RuntimeError(f"filesystem oracle under {root} is unbounded")
        for path in paths:
            fields = runtime.succeed(
                f"{COREUTILS}/stat -c '%F|%u|%g|%a|%s|%y|%z' "
                f"{shlex.quote(path)}"
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
    observable_prefixes = (
        "/boot/loader/entries/",
        "/etc/aos/ability-revisions/",
        "/run/aos-ability-postgresql/",
        "/var/lib/aos/",
        "/var/lib/profiles/image/ability-rollouts/",
    )
    for value in values:
        paths.extend(
            literal
            for literal in string_literals(value)
            if literal.startswith(observable_prefixes)
            and ".." not in PurePosixPath(literal).parts
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
    operation: dict[str, Any], documents: list[tuple[str, Any]]
) -> dict[str, Any]:
    """Reads the exact live unit when present plus provider revision receipts."""

    units = sorted({
        value
        for source in [operation["inputs"], *[document for _, document in documents]]
        for value in string_literals(source)
        if value.endswith(".service")
    })
    observations = []
    effect_markers = []
    for unit in units:
        result = runtime.succeed(
            f"{SYSTEMCTL} show {shlex.quote(unit)} "
            "-p Id -p LoadState -p ActiveState -p SubState -p FragmentPath "
            "-p InvocationID 2>/dev/null || true"
        )
        observations.append({"unit": unit, "properties": result})
        if unit == "nginx-main.service":
            effect_markers.append("/run/ability-nginx-reload.calls")
        elif unit.startswith("aos-matrix-"):
            effect_markers.append(
                "/run/" + unit.removesuffix(".service") + ".reloaded"
            )
    return {
        "kind": "systemd",
        "units": observations,
        "receipts": exact_filesystem_snapshot(operation, documents),
        "effect-markers": filesystem_snapshot(effect_markers),
    }


def kubernetes_snapshot(operation: dict[str, Any]) -> dict[str, Any]:
    """Reads the concrete Kubernetes object directly from the API server."""

    objects = kubernetes_objects(operation["inputs"])
    if len(objects) != 1:
        raise RuntimeError("Kubernetes operation does not carry one exact object")
    document = objects[0]
    metadata = document["metadata"]
    name = metadata["name"]
    namespace = metadata.get("namespace")
    namespace_argument = "" if namespace is None else f" -n {shlex.quote(namespace)}"
    output = runtime.succeed(
        f"{KUBECTL} --kubeconfig=/etc/rancher/k3s/k3s.yaml "
        f"get {shlex.quote(document['kind'])} {shlex.quote(name)}"
        f"{namespace_argument} -o json 2>/dev/null || true"
    )
    api_document = json.loads(output) if output.strip() else None
    if api_document is not None:
        object_metadata = api_document.get("metadata", {})
        stable_metadata = {
            field: object_metadata[field]
            for field in (
                "annotations",
                "deletionTimestamp",
                "generation",
                "labels",
                "name",
                "namespace",
                "ownerReferences",
                "uid",
            )
            if field in object_metadata
        }
        api_document = {
            "apiVersion": api_document.get("apiVersion"),
            "kind": api_document.get("kind"),
            "metadata": stable_metadata,
            "spec": api_document.get("spec"),
        }
    encoded_api_document = canonical(api_document)
    return {
        "kind": "kubernetes",
        "identity": {
            "api-version": document["apiVersion"],
            "kind": document["kind"],
            "namespace": namespace,
            "name": name,
        },
        "api-document-digest": hashlib.sha256(encoded_api_document).hexdigest(),
        "api-document": api_document,
    }


def postgresql_snapshot(
    operation: dict[str, Any], documents: list[tuple[str, Any]]
) -> dict[str, Any]:
    """Reads owned cluster files and asks the live PostgreSQL servers for status."""

    sockets = []
    for _, document in documents:
        details = document.get("details") if isinstance(document, dict) else None
        if not isinstance(details, dict):
            continue
        run_path = details.get("run_path")
        server_port = details.get("server_port")
        if (
            isinstance(run_path, str)
            and run_path.startswith("/run/aos-ability-postgresql/")
            and isinstance(server_port, int)
            and 1 <= server_port <= 65535
        ):
            sockets.append(f"{run_path}/.s.PGSQL.{server_port}")
    sockets = sorted(set(sockets))
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

    roots = [
        "/var/lib/profiles/image/state.json",
        "/var/lib/profiles/image/ability-rollouts",
        "/boot/loader/loader.conf",
        "/boot/loader/entries",
        "/boot/EFI/.aos-rollout-retention",
    ]
    paths = []
    for root in roots:
        paths.extend(
            runtime.succeed(
                f"if test -e {shlex.quote(root)}; then "
                f"{FIND} {shlex.quote(root)} -xdev -maxdepth 4 "
                r"\( -type f -o -type l \) -print; fi"
            ).splitlines()
        )
    paths = sorted(set(paths))
    if not 1 <= len(paths) <= 512:
        raise RuntimeError("rollout physical-state inventory is absent or unbounded")

    return {
        "kind": "image-rollout",
        "filesystem": filesystem_snapshot(paths),
        "hook-state": filesystem_snapshot([
            "/var/lib/aos-test/drained-boot-id",
            "/var/lib/aos-test/health-observations",
        ]),
        "kernel-command-line": runtime.succeed(f"{COREUTILS}/cat /proc/cmdline").strip(),
    }


def foreground_process_snapshot(
    operation: dict[str, Any], documents: list[tuple[str, Any]]
) -> dict[str, Any]:
    """Authenticates a receipt against the exact live process confinement."""

    matching = [
        (path, document)
        for path, document in documents
        if document.get("schema") == "aos.ability.foreground-process-state/v1"
    ]
    if len(matching) > 1:
        raise RuntimeError("foreground resource has multiple durable receipts")
    if not matching:
        return {
            "kind": "foreground-process",
            "receipt": None,
            "process": None,
        }

    path, receipt = matching[0]
    request = receipt.get("request")
    if not isinstance(request, dict) or request.get("resource") != operation["target"]["resource"]:
        raise RuntimeError("foreground receipt names another logical resource")
    identity = receipt.get("identity")
    if identity is None:
        process = None
    else:
        pid = identity.get("pid")
        process_group = identity.get("process_group")
        if (
            not isinstance(pid, int)
            or pid <= 0
            or not isinstance(process_group, int)
            or process_group != pid
        ):
            raise RuntimeError("foreground receipt has an invalid process identity")
        prefix = f"/proc/{pid}"
        ownership = receipt.get("ownership_token")
        if not isinstance(ownership, str) or not ownership:
            raise RuntimeError("foreground receipt lacks an ownership token")
        environment = runtime.succeed(
            f"{COREUTILS}/tr '\\000' '\\n' < {shlex.quote(prefix + '/environ')}"
        ).splitlines()
        if f"AOS_FOREGROUND_PROCESS_OWNERSHIP={ownership}" not in environment:
            raise RuntimeError("live foreground process lacks the exact ownership token")
        process = {
            "identity": identity,
            "executable": runtime.succeed(
                f"{COREUTILS}/readlink {shlex.quote(prefix + '/exe')}"
            ).strip(),
            "command-line": runtime.succeed(
                f"{COREUTILS}/tr '\\000' '\\n' < {shlex.quote(prefix + '/cmdline')}"
            ).splitlines(),
            "cgroup": runtime.succeed(
                f"{COREUTILS}/cat {shlex.quote(prefix + '/cgroup')}"
            ).strip(),
            "namespaces": {
                namespace: runtime.succeed(
                    f"{COREUTILS}/readlink "
                    f"{shlex.quote(prefix + '/ns/' + namespace)}"
                ).strip()
                for namespace in ["mnt", "net", "pid", "user"]
            },
            "ownership-token-digest": hashlib.sha256(
                ownership.encode()
            ).hexdigest(),
        }
    return {
        "kind": "foreground-process",
        "receipt": {
            "path": path,
            "digest": hashlib.sha256(canonical(receipt)).hexdigest(),
            "document": receipt,
        },
        "process": process,
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
