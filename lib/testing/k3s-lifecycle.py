"""Checks a running K3s cluster independently of how its packages were installed.

Callers supply a guest command interface and the kubectl path from the tested
package. This keeps the behavioral assertions reusable by repository fleets
and release qualification using authenticated staged artifacts.
"""

import json
import re
import shlex


def assert_k3s_cluster(machine, kubectl, expected_nodes, combined_node=None):
    """Requires a healthy API, the exact ready node set, and role scheduling.

    The guest interface provides ``succeed`` and ``wait_until_succeeds``.
    Authentication uses the cluster's generated administrator kubeconfig.
    """

    if not expected_nodes or len(expected_nodes) != len(set(expected_nodes)):
        raise ValueError("K3s expected nodes must be nonempty and unique")
    if combined_node is not None and combined_node not in expected_nodes:
        raise ValueError("K3s combined node must belong to the expected node set")

    command = shlex.join([kubectl, "--kubeconfig=/etc/rancher/k3s/k3s.yaml"])
    machine.wait_until_succeeds(
        command + " get --raw=/healthz | grep -qx ok", timeout=60
    )
    for name in expected_nodes:
        machine.wait_until_succeeds(
            command
            + " wait --for=condition=Ready --timeout=1s "
            + shlex.quote("node/" + name),
            timeout=180,
        )

    inventory = json.loads(machine.succeed(command + " get nodes -o json"))
    nodes = inventory["items"]
    actual_names = [node["metadata"]["name"] for node in nodes]
    if sorted(actual_names) != sorted(expected_nodes):
        raise AssertionError(
            f"expected K3s nodes {sorted(expected_nodes)!r}, got {actual_names!r}"
        )
    for node in nodes:
        ready = [
            condition["status"]
            for condition in node["status"]["conditions"]
            if condition["type"] == "Ready"
        ]
        if ready != ["True"]:
            raise AssertionError(f"K3s node {node['metadata']['name']} is not Ready")
        if node["metadata"]["name"] == combined_node and node["spec"].get("taints"):
            raise AssertionError("K3s combined node has unexpected scheduling taints")

    node_ids = {node["metadata"]["name"]: node["metadata"]["uid"] for node in nodes}
    namespace = json.loads(machine.succeed(command + " get namespace kube-system -o json"))
    cluster_id = namespace["metadata"]["uid"]
    if not cluster_id or not all(node_ids.values()):
        raise AssertionError("K3s cluster does not expose persistent API object identities")

    return {
        "ready_nodes": sorted(actual_names),
        "node_ids": node_ids,
        "cluster_id": cluster_id,
        "api_healthy": True,
    }


def import_k3s_workload(machine, ctr, crictl, archive, image):
    """Imports a local OCI archive and requires its digest alias in CRI."""

    if re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image) is None:
        raise ValueError("K3s workload import requires a SHA-256 image reference")
    # Match K3s's direct containerd import path. Transfer-service imports can
    # complete without making the requested digest alias visible to kubelet.
    machine.succeed(
        shlex.join([
            ctr, "--namespace", "k8s.io", "images", "import", "--local",
            "--digests", "--base-name", image.split("@", 1)[0],
            "--label", "io.cri-containerd.image=managed", archive,
        ])
    )
    inspect = shlex.join([crictl, "inspecti", image])
    machine.wait_until_succeeds(inspect, timeout=30)
    status = json.loads(machine.succeed(inspect))["status"]
    if image not in status["repoDigests"] or not status["id"]:
        raise AssertionError("K3s CRI does not expose the imported workload digest")
    return status["id"]


def assert_k3s_workload(
    machine, kubectl, image, command, expected_stdout, node_name, namespace
):
    """Runs an imported image by digest and checks its exit status and output.

    The caller authenticates and imports the image on the selected node first.
    Pulling is disabled so a registry cannot replace or supply missing content.
    The namespace must be unique to the attempt; an existing namespace fails
    creation rather than being reused or removed by this check.
    """

    if re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image) is None:
        raise ValueError("K3s workload requires an image reference with a SHA-256 digest")
    if not command or not all(isinstance(value, str) and value for value in command):
        raise ValueError("K3s workload requires a nonempty command")
    for name in (node_name, namespace):
        if re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", name) is None:
            raise ValueError("K3s workload node and namespace must be DNS labels")

    client = shlex.join([kubectl, "--kubeconfig=/etc/rancher/k3s/k3s.yaml"])
    scoped = client + " --namespace=" + shlex.quote(namespace)
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "qualification-workload", "namespace": namespace},
        "spec": {
            "nodeName": node_name,
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [
                {
                    "name": "workload",
                    "image": image,
                    "imagePullPolicy": "Never",
                    "command": command,
                    "resources": {
                        "requests": {"cpu": "100m", "memory": "32Mi"},
                        "limits": {"cpu": "500m", "memory": "128Mi"},
                    },
                }
            ],
        },
    }

    machine.succeed(client + " create namespace " + shlex.quote(namespace))
    try:
        machine.succeed(
            "printf %s " + shlex.quote(json.dumps(pod)) + " | " + scoped + " create -f -"
        )
        machine.wait_until_succeeds(
            scoped
            + " wait --for=jsonpath='{.status.phase}'=Succeeded --timeout=1s"
            + " pod/qualification-workload",
            timeout=180,
        )
        observed = json.loads(
            machine.succeed(scoped + " get pod qualification-workload -o json")
        )
        status = observed["status"]["containerStatuses"]
        if (
            observed["spec"]["nodeName"] != node_name
            or observed["spec"]["containers"][0]["image"] != image
            or len(status) != 1
            or status[0]["state"]["terminated"]["exitCode"] != 0
            or not status[0].get("imageID")
        ):
            raise AssertionError("K3s workload did not complete with the selected image and node")
        output = machine.succeed(scoped + " logs qualification-workload -c workload")
        if output != expected_stdout:
            raise AssertionError(f"K3s workload output differs: {output!r}")
        result = {"node": node_name, "image": image, "image_id": status[0]["imageID"]}
    except Exception:
        # Keep the workload failure authoritative if API discovery also prevents
        # namespace deletion. Retain pod state before requesting cleanup.
        try:
            print(
                machine.succeed(
                    scoped + " describe pod qualification-workload 2>&1 || true",
                    timeout=30,
                )
            )
            print(
                machine.succeed(
                    scoped + " get events --sort-by=.metadata.creationTimestamp 2>&1 || true",
                    timeout=30,
                )
            )
            machine.succeed(
                client + " delete namespace " + shlex.quote(namespace) + " --wait=false",
                timeout=30,
            )
        except Exception as cleanup_error:
            print(f"K3s workload diagnostics or cleanup failed: {cleanup_error}")
        raise

    try:
        machine.succeed(
            client + " delete namespace " + shlex.quote(namespace) + " --wait=true --timeout=60s",
            timeout=90,
        )
    except Exception:
        # Namespace finalization depends on API discovery as well as pod
        # removal. Preserve both states without bypassing any finalizers.
        for diagnostic in (
            client + " get namespace " + shlex.quote(namespace) + " -o json",
            client + " get apiservices -o json",
            client + " get pods --all-namespaces -o wide",
            scoped + " get pods -o json",
        ):
            try:
                print(machine.succeed(diagnostic, timeout=30))
            except Exception as diagnostic_error:
                print(f"K3s cleanup diagnostic failed: {diagnostic_error}")
        raise
    return result
