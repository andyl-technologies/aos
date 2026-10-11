"""Checks a running K3s cluster independently of how its packages were installed.

Callers supply a guest command interface and the kubectl path from the tested
package. This keeps the behavioral assertions reusable by repository fleets
and release qualification using authenticated staged artifacts.
"""

import ipaddress
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


def assert_k3s_default_addons(machine, kubectl):
    """Requires the bundled default controllers and aggregated metrics API.

    Helm must install the embedded Traefik chart, and service-lb must make its
    resulting service available. Inspect actual pod images to reject an
    accidental fallback to an upstream binary image.
    """

    client = shlex.join([kubectl, "--kubeconfig=/etc/rancher/k3s/k3s.yaml"])
    scoped = client + " --namespace=kube-system"
    try:
        for deployment in (
            "coredns", "metrics-server", "local-path-provisioner", "traefik"
        ):
            machine.wait_until_succeeds(
                scoped + " rollout status deployment/" + deployment + " --timeout=1s",
                timeout=240,
            )
        machine.wait_until_succeeds(
            client
            + " wait --for=condition=Available apiservice/v1beta1.metrics.k8s.io --timeout=1s",
            timeout=120,
        )
        nodes = json.loads(machine.succeed(client + " get nodes -o json"))["items"]
        for node in nodes:
            name = node["metadata"]["name"]
            query = client + " get --raw=" + shlex.quote(
                "/apis/metrics.k8s.io/v1beta1/nodes/" + name
            )
            machine.wait_until_succeeds(query, timeout=120)
            metrics = json.loads(machine.succeed(query))
            if not {"cpu", "memory"}.issubset(metrics.get("usage", {})):
                raise AssertionError(f"K3s metrics server has no resource sample for {name}")

        machine.wait_until_succeeds(
            scoped
            + " get service traefik -o jsonpath='{.status.loadBalancer.ingress[0].ip}'"
            + " | grep -Eq '^[0-9]+[.]'",
            timeout=120,
        )

        pods = json.loads(machine.succeed(scoped + " get pods -o json"))["items"]
        observed = set()
        for pod in pods:
            containers = (
                pod["spec"].get("initContainers", []) + pod["spec"]["containers"]
            )
            for container in containers:
                image = container["image"]
                match = re.fullmatch(
                    r"aos[.]invalid/k3s/([a-z-]+)(?::[^@]+)?@sha256:[0-9a-f]{64}",
                    image,
                )
                if match is None:
                    raise AssertionError(f"default addon uses an unbound image: {image}")
                observed.add(match.group(1))
        required = {
            "coredns", "metrics-server", "local-path-provisioner", "traefik", "service-lb"
        }
        if not required.issubset(observed):
            missing = sorted(required - observed)
            raise AssertionError(f"missing default addon workloads: {missing}")
    except Exception:
        for query in (
            " get pods -o wide",
            " get jobs -o wide",
            " get events --sort-by=.metadata.creationTimestamp",
            " logs deployment/coredns --all-containers=true --tail=100",
            " logs deployment/metrics-server --all-containers=true --tail=100",
            " logs deployment/local-path-provisioner --all-containers=true --tail=100",
            " logs deployment/traefik --all-containers=true --tail=100",
            " logs job/helm-install-traefik --all-containers=true --tail=100",
            " logs job/helm-install-traefik-crd --all-containers=true --tail=100",
        ):
            try:
                print(machine.succeed(scoped + query, timeout=30))
            except Exception as diagnostic_error:
                print(f"K3s addon diagnostic failed: {diagnostic_error}")
        raise


def assert_k3s_addon_services(machine, kubectl, inventory_path, node_name, namespace):
    """Exercises DNS, Traefik, local volumes, and network-policy enforcement.

    The bundled helper image supplies Bash and its DNS-capable TCP redirection.
    Two separate pods share a claim so the read verifies persistent storage.
    Node selection goes through the scheduler because local-path volumes use
    WaitForFirstConsumer binding. Egress probes verify deny and allow policy
    transitions before the namespace and its persistent volume are removed.
    """

    inventory = json.loads(machine.succeed("cat " + shlex.quote(inventory_path)))
    helpers = [entry for entry in inventory["images"] if entry["name"] == "local-path-helper"]
    if inventory.get("schema") != "aos.k3s.addon-images/v1" or len(helpers) != 1:
        raise ValueError("K3s addon service test requires the bundled helper inventory")
    image = helpers[0]["repository"] + "@" + helpers[0]["digest"]
    if re.fullmatch(r"aos[.]invalid/k3s/local-path-helper@sha256:[0-9a-f]{64}", image) is None:
        raise ValueError("K3s addon service test requires the immutable helper image")
    for name in (node_name, namespace):
        if re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", name) is None:
            raise ValueError("K3s addon test node and namespace must be DNS labels")

    client = shlex.join([kubectl, "--kubeconfig=/etc/rancher/k3s/k3s.yaml"])
    scoped = client + " --namespace=" + shlex.quote(namespace)

    def create(resource):
        machine.succeed(
            "printf %s " + shlex.quote(json.dumps(resource)) + " | " + scoped + " create -f -"
        )

    def run_pod(name, script, expected_output, network_probe=False):
        metadata = {"name": name, "namespace": namespace}
        if network_probe:
            metadata["labels"] = {"aos.andyl.org/network-policy-probe": "true"}

        create({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": metadata,
            "spec": {
                "nodeSelector": {"kubernetes.io/hostname": node_name},
                "restartPolicy": "Never",
                "activeDeadlineSeconds": 180,
                "automountServiceAccountToken": False,
                "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "data"}}],
                "containers": [{
                    "name": "probe",
                    "image": image,
                    "imagePullPolicy": "Never",
                    "command": ["bash", "-euc", script],
                    "volumeMounts": [{"name": "data", "mountPath": "/data"}],
                    "resources": {
                        "requests": {"cpu": "100m", "memory": "32Mi"},
                        "limits": {"cpu": "500m", "memory": "128Mi"},
                    },
                }],
            },
        })
        machine.wait_until_succeeds(
            scoped + " wait --for=jsonpath='{.status.phase}'=Succeeded --timeout=1s pod/" + name,
            timeout=240,
        )
        output = machine.succeed(scoped + " logs " + name)
        if output != expected_output:
            raise AssertionError(f"K3s addon {name} output differs: {output!r}")

    machine.succeed(client + " create namespace " + shlex.quote(namespace))
    try:
        create({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {"name": "data", "namespace": namespace},
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": "local-path",
                "resources": {"requests": {"storage": "16Mi"}},
            },
        })
        run_pod("writer", r'''
exec 3<>/dev/tcp/kubernetes.default.svc.cluster.local/443
exec 3>&-
printf 'persistent-volume-passed\n' > /data/evidence

exec 3<>/dev/tcp/traefik.kube-system.svc.cluster.local/80
printf 'GET / HTTP/1.1\r\nHost: qualification.invalid\r\nConnection: close\r\n\r\n' >&3
IFS= read -r response <&3
[[ "$response" == "HTTP/1.1 404 "* ]]
exec 3>&-
printf 'dns-storage-ingress-passed\n'
''', "dns-storage-ingress-passed\n")
        run_pod("reader", r'''
IFS= read -r evidence < /data/evidence
[[ "$evidence" == "persistent-volume-passed" ]]
printf '%s\n' "$evidence"
''', "persistent-volume-passed\n")

        claim = json.loads(machine.succeed(scoped + " get pvc data -o json"))
        volume = claim["spec"]["volumeName"]
        if claim["status"]["phase"] != "Bound" or not volume:
            raise AssertionError("K3s local-path claim is not bound to a persistent volume")

        # Reach the worker's exposed port from the host network namespace to
        # exercise service-lb as well as the ClusterIP path checked by the pod.
        worker = json.loads(machine.succeed(client + " get node " + shlex.quote(node_name) + " -o json"))
        addresses = [
            str(ipaddress.ip_address(entry["address"]))
            for entry in worker["status"]["addresses"]
            if entry["type"] == "InternalIP"
        ]
        if not addresses:
            raise AssertionError("K3s service-lb probe requires the worker's internal address")
        ingress_probe = """
exec 3<>/dev/tcp/ADDRESS/80
printf 'GET / HTTP/1.1\\r\\nHost: qualification.invalid\\r\\nConnection: close\\r\\n\\r\\n' >&3
IFS= read -r response <&3
[[ "$response" == "HTTP/1.1 404 "* ]]
""".replace("ADDRESS", addresses[0])
        machine.wait_until_succeeds(
            "timeout 5 bash -euc " + shlex.quote(ingress_probe), timeout=120
        )

        # Check both transitions so an unrelated connectivity failure cannot
        # stand in for an enforced network policy. Use the API address directly
        # because the deny rule intentionally blocks DNS as well.
        service = json.loads(machine.succeed(
            client + " --namespace=default get service kubernetes -o json"
        ))
        address = str(ipaddress.ip_address(service["spec"]["clusterIP"]))
        connection = shlex.quote("exec 3<>/dev/tcp/" + address + "/443")
        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "probe-egress", "namespace": namespace},
            "spec": {
                "podSelector": {
                    "matchLabels": {"aos.andyl.org/network-policy-probe": "true"}
                },
                "policyTypes": ["Egress"],
                "egress": [],
            },
        }
        create(policy)
        run_pod("egress-denied", """
for attempt in {1..30}; do
    if timeout 2 bash -c CONNECTION 2>/dev/null; then
        sleep 1
    else
        printf 'egress-denied\\n'
        exit 0
    fi
done
exit 1
""".replace("CONNECTION", connection), "egress-denied\n", network_probe=True)

        policy["spec"]["egress"] = [{}]
        machine.succeed(
            "printf %s " + shlex.quote(json.dumps(policy))
            + " | " + scoped + " apply -f -"
        )
        run_pod("egress-allowed", """
for attempt in {1..30}; do
    if timeout 2 bash -c CONNECTION 2>/dev/null; then
        printf 'egress-allowed\\n'
        exit 0
    fi
    sleep 1
done
exit 1
""".replace("CONNECTION", connection), "egress-allowed\n", network_probe=True)
    except Exception:
        for query in (
            " get pods,pvc -o wide",
            " describe pods",
            " get events --sort-by=.metadata.creationTimestamp",
            " logs writer",
            " logs reader",
            " logs egress-denied",
            " logs egress-allowed",
        ):
            try:
                print(machine.succeed(scoped + query, timeout=30))
            except Exception as diagnostic_error:
                print(f"K3s addon service diagnostic failed: {diagnostic_error}")
        raise

    # A failed attempt keeps its namespace for diagnostics. Successful probes
    # require deletion to exercise the provisioner's teardown helper as well.
    machine.succeed(
        client + " delete namespace " + shlex.quote(namespace) + " --wait=true --timeout=90s",
        timeout=120,
    )
    machine.wait_until_succeeds(
        client + " wait --for=delete pv/" + shlex.quote(volume) + " --timeout=1s",
        timeout=120,
    )


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
