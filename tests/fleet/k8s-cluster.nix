# tests/fleet/k8s-cluster.nix — Kubernetes cluster formation test
#
# Boots a control-plane node and a worker node, runs kubeadm init on the
# control plane, joins the worker, verifies both nodes reach Ready state,
# and schedules a test pod.
#
# Usage:
#   nix-build -A checks.fleet.k8s-cluster

{
  pkgs,
  lib,
  systems,
}:

let
  fleetLib = import ./lib.nix { inherit pkgs lib; };
in
fleetLib.mkFleetTest {
  name = "k8s-cluster";
  machines = {
    control-plane = {
      system = systems.k8s-control-plane;
      role = "control-plane";
      netPort = 10001;
      mac = "52:54:00:00:00:01";
    };
    worker = {
      system = systems.k8s-worker;
      role = "worker";
      netPort = 10002;
      mac = "52:54:00:00:00:02";
    };
  };
  testScript = ''
    # Wait for both machines to be fully booted
    assert_on "control-plane" "systemctl is-system-running --wait" \
      "Control plane booted"
    assert_on "worker" "systemctl is-system-running --wait" \
      "Worker booted"

    # Initialize the control plane with kubeadm
    assert_on "control-plane" \
      "kubeadm init --pod-network-cidr=10.244.0.0/16 --skip-phases=addon/kube-proxy" \
      "kubeadm init succeeded"

    # Get the join command token from the control plane
    JOIN_CMD=$(run_on "control-plane" "kubeadm token create --print-join-command" | jq -r '.stdout')

    # Join the worker to the cluster
    assert_on "worker" "$JOIN_CMD" \
      "Worker joined cluster"

    # Verify both nodes are registered and Ready
    assert_on "control-plane" \
      "kubectl --kubeconfig=/etc/kubernetes/admin.conf get nodes | grep -c Ready | grep -q 2" \
      "Both nodes are Ready"

    # Schedule a test pod
    assert_on "control-plane" \
      "kubectl --kubeconfig=/etc/kubernetes/admin.conf run test-pod --image=registry.k8s.io/pause:3.10 --restart=Never" \
      "Test pod created"

    # Wait for the test pod to be running
    assert_on "control-plane" \
      "kubectl --kubeconfig=/etc/kubernetes/admin.conf wait --for=condition=Ready pod/test-pod --timeout=60s" \
      "Test pod reached Ready state"
  '';
  timeout = 600;
}
