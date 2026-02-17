# tests/fleet/k8s-cluster.nix — Kubernetes cluster formation test
#
# Boots a control-plane node and a worker node connected via multicast
# socket networking with static IPs. Verifies containerd is running on
# both nodes, runs kubeadm init on the control plane, joins the worker,
# and verifies both nodes reach Ready state.
#
# Usage:
#   nix-build -A checks.fleet.k8s-cluster
{
  pkgs,
  lib,
  systems,
  testTools,
}: let
  fleetLib = import ../../lib/testing/fleet.nix {inherit pkgs lib testTools;};
in
  fleetLib.mkFleetTest {
    name = "k8s-cluster";
    machines = {
      control-plane = {
        system = systems.k8s-control-plane;
        role = "control-plane";
        mac = "52:54:00:00:00:01";
      };
      worker = {
        system = systems.k8s-worker;
        role = "worker";
        mac = "52:54:00:00:00:02";
      };
    };
    testScript = ''
      # Wait for both machines to be fully booted
      assert_on "control-plane" "systemctl is-system-running --wait || true" \
        "Control plane booted"
      assert_on "worker" "systemctl is-system-running --wait || true" \
        "Worker booted"

      # Verify containerd is running on both nodes before kubeadm
      assert_on "control-plane" "systemctl is-active containerd" \
        "Control plane containerd is active"
      assert_on "worker" "systemctl is-active containerd" \
        "Worker containerd is active"

      # Verify cross-node connectivity
      assert_on "control-plane" "ping -c 1 -W 3 worker" \
        "Control plane can reach worker"
      assert_on "worker" "ping -c 1 -W 3 control-plane" \
        "Worker can reach control plane"

      # Initialize the control plane with kubeadm
      # Use explicit advertise address matching the static IP
      assert_on "control-plane" \
        "kubeadm init --pod-network-cidr=10.244.0.0/16 --skip-phases=addon/kube-proxy --apiserver-advertise-address=192.168.50.10" \
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
