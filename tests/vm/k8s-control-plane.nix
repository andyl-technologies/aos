# tests/vm/k8s-control-plane.nix — Kubernetes control plane config test
#
# Verifies control plane components: containerd, kubelet, k8s networking,
# plus control-plane-specific config (kubeadm, etcd directory).
# Uses the k8s-control-plane variant.
#
# Usage:
#   nix-build -A checks.vm.k8s-control-plane
{
  pkgs,
  lib,
  systems,
  testTools,
}: let
  harness = import ../../lib/testing {inherit pkgs lib testTools;};
  containerSupport = import ./checks/container-support.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
  containerd = import ./checks/containerd.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
  kubelet = import ./checks/kubelet.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
  k8sNetworking = import ./checks/k8s-networking.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
in
  harness.mkVMTest {
    name = "k8s-control-plane";
    system = systems.k8s-control-plane;
    timeout = 300;
    checks = [
      containerSupport
      containerd
      kubelet
      k8sNetworking
    ];
    testScript = ''
      # Control-plane-specific checks (kubeadm config, etcd dir)
      assert_success "test -d /etc/kubernetes" \
        "/etc/kubernetes directory exists"
      assert_success "test -d /var/lib/etcd" \
        "/var/lib/etcd directory exists"
    '';
  }
