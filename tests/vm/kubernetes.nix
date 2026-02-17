# tests/vm/kubernetes.nix — Kubernetes component test
#
# Verifies containerd, kubelet, CNI plugins, required kernel features,
# and Kubernetes-specific sysctl values on a k8s-worker image.
#
# Usage:
#   nix-build -A checks.vm.kubernetes
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
    name = "kubernetes";
    system = systems.k8s-worker;
    timeout = 300;
    checks = [
      containerSupport
      containerd
      kubelet
      k8sNetworking
    ];
  }
