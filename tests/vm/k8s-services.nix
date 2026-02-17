# tests/vm/k8s-services.nix — Kubernetes services depth test
#
# Verifies the full k8s worker stack: containerd, kubelet, k8s networking
# prerequisites, and node-exporter. Uses the k8s-worker variant.
#
# Usage:
#   nix-build -A checks.vm.k8s-services
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
  nodeExporter = import ./checks/node-exporter.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
in
  harness.mkVMTest {
    name = "k8s-services";
    system = systems.k8s-worker;
    timeout = 300;
    checks = [
      containerSupport
      containerd
      kubelet
      k8sNetworking
      nodeExporter
    ];
  }
