# tests/fleet/default.nix — Fleet (multi-VM) test suite
#
# Multi-VM orchestration tests that boot several QEMU instances connected
# via multicast socket networking and coordinate operations across them.
#
# Available tests:
#   k8s-cluster    — Boot control-plane + worker, kubeadm init/join
#   rolling-update — Rolling update with health checks across servers
{
  pkgs,
  lib,
  systems,
  testTools,
}: {
  k8s-cluster = import ./k8s-cluster.nix {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
  rolling-update = import ./rolling-update.nix {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
}
