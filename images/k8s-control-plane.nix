# images/k8s-control-plane.nix — Kubernetes control plane disk image
#
# Produces a 32G raw disk image for Kubernetes control plane nodes. The
# larger root partition accommodates etcd data and control plane binaries.
# Layout: 1G ESP + 12G root + 19G unpartitioned (for ZFS at runtime).

{ pkgs, lib, system }:

import ./builder.nix {
  inherit pkgs lib system;
  name = "k8s-control-plane";
  diskSize = "32G";
  espSize = "1G";
  rootSize = "12G";
}
