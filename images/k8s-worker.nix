# images/k8s-worker.nix — Kubernetes worker node disk image
#
# Produces a 32G raw disk image for Kubernetes worker nodes. The larger
# disk accommodates container images and ephemeral pod storage.
# Layout: 1G ESP + 12G root + 19G unpartitioned (for ZFS at runtime).

{
  pkgs,
  lib,
  system,
}:

import ./builder.nix {
  inherit pkgs lib system;
  name = "k8s-worker";
  diskSize = "32G";
  espSize = "1G";
  rootSize = "12G";
}
