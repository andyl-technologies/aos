# images/base.nix — Base variant disk image
#
# Produces a 16G raw disk image for the minimal AOS base system.
# Layout: 1G ESP + 8G root + 7G unpartitioned (for ZFS at runtime).

{ pkgs, lib, system }:

import ./builder.nix {
  inherit pkgs lib system;
  name = "base";
  diskSize = "16G";
  espSize = "1G";
  rootSize = "8G";
}
