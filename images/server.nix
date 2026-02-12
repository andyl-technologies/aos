# images/server.nix — Server variant disk image
#
# Produces a 16G raw disk image for the production server variant.
# Includes SELinux policy, SSH, audit, and update tooling.
# Layout: 1G ESP + 8G root + 7G unpartitioned (for ZFS at runtime).

{
  pkgs,
  lib,
  system,
}:

import ./builder.nix {
  inherit pkgs lib system;
  name = "server";
  diskSize = "16G";
  espSize = "1G";
  rootSize = "8G";
}
