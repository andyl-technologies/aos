##! Package-owned systemd rootfs constructor for VM platform tests.
{
  lib,
  pkgs,
}: let
  buildRootfs = import ../platform/_rootfs-builder.nix;
  closureInfoFor = import ../../../../lib/build/closure-info.nix {inherit lib pkgs;};
in
  arguments:
    buildRootfs (
      arguments
      // {
        inherit closureInfoFor lib pkgs;
      }
    )
