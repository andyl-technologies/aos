##! Package-owned systemd rootfs constructor for VM platform tests.
{
  lib,
  pkgs,
}: let
  buildRootfs = import ../platform/_rootfs-builder.nix;
  closureInfoFor = lib.build.closureInfo {inherit pkgs;};
in
  arguments:
    buildRootfs (
      arguments
      // {
        inherit closureInfoFor lib pkgs;
      }
    )
