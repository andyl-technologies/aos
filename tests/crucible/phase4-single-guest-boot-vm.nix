# Independent real guest execution and cleanup through the public campaign CLI.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  singleGuest = "boot";
}
