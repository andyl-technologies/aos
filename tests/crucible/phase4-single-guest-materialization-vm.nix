# One actual disk-backed fork, thin replay, exact restore, and process cleanup.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  singleGuest = "materialization";
}
