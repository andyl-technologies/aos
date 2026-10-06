# Advisory delivery snapshots around the original materialization scenario.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  singleGuest = "materialization";
  nativeControlSummary = true;
}
