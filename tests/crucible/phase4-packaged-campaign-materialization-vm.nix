# Public packaged QEMU flight through all three campaign materialization tiers.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  hotForkFlight = true;
}
