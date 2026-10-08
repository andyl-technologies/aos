# Real typed guest-choice and exact-resume campaign flight.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  guestChoice = true;
}
