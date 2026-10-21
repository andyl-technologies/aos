# Real typed guest-choice and exact-resume campaign flight.
{
  pkgs,
  lib,
  # Optional { minimumIcount; maximumIcount; } window whose fingerprint
  # preimages the flight keeps for replay-oracle mismatch diagnosis.
  fingerprintMaterialWindow ? null,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib fingerprintMaterialWindow;
  guestChoice = true;
}
