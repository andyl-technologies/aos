# Standalone real-QEMU exact pause and executable maintenance-transfer flight.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  guestChoice = true;
  maintenanceTransfer = true;
}
