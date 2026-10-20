# One public CLI lifecycle flight against packaged QEMU and the campaign daemon.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  guestChoice = true;
  campaignLifecycle = true;
}
