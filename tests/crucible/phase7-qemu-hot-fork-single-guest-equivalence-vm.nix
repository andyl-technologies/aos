# Retains one Linux guest's hot-fork equivalence subset before the full world matrix.
{
  pkgs,
  lib,
}:
import ./phase7-qemu-hot-fork-equivalence-vm.nix {
  inherit pkgs lib;
  caseProfile = "single-guest";
  attrPath = "checks.crucible.phase7.qemuHotForkSingleGuestEquivalenceVm";
  taskIds = ["T-CAM-6.5" "T-CAM-7.6"];
}
