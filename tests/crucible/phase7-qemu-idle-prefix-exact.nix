# Verifies a real QEMU idle advance with instructions pending in the current vCPU.
{
  pkgs,
  lib,
}:
import ./phase7-qemu-hot-fork-atomic-world-vm.nix {
  inherit pkgs lib;
  attrPath = "checks.crucible.phase7.qemuIdlePrefixExact";
  prefixOnly = true;
}
