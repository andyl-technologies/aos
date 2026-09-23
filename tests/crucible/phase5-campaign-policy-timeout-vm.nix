# Standalone real-QEMU campaign policy-timeout and causal-evidence flight.
{
  pkgs,
  lib,
}:
import ./phase4-packaged-campaign-vm.nix {
  inherit pkgs lib;
  policyTimeout = true;
}
