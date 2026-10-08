{
  pkgs,
  lib,
  src ? import ../../pkgs/tools/crucible/_source.nix {inherit lib;},
}:
pkgs.fetchCargoVendor {
  inherit src;
  name = "crucible-test-vendor-0.1.0";
  sourceRoot = "source/crates";
  # Pin the complete test workspace lock independently of the production vendor.
  hash = "sha256-mc/IH7ph6x/X7mLpAXs7NSuH352FFxoaN4/FiJv1dXI=";
}
