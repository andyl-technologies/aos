{
  pkgs,
  lib,
}: let
  src = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
in
  pkgs.fetchCargoVendor {
    inherit src;
    name = "crucible-test-vendor-0.1.0";
    sourceRoot = "source/crates";
    hash = "sha256-CHxtW0lBAN3Ux2p9SGkWlcc9iHhCUiWWDCEmrRWb76I=";
  }
