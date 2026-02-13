# lib/testing/default.nix — AOS test infrastructure library
#
# Provides test harness builders for VM and fleet tests.
# Usage:
#   let testing = import ./lib/testing { inherit pkgs lib testTools; };
#   in testing.mkVMTest { ... }

{
  pkgs,
  lib,
  testTools,
}:

let
  vm = import ./vm.nix { inherit pkgs lib testTools; };
  fleet = import ./fleet.nix { inherit pkgs lib; };
  assertions = import ./assertions.nix;
in
{
  inherit (vm) mkVMTest mkTestRootfs;
  inherit (fleet) mkFleetTest;
  inherit assertions;
}
