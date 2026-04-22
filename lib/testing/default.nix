# lib/testing/default.nix — AOS test infrastructure library
#
# Provides test harness builders for VM and fleet tests, higher-level
# integration check wrappers, plus the composable check module system
# for reusable test assertions.
#
# mkVMTest supports two modes:
#   - System mode (system param): full systemd + agent, for module checks
#   - Headless mode (rootfsDeps param): test script IS init, for package checks
#
# Usage:
#   let testing = import ./lib/testing { inherit pkgs lib testTools; };
#   in testing.mkVMTest { name = "boot"; system = ...; checks = [...]; }
#   in testing.mkVMTest { name = "zlib-link"; rootfsDeps = [...]; testScript = "..."; }
{
  pkgs,
  lib,
  testTools ? { },
}:
let
  vm = import ./vm.nix { inherit pkgs lib testTools; };
  fleet = import ./fleet.nix { inherit pkgs lib testTools; };
  firecracker = import ./firecracker.nix { inherit pkgs lib; };
  integration = import ./integration.nix {
    inherit pkgs lib;
    inherit (vm) mkVMTest;
  };
  assertions = import ./assertions.nix;
  checks = import ./checks.nix;
in
{
  inherit (vm) mkVMTest mkTestRootfs;
  inherit (fleet) mkFleetTest;
  inherit (firecracker) mkFirecrackerRootfs;
  inherit (integration)
    mkLinkCheck
    mkToolCheck
    mkCompileCheck
    mkCxxCompileCheck
    mkSONAMECheck
    mkRPATHCheck
    mkSymbolCheck
    mkVersionCheck
    mkDynLinkerCheck
    ;
  inherit assertions;
  inherit (checks) composeChecks;
}
