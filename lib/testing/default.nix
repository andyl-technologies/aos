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
#   let testing = import ./lib/testing { inherit pkgs lib; };
#   in testing.mkVMTest { name = "boot"; system = ...; checks = [...]; }
#   in testing.mkVMTest { name = "zlib-link"; rootfsDeps = [...]; testScript = "..."; }
{
  pkgs,
  lib,
}: let
  vm = import ./vm.nix {inherit pkgs lib;};
  fleet = import ./fleet.nix {inherit pkgs lib;};
  darling = import ./darling.nix {inherit pkgs lib;};
  firecracker = import ./firecracker.nix {inherit pkgs lib;};
  integration = import ./integration.nix {
    inherit pkgs lib;
    inherit (vm) mkVMTest;
  };
  checks = import ./checks.nix;
in {
  inherit (vm) mkVMTest mkTestDisk;
  inherit (fleet) mkFleetTest uriEncode dataUrl;
  inherit (darling) mkDarlingFleetSpec;
  inherit (firecracker) mkFirecrackerRootfs;
  inherit
    (integration)
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
  inherit (checks) composeChecks;
}
