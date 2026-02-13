# tests/vm/networking.nix — Networking test
#
# Verifies basic network interface state and hostname configuration
# on the server variant.
#
# Usage:
#   nix-build -A checks.vm.networking

{
  pkgs,
  lib,
  systems,
  testTools,
}:

let
  harness = import ../../lib/testing { inherit pkgs lib testTools; };
  networkingBase = import ./checks/networking-base.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
in
harness.mkVMTest {
  name = "networking";
  system = systems.server;
  timeout = 300;
  checks = [ networkingBase ];
}
