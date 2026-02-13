# tests/vm/security.nix — Security test
#
# Verifies kernel sysctl hardening parameters on the base system.
# For deep security testing (SELinux, audit, firewall, SSH), see
# server-security.nix which uses the server variant.
#
# Usage:
#   nix-build -A checks.vm.security

{
  pkgs,
  lib,
  systems,
  testTools,
}:

let
  harness = import ../../lib/testing { inherit pkgs lib testTools; };
  kernelSecurity = import ./checks/kernel-security.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
in
harness.mkVMTest {
  name = "security";
  system = systems.server;
  timeout = 300;
  checks = [ kernelSecurity ];
}
