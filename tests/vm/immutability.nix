# tests/vm/immutability.nix — Immutability test
#
# Verifies the immutable filesystem layout: /tmp and /run are tmpfs,
# /var is writable, /nix/store is populated, and /etc has expected files.
#
# Usage:
#   nix-build -A checks.vm.immutability
{
  pkgs,
  lib,
  systems,
  testTools,
}: let
  harness = import ../../lib/testing {inherit pkgs lib testTools;};
  filesystem = import ./checks/filesystem.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
in
  harness.mkVMTest {
    name = "immutability";
    system = systems.base;
    timeout = 300;
    checks = [filesystem];
  }
