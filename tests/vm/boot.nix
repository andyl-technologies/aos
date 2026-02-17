# tests/vm/boot.nix — Boot smoke test
#
# Verifies the system boots to multi-user target with systemd healthy,
# correct kernel version, and proper os-release.
#
# Usage:
#   nix-build -A checks.vm.boot
{
  pkgs,
  lib,
  systems,
  testTools,
}: let
  harness = import ../../lib/testing {inherit pkgs lib testTools;};
  bootBasics = import ./checks/boot-basics.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
in
  harness.mkVMTest {
    name = "boot";
    system = systems.base;
    timeout = 300;
    checks = [bootBasics];
  }
