# tests/vm/seed.nix — Seed server integration test
#
# Boots the seed variant in QEMU and verifies the complete seed server
# infrastructure: nginx web server (ACME config present but not exercised),
# Nix daemon with build users, and seed build/publish orchestration.
#
# Usage:
#   nix-build -A checks.vm.seed
{
  pkgs,
  lib,
  systems,
  testTools,
}: let
  harness = import ../../lib/testing {inherit pkgs lib testTools;};
  nginx = import ./checks/nginx.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
  nixDaemon = import ./checks/nix-daemon.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
  seed = import ./checks/seed.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
in
  harness.mkVMTest {
    name = "seed";
    system = systems.seed;
    timeout = 300;
    checks = [
      nginx
      nixDaemon
      seed
    ];
  }
