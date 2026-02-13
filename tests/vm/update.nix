# tests/vm/update.nix — Update mechanism test
#
# Verifies the atomic update pipeline on the server variant: update-check
# timer, health-check service, garbage collection timer, and the systemd
# infrastructure supporting them.
#
# Usage:
#   nix-build -A checks.vm.update

{
  pkgs,
  lib,
  systems,
  testTools,
}:

let
  harness = import ../../lib/testing { inherit pkgs lib testTools; };
  systemdBasics = import ./checks/systemd-basics.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
  updateInfra = import ./checks/update-infra.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
in
harness.mkVMTest {
  name = "update";
  system = systems.server;
  timeout = 300;
  checks = [
    systemdBasics
    updateInfra
  ];
}
