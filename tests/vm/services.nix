# tests/vm/services.nix — Services test
#
# Verifies that the systemd service infrastructure is functional on the
# server variant, including runtime directories, timers, chrony NTP,
# and SSH daemon.
#
# Usage:
#   nix-build -A checks.vm.services

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
  chrony = import ./checks/chrony.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
  ssh = import ./checks/ssh.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
in
harness.mkVMTest {
  name = "services";
  system = systems.server;
  timeout = 300;
  checks = [
    systemdBasics
    chrony
    ssh
  ];
}
