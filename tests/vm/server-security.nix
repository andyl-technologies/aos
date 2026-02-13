# tests/vm/server-security.nix — Server security depth test
#
# Verifies the full server security stack: SSH, firewall (nftables),
# kernel hardening, SELinux, and audit. Uses the server variant which
# has all security modules loaded.
#
# Usage:
#   nix-build -A checks.vm.server-security

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
  ssh = import ./checks/ssh.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
  firewall = import ./checks/firewall.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
  hardening = import ./checks/hardening.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
  selinux = import ./checks/selinux.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
  audit = import ./checks/audit.nix {
    inherit (harness) mkCheck mkCheckGroup;
  };
in
harness.mkVMTest {
  name = "server-security";
  system = systems.server;
  timeout = 300;
  checks = [
    kernelSecurity
    ssh
    firewall
    hardening
    selinux
    audit
  ];
}
