# tests/vm/services.nix — Services smoke test
#
# Verifies that the systemd service infrastructure is functional,
# including runtime directories, timers, and accessible kernel
# tunables that services depend on.
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
  harness = import ./lib.nix { inherit pkgs lib testTools; };
in
harness.mkVMTest {
  name = "services";
  system = systems.base;
  timeout = 300;
  testScript = ''
    assert_success "test -d /run/systemd/system" \
      "systemd runtime directory exists"

    assert_success "systemctl list-timers --no-pager" \
      "systemd timers are functional"

    assert_output_contains "cat /proc/sys/vm/swappiness" "60" \
      "vm.swappiness sysctl is accessible"
  '';
}
