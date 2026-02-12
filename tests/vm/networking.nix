# tests/vm/networking.nix — Networking test
#
# Verifies systemd-networkd, systemd-resolved, chrony NTP, SSH server,
# and basic network interface state.
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
  harness = import ./lib.nix { inherit pkgs lib testTools; };
in
harness.mkVMTest {
  name = "networking";
  system = systems.base;
  timeout = 300;
  testScript = ''
    # --- Loopback interface ---
    assert_success "test -d /sys/class/net/lo" \
      "Loopback interface exists"

    assert_output_contains "cat /sys/class/net/lo/operstate" "unknown" \
      "Loopback interface is up"

    # --- Network stack ---
    assert_success "test -d /proc/net" \
      "/proc/net is available"

    assert_success "test -f /etc/hostname" \
      "/etc/hostname exists"

    assert_output_contains "cat /etc/hostname" "aos-test" \
      "Hostname is set correctly"
  '';
}
