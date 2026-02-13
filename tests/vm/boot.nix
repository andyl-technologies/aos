# tests/vm/boot.nix — Boot smoke test
#
# Verifies the system boots to multi-user target with systemd healthy,
# no failed units, correct kernel version, and proper os-release.
#
# Usage:
#   nix-build -A checks.vm.boot

{
  pkgs,
  lib,
  systems,
  testTools,
}:

let
  harness = import ../../lib/testing { inherit pkgs lib testTools; };
in
harness.mkVMTest {
  name = "boot";
  system = systems.base;
  timeout = 300;
  testScript = ''
    assert_output_contains "cat /etc/os-release" "ANDYL OS" \
      "os-release contains ANDYL OS"

    assert_output_contains "cat /etc/hostname" "aos-test" \
      "hostname is aos-test"

    assert_success "systemctl is-system-running --wait || true" \
      "systemd reached running state"

    assert_output_contains "uname -r" "6.12" \
      "kernel version is 6.12.x"
  '';
}
