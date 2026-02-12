# tests/vm/boot.nix — Boot smoke test
#
# Verifies the system boots to multi-user target with systemd healthy,
# no failed units, correct kernel version, and proper os-release.
#
# Usage:
#   nix-build -A checks.vm.boot

{ pkgs, lib, systems }:

let
  harness = import ./lib.nix { inherit pkgs lib; };
in
harness.mkVMTest {
  name = "boot";
  system = systems.server;
  testScript = ''
    # System reaches running state
    assert_success "systemctl is-system-running --wait" \
      "System reached running state"

    # No failed systemd units
    assert_success "systemctl --no-pager --failed | grep -c '^0'" \
      "No failed units"

    # os-release identifies AOS
    assert_output_contains "cat /etc/os-release" "AOS" \
      "os-release contains AOS"

    # Kernel version is 6.12.x
    assert_output_contains "uname -r" "6.12" \
      "Kernel version is 6.12.x"

    # machine-id was generated at first boot
    assert_success "test -f /etc/machine-id" \
      "machine-id exists"

    # systemd-journald is running (log infrastructure)
    assert_success "systemctl is-active systemd-journald" \
      "journald is active"
  '';
}
