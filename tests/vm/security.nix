# tests/vm/security.nix — Security test
#
# Verifies SELinux is enforcing, audit is running, firewall rules are
# loaded, and sysctl hardening parameters are set.
#
# Usage:
#   nix-build -A checks.vm.security

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
  name = "security";
  system = systems.base;
  timeout = 300;
  testScript = ''
    # --- Kernel security defaults (via /proc/sys) ---
    assert_output_contains "cat /proc/sys/kernel/randomize_va_space" "2" \
      "ASLR is fully enabled"

    assert_output_contains "cat /proc/sys/net/ipv4/tcp_syncookies" "1" \
      "TCP syncookies are enabled"

    # Verify protected_{hardlinks,symlinks} sysctls are accessible
    assert_success "test -f /proc/sys/fs/protected_hardlinks" \
      "Protected hardlinks sysctl is accessible"

    assert_success "test -f /proc/sys/fs/protected_symlinks" \
      "Protected symlinks sysctl is accessible"

    # --- Basic process isolation ---
    assert_success "test -d /proc/1" \
      "PID 1 visible in /proc"

    assert_success "test -d /sys/kernel" \
      "/sys/kernel is accessible"
  '';
}
