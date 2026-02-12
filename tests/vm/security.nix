# tests/vm/security.nix — Security test
#
# Verifies SELinux is enforcing, audit is running, firewall rules are
# loaded, and sysctl hardening parameters are set.
#
# Usage:
#   nix-build -A checks.vm.security

{ pkgs, lib, systems }:

let
  harness = import ./lib.nix { inherit pkgs lib; };
in
harness.mkVMTest {
  name = "security";
  system = systems.server;
  testScript = ''
    # --- SELinux ---
    assert_output_contains "getenforce" "Enforcing" \
      "SELinux is enforcing"

    assert_success "sestatus" \
      "sestatus runs successfully"

    # --- Audit ---
    assert_success "systemctl is-active auditd" \
      "auditd is active"

    assert_success "auditctl -l | head -1" \
      "Audit rules are loaded"

    # --- Firewall ---
    assert_success "systemctl is-active nftables" \
      "nftables is active"

    assert_success "nft list ruleset | grep -q 'table'" \
      "nftables rules are loaded"

    # --- Sysctl hardening ---
    assert_output_contains "sysctl kernel.randomize_va_space" "2" \
      "ASLR is fully enabled"

    assert_output_contains "sysctl kernel.kptr_restrict" "2" \
      "Kernel pointer restriction is set"

    assert_output_contains "sysctl kernel.dmesg_restrict" "1" \
      "dmesg restricted to privileged users"

    assert_output_contains "sysctl net.ipv4.tcp_syncookies" "1" \
      "TCP syncookies are enabled"

    assert_output_contains "sysctl fs.protected_hardlinks" "1" \
      "Protected hardlinks enabled"

    assert_output_contains "sysctl fs.protected_symlinks" "1" \
      "Protected symlinks enabled"
  '';
}
