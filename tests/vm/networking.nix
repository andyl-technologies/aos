# tests/vm/networking.nix — Networking test
#
# Verifies systemd-networkd, systemd-resolved, chrony NTP, SSH server,
# and basic network interface state.
#
# Usage:
#   nix-build -A checks.vm.networking

{ pkgs, lib, systems }:

let
  harness = import ./lib.nix { inherit pkgs lib; };
in
harness.mkVMTest {
  name = "networking";
  system = systems.server;
  testScript = ''
    # --- systemd-networkd ---
    assert_success "systemctl is-active systemd-networkd" \
      "systemd-networkd is active"

    # --- systemd-resolved ---
    assert_success "systemctl is-active systemd-resolved" \
      "systemd-resolved is active"

    assert_success "resolvectl status" \
      "resolvectl status works"

    # --- Chrony NTP ---
    assert_success "systemctl is-active chronyd" \
      "chronyd is active"

    assert_success "chronyc tracking" \
      "chronyc tracking works"

    # --- SSH ---
    assert_success "systemctl is-active sshd" \
      "sshd is active"

    assert_success "ss -tlnp | grep -q ':22'" \
      "SSH is listening on port 22"

    # SSH hardening: password auth disabled
    assert_output_contains "sshd -T | grep -i passwordauthentication" "no" \
      "SSH password authentication is disabled"

    # SSH hardening: X11 forwarding disabled
    assert_output_contains "sshd -T | grep -i x11forwarding" "no" \
      "SSH X11 forwarding is disabled"

    # --- Network interface ---
    assert_success "ip link show | grep -q 'state UP'" \
      "At least one network interface is UP"
  '';
}
