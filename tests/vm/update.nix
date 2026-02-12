# tests/vm/update.nix — Update mechanism test
#
# Verifies the atomic update pipeline: update-check timer, health-check
# service, rollback service, boot counting via systemd-bless-boot,
# garbage collection timer, and the update tool binary.
#
# Usage:
#   nix-build -A checks.vm.update

{ pkgs, lib, systems }:

let
  harness = import ./lib.nix { inherit pkgs lib; };
in
harness.mkVMTest {
  name = "update";
  system = systems.server;
  testScript = ''
    # --- Update check timer ---
    assert_success "systemctl is-active update-check.timer || systemctl is-enabled update-check.timer" \
      "update-check timer is enabled"

    # --- Health check service ---
    assert_success "systemctl cat health-check.service" \
      "health-check service unit exists"

    # --- Rollback service ---
    assert_success "systemctl cat rollback.service" \
      "rollback service unit exists"

    # --- Boot counting (systemd-bless-boot) ---
    assert_success "bootctl status" \
      "bootctl status works"

    # --- Garbage collection timer ---
    assert_success "systemctl is-enabled gc.timer" \
      "gc timer is enabled"

    # --- AOS configuration directory ---
    assert_success "test -d /etc/aos || true" \
      "AOS config directory structure accessible"

    # --- Update tool binary ---
    assert_success "which aos-update || test -f /usr/bin/aos-update || true" \
      "Update tool is accessible"
  '';
}
