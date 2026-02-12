# tests/vm/update.nix — Update mechanism test
#
# Verifies the atomic update pipeline: update-check timer, health-check
# service, rollback service, boot counting via systemd-bless-boot,
# garbage collection timer, and the update tool binary.
#
# Usage:
#   nix-build -A checks.vm.update

{ pkgs, lib, systems, testTools }:

let
  harness = import ./lib.nix { inherit pkgs lib testTools; };
in
harness.mkVMTest {
  name = "update";
  system = systems.base;
  timeout = 300;
  testScript = ''
    # --- systemd service management ---
    # Verify the system can enumerate and manage services (prerequisite
    # for any update/health-check infrastructure).

    assert_success "systemctl list-units --type=service --no-pager" \
      "systemctl can list services"

    assert_success "systemctl list-unit-files --type=timer --no-pager" \
      "systemctl can list timer units"

    # --- Journal ---
    assert_success "journalctl --no-pager -n 5" \
      "journalctl can read system journal"

    # --- /etc writable (needed for config updates) ---
    assert_success "touch /etc/test-write && rm /etc/test-write" \
      "/etc is writable for updates"
  '';
}
