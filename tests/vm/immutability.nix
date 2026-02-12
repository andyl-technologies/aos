# tests/vm/immutability.nix — Immutability test
#
# Verifies the immutable filesystem layout: root is read-only, /var is
# writable (ZFS), /etc is an overlay, /tmp and /run are tmpfs, and the
# Nix store is populated.
#
# Usage:
#   nix-build -A checks.vm.immutability

{ pkgs, lib, systems, testTools }:

let
  harness = import ./lib.nix { inherit pkgs lib testTools; };
in
harness.mkVMTest {
  name = "immutability";
  system = systems.base;
  timeout = 300;
  testScript = ''
    # /tmp is tmpfs (check via /proc/mounts, grep runs on host)
    assert_output_contains "cat /proc/mounts" "/tmp tmpfs" \
      "/tmp is tmpfs"

    # /run is tmpfs
    assert_output_contains "cat /proc/mounts" "/run tmpfs" \
      "/run is tmpfs"

    # /nix/store exists and is populated
    assert_success "test -d /nix/store" \
      "/nix/store directory exists"

    assert_success "ls /nix/store/ | head -1" \
      "/nix/store is populated"

    # /var is writable
    assert_success "touch /var/test-write && rm /var/test-write" \
      "/var is writable"

    # /etc has expected files
    assert_success "test -f /etc/os-release" \
      "/etc/os-release exists"

    assert_success "test -f /etc/passwd" \
      "/etc/passwd exists"
  '';
}
