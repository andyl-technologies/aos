# tests/vm/immutability.nix — Immutability test
#
# Verifies the immutable filesystem layout: root is read-only, /var is
# writable (ZFS), /etc is an overlay, /tmp and /run are tmpfs, and the
# Nix store is populated.
#
# Usage:
#   nix-build -A checks.vm.immutability

{ pkgs, lib, systems }:

let
  harness = import ./lib.nix { inherit pkgs lib; };
in
harness.mkVMTest {
  name = "immutability";
  system = systems.server;
  testScript = ''
    # Root filesystem is mounted read-only
    assert_success "mount | grep 'on / ' | grep -q 'ro'" \
      "Root is mounted read-only"

    # Writing to root should fail
    assert_success "! touch /test-write 2>/dev/null" \
      "Cannot write to root filesystem"

    # /var is writable (persistent state partition)
    assert_success "touch /var/test-write && rm /var/test-write" \
      "/var is writable"

    # /etc is an overlay mount
    assert_success "mount | grep 'on /etc ' | grep -q 'overlay'" \
      "/etc is overlay mount"

    # /tmp is tmpfs
    assert_success "mount | grep 'on /tmp ' | grep -q 'tmpfs'" \
      "/tmp is tmpfs"

    # /run is tmpfs
    assert_success "mount | grep 'on /run ' | grep -q 'tmpfs'" \
      "/run is tmpfs"

    # /nix/store exists and is populated
    assert_success "test -d /nix/store" \
      "/nix/store directory exists"

    assert_success "ls /nix/store/ | head -1" \
      "/nix/store is populated"
  '';
}
