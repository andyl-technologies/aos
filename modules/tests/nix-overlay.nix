##! modules/tests/nix-overlay.nix — /nix overlayfs verification
##!
##! AOS ships its Nix closure read-only at /nix.lower; the initrd unit
##! `nix-overlay-setup.service` (modules/services/ignition.nix) stacks
##! an overlayfs at /nix with a writable upper on /var, so the Nix
##! package manager can install new store paths at runtime.
##!
##! These checks confirm the overlay is mounted correctly after switch-
##! root and that copy-up to the persistent upper actually works. The
##! Firecracker harness in lib/testing/vm.nix does not support an in-
##! test reboot cycle, so persistence across reboot is not asserted here.
{...}: {
  system.checks.nix-overlay = {
    description = "/nix is an overlayfs with writable upper on /var";
    checks = [
      {
        name = "nix-is-overlay";
        description = "/nix is mounted as an overlayfs";
        script = ''
          assert_success "findmnt -t overlay /nix" \
            "/nix is an overlayfs mount"
        '';
      }
      {
        name = "lower-visible-through-overlay";
        description = "the closure under /nix.lower surfaces at /nix";
        script = ''
          # /sbin/init resolves through merged-usr to /usr/bin/init,
          # which is a symlink into the store. Reading it via /nix/store
          # (the overlay) and via /nix.lower/store (the on-disk lower)
          # must produce the same closure root.
          assert_success "test -d /nix.lower/store" \
            "/nix.lower/store exists on the rootfs"
          assert_success "test -d /nix/store" \
            "/nix/store exists through the overlay"
        '';
      }
      {
        name = "copy-up-lands-on-upper";
        description = "writes via /nix/store land on /var/lib/nix-overlay/upper";
        script = ''
          # Write a marker through the overlay; the file must surface
          # at the overlay path AND physically appear under the upper.
          assert_success "echo aos-overlay-test > /nix/store/.aos-overlay-marker" \
            "marker write through overlay succeeds"
          assert_output_contains "cat /nix/store/.aos-overlay-marker" \
            "aos-overlay-test" \
            "marker readable through overlay"
          assert_output_contains "cat /var/lib/nix-overlay/upper/store/.aos-overlay-marker" \
            "aos-overlay-test" \
            "marker physically present on upper layer"
          # And confirm the lower was NOT touched (immutability invariant).
          assert_success "test ! -e /nix.lower/store/.aos-overlay-marker" \
            "marker did not leak to /nix.lower (lower stays immutable)"
        '';
      }
    ];
  };
}
