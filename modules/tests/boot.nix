##! modules/tests/boot.nix — Core boot verification checks
##!
##! Verifies that the system boots to multi-user.target with systemd as PID 1,
##! essential filesystems are mounted, and the system identity is correct.
{
  config,
  lib,
  ...
}: {
  system.checks.system-boot = {
    description = "Core system boot verification";
    checks = [
      {
        name = "systemd-pid1";
        description = "systemd is running as PID 1";
        script = ''
          assert "systemd" in vm.succeed("cat /proc/1/comm")
        '';
      }
      {
        name = "multi-user-target";
        description = "system reached multi-user.target";
        script = ''
          vm.succeed("systemctl is-active multi-user.target")
        '';
      }
      {
        name = "os-release";
        description = "/etc/os-release identifies the configured OS name";
        script = ''
          assert 'NAME="${config.aos.system.name}"' in vm.succeed("cat /etc/os-release")
        '';
      }
      {
        name = "hostname";
        description = "hostname is set";
        script = ''
          vm.succeed("test -s /etc/hostname")
        '';
      }
      {
        name = "nix-store-present";
        description = "/nix/store contains system packages";
        script = ''
          vm.succeed("test -d /nix/store")
          vm.succeed("test -e /sbin/init")
        '';
      }
      {
        name = "essential-filesystems";
        description = "proc, sys, dev are mounted";
        script = ''
          vm.succeed("test -d /proc/1")
          vm.succeed("test -d /sys/class")
          vm.succeed("test -c /dev/null")
        '';
      }
      {
        name = "root-read-only";
        description = "root filesystem is mounted read-only (immutable OS design)";
        script = ''
          # The immutable OS design mounts / as ext4 ro; mutable state
          # lives on /var (rw) and /etc is an overlayfs with a tmpfs
          # upper layer. A writable / would undermine the model.
          #
          # `findmnt -O ro /` filters by mount option: exit 0 iff `/`
          # actually carries the `ro` flag. We previously substring-
          # grepped the OPTIONS column for "ro", which silently passed
          # on a writable ext4 root because `errors=remount-ro` (the
          # ext4 default) contains the literal "ro" — exactly the
          # regression we were trying to catch.
          vm.succeed("findmnt -O ro /")
        '';
      }
      {
        name = "etc-three-layer-overlay";
        description = "/etc is the composefs three-layer overlay (spec v12 §1)";
        script = ''
          # /etc is mounted as overlayfs with lowerdir+= /var/etc,
          # /run/etc/config-<gen>/etc, /run/etc/system-<gen>/
          # metadata, plus datadir+= /run/etc/system-<gen>/content
          # and upperdir on /run/etc/upper-<gen>.
          #
          # Path shapes in the option line:
          # - /var/etc is constructed under /sysroot in stage-1, but
          #   overlayfs reports it by its stage-2 path after switch_root.
          # - /run/etc/... does NOT carry /sysroot: the per-gen lower
          #   mounts live in the initrd's /run, which switch_root
          #   moves to /sysroot/run and then pivots, so the paths
          #   were already in their post-pivot shape when the
          #   overlay was constructed.
          #
          # metacopy=on / redirect_dir=on don't appear in the option
          # line: kernel defaults (CONFIG_OVERLAY_FS_METACOPY=y +
          # CONFIG_OVERLAY_FS_REDIRECT_DIR=y) make them implicit.
          mount_line = vm.succeed("findmnt -no SOURCE,FSTYPE,OPTIONS /etc")
          assert "overlay" in mount_line, f"/etc is not overlayfs: {mount_line!r}"
          for needle in (
              "lowerdir+=/var/etc",
              "lowerdir+=/run/etc/config-",
              "lowerdir+=/run/etc/system-",
              "datadir+=/run/etc/system-",
              "upperdir=/run/etc/upper-",
          ):
              assert needle in mount_line, \
                  f"/etc overlay missing {needle}: {mount_line!r}"

          # The per-gen subtree must be reachable by path post-pivot
          # — i.e. the /run/etc tmpfs and its sub-mounts must be
          # children of the moved-from-initrd /run, not shadowed by
          # it. Stat the system-<gen>/metadata mountpoint to prove
          # the path resolves, not just that findmnt sees the mount.
          vm.succeed("test -d /run/etc/system-1/metadata")
          vm.succeed("test -d /run/etc/config-1/etc")
        '';
      }
      {
        name = "system-erofs-mounted";
        description = "system EROFS metadata image is mounted as the bottom lower";
        script = ''
          # etc-overlay-setup.service mounts the toplevel's
          # etc-metadata.erofs at /run/etc/system-<gen>/metadata in
          # stage-1. The mount lives inside the initrd's /run (so
          # systemd-initrd's `mount --move /run /sysroot/run` carries
          # it through switch_root) and remains reachable by path
          # post-pivot at /run/etc/system-1/metadata.
          vm.succeed("findmnt -t erofs /run/etc/system-1/metadata")
        '';
      }
      {
        name = "machine-id-format";
        description =
          "/etc/machine-id is a 32-hex-char systemd machine ID"
          + " (seeded by aos-machine-id.service, spec v12 §6.1.5)";
        script = ''
          # Format: 32 lowercase hex chars + trailing newline (33 bytes).
          # Generated by `tr -d '-' < /proc/sys/kernel/random/uuid`.
          val = vm.succeed("cat /etc/machine-id")
          assert len(val) == 33, f"expected 33 bytes, got {len(val)}"
          assert all(c in '0123456789abcdef\n' for c in val), \
              f"non-hex chars in machine-id: {val!r}"
        '';
      }
    ];
  };
}
