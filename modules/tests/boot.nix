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
        description = "/etc/os-release identifies ANDYL OS";
        script = ''
          assert "ANDYL OS" in vm.succeed("cat /etc/os-release")
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
          # spec v12 §6.1.4: /etc is mounted as overlayfs with lowerdir+=
          # /var/etc, /run/etc/ignition-<gen>/etc, /run/etc/system-<gen>/
          # metadata, plus datadir+= /run/etc/system-<gen>/content and
          # upperdir on /run/etc/upper-<gen>.
          #
          # The /sysroot prefix survives switch_root because the mount
          # was set up in stage-1 before pivoting — the kernel keeps
          # the literal source path strings, so all four paths still
          # carry /sysroot/ at runtime. We grep for that shape rather
          # than the post-pivot form. metacopy=on / redirect_dir=on
          # don't appear in the option line: kernel defaults
          # (CONFIG_OVERLAY_FS_METACOPY=y +
          # CONFIG_OVERLAY_FS_REDIRECT_DIR=y) make them implicit.
          mount_line = vm.succeed("findmnt -no SOURCE,FSTYPE,OPTIONS /etc")
          assert "overlay" in mount_line, f"/etc is not overlayfs: {mount_line!r}"
          for needle in (
              "lowerdir+=/sysroot/var/etc",
              "lowerdir+=/sysroot/run/etc/ignition-",
              "lowerdir+=/sysroot/run/etc/system-",
              "datadir+=/sysroot/run/etc/system-",
              "upperdir=/sysroot/run/etc/upper-",
          ):
              assert needle in mount_line, \
                  f"/etc overlay missing {needle}: {mount_line!r}"
        '';
      }
      {
        name = "system-erofs-mounted";
        description = "system EROFS metadata image is mounted as the bottom lower";
        script = ''
          # etc-overlay-setup.service mounts the toplevel's
          # etc-metadata.erofs at /sysroot/run/etc/system-<gen>/metadata
          # in stage-1. switch_root moves submounts under /sysroot to
          # their post-pivot path, so the mountpoint becomes
          # /run/etc/system-1/metadata in stage-2. (The /etc overlay's
          # option-string lowerdir/datadir paths keep their literal
          # /sysroot prefix because they're stored as strings, not
          # mountpoint references.)
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
