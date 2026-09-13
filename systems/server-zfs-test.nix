##! systems/server-zfs-test.nix — Server image with a real ZFS pool under test.
##!
##! The ZFS modules cannot be exercised against a configuration alone: the
##! memory policy is applied by the kernel module, dataset realization needs a
##! pool to converge against, and mount units need a real filesystem. This
##! variant boots the production server image with ZFS enabled and a pool built
##! on a blank device the check harness attaches.
##!
##! The pool carries data datasets only. `/var` stays on the image's own
##! partition (`aos.filesystems.zfs.systemState = false`) because the test
##! harness seeds the guest agent and its units into that partition at build
##! time; mounting a freshly created pool over `/var` would hide them and the
##! machine would never reach the driver. Production hosts that put `/var` on
##! the pool are the default and are covered by the installer path.
##!
##! Auto-registers as systems.server-zfs-test.
{
  config,
  lib,
  pkgs,
  ...
}: let
  # The harness attaches blank devices in declaration order after the root
  # disk, so the pool's single vdev is the first of them.
  poolDevice = "/dev/vdb";
  poolDiskSizeMiB = 2048;
in {
  imports = [./server-test.nix];

  aos.filesystems.zfs = {
    enable = true;
    poolName = "aostest";

    # Data-only pool; see the header for why /var stays on the image.
    systemState = false;

    # The guest has modest memory, so the proportional cap is what binds here
    # rather than the absolute ceiling. That is the path worth exercising: it
    # is the one that keeps the same configuration safe on a small host.
    memory = {
      maxBytes = 1024 * 1024 * 1024;
      maxPercent = 25;
      # Scaled to this guest. The reserve is an absolute amount of system
      # memory the ARC keeps free, so on a small machine it has to shrink with
      # the budget it sits beside.
      systemFreeReserve = 128 * 1024 * 1024;
    };

    datasets = {
      "data" = {
        mountPoint = "/srv/data";
        quota = "512M";
      };
      "data/records" = {
        mountPoint = "/srv/data/records";
        recordSize = "16K";
        compression = "zstd-1";
      };
      # A container dataset with no mount point: it must be created, must not
      # acquire a mount point from its parent, and must not gain a mount unit.
      "data/archive" = {
        snapshot = false;
      };
    };

    reservedSpace.size = "64M";
  };

  # A production host's pool is created by the installer against real disks,
  # under an operator's explicit confirmation. Nothing in the modules creates a
  # pool on its own, because auto-creating one on a blank device is how data on
  # an unrelated disk gets destroyed. This unit is test scaffolding and lives
  # in the fixture for exactly that reason.
  systemd.services."aos-zfs-test-pool" = {
    description = "Create the test ZFS pool on ${poolDevice}";
    wantedBy = ["local-fs.target"];
    before = ["local-fs.target" "zfs-import.service"];
    after = ["systemd-udev-settle.service" "systemd-modules-load.service"];
    requires = ["systemd-modules-load.service"];
    unitConfig.DefaultDependencies = "no";
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      set -euo pipefail
      PATH=${lib.makeBinPath [config.aos.filesystems.zfs.package pkgs.coreutils]}''${PATH:+:$PATH}

      if zpool list -H aostest >/dev/null 2>&1; then
        exit 0
      fi
      if zpool import -N -f aostest >/dev/null 2>&1; then
        exit 0
      fi

      # Mirrors the installer's pool geometry and inherited properties so the
      # checks observe the same defaults a real installation produces.
      zpool create -f -o ashift=12 -o autotrim=on -o compatibility=openzfs-2.3 \
        -O compression=zstd-3 -O atime=off -O mountpoint=none \
        -O recordsize=128K -O dedup=off -O xattr=sa -O acltype=posixacl \
        aostest ${poolDevice}
    '';
  };

  # Enabling ZFS turns on hardware monitoring, which a storage host wants on
  # real disks. This guest's devices are virtio-blk and report no SMART data,
  # so smartd would fail and restart for the life of the test. The watchdog
  # half of that module is what ZFS actually depends on and stays enabled.
  aos.monitoring.hardware.smartd = false;

  # Every ZFS check group runs against a machine with the pool device attached
  # and enough memory for the proportional budget to be meaningful.
  system.checks =
    lib.genAttrs [
      "zfs-memory"
      "zfs-datasets"
      "zfs-maintenance"
    ] (_: {
      extraDisks = [{sizeMiB = poolDiskSizeMiB;}];
      memoryMiB = 2048;
      # A ZFS guest creates a pool, realizes datasets, and mounts them before
      # the system is usable, all after the image's own boot. Give the group
      # room for that rather than measuring against a stock boot.
      timeoutSeconds = 300;
      # The harness boots the guest with its own command line, so the module
      # parameters these checks verify have to be named here. They come from
      # the same derivation the image's UKI would carry.
      kernelParams = config.aos.filesystems.zfs.moduleParameters;
    });
}
