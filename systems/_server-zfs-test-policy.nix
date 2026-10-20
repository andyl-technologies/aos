##! Retains the authored ZFS pool, datasets, memory policy, and fixture service.
{config, ...}: {
  aos.filesystems.zfs = {
    enable = true;

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
        # Small enough that a check can fill it quickly and observe the quota
        # stop the write rather than the pool filling up.
        quota = "32M";
      };
      # A container dataset with no mount point: it must be created, must not
      # acquire a mount point from its parent, and must not gain a mount unit.
      "data/archive" = {
        snapshot = false;
      };
    };

    reservedSpace.size = "64M";
  };

  aos.tests.zfsPool = {
    enable = true;
    device = "/dev/vdb";
  };
  aos.filesystems.zfs.poolName = config.aos.tests.zfsPool.poolName;

  # A production host's pool is created by the installer against real disks,
  # under an operator's explicit confirmation. Nothing in the modules creates a
  # pool on its own, because auto-creating one on a blank device is how data on
  # an unrelated disk gets destroyed. This unit is test scaffolding and lives
  # in the fixture for exactly that reason.
  # Enabling ZFS turns on hardware monitoring, which a storage host wants on
  # real disks. This guest's devices are virtio-blk and report no SMART data,
  # so smartd would fail and restart for the life of the test. The watchdog
  # half of that module is what ZFS actually depends on and stays enabled.
  aos.monitoring.hardware.smartd = false;
}
