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
  poolDiskSizeMiB = 2048;
in {
  imports = [./server-test.nix];

  # Single-VM checks boot a writable ext4 test disk that the harness assembles,
  # not the signed, dm-verity-authenticated image. The production root contract
  # cannot be satisfied there: the boot identity guard finds no validated
  # identity, isolates to its failure target, and the guest never switches
  # root. Match the root contract the harness provides, exactly as the
  # `server-vm` system does for the same reason.
  aos.filesystems.rootFsType = lib.mkForce "ext4";
  aos.security.verity.enable = lib.mkForce false;

  # The writable ext4 fixture retains free-space headroom in addition to the
  # ZFS runtime payload. Keep that test-only allocation out of the production
  # server image contract while leaving enough room for the populated image.
  aos.image.rootPartitionMiB = 2688;
  aos.image.qualification.extraDisks = [{sizeMiB = poolDiskSizeMiB;}];
  aos.image.budgets = {
    maxRootMiB = 2624;
    maxConvertedDownloadMiB =
      if pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64"
      then 1696
      else 1504;
  };

  aos.activation.stages.host.configuration = [
    (builtins.path {
      path = ./_server-zfs-test-policy.nix;
      name = "aos-server-zfs-test-policy.nix";
    })
  ];

  environment.systemPackages = [pkgs.aos-zfs-test-pool];

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
