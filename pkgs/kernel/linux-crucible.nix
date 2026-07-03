{
  lib,
  linuxWith,
}: let
  extraConfig = ''
    # Crucible deterministic guest fixture kernel. This is only for Crucible's
    # shipped test fixtures; user guests keep supplying their own kernels.
    # CONFIG_SMP is not set
    CONFIG_NR_CPUS=1

    CONFIG_HZ_PERIODIC=y
    # CONFIG_NO_HZ_IDLE is not set
    # CONFIG_NO_HZ_FULL is not set
    CONFIG_HZ_100=y
    CONFIG_HZ=100

    CONFIG_SERIAL_8250=y
    CONFIG_SERIAL_8250_CONSOLE=y
    CONFIG_VIRTIO=y
    CONFIG_VIRTIO_PCI=y
    CONFIG_VIRTIO_PCI_LEGACY=y
    CONFIG_VIRTIO_BLK=y
    CONFIG_VIRTIO_NET=y
    CONFIG_VIRTIO_CONSOLE=y
    CONFIG_NET_9P=y
    CONFIG_NET_9P_VIRTIO=y
    CONFIG_9P_FS=y
    CONFIG_9P_FS_POSIX_ACL=y
    CONFIG_EXT4_FS=y

    CONFIG_RANDOM_TRUST_BOOTLOADER=y
    # CONFIG_RANDOM_TRUST_CPU is not set
    # CONFIG_HW_RANDOM_VIRTIO is not set

    # CONFIG_MODULES is not set
    # CONFIG_KMOD is not set
    # CONFIG_ACPI is not set
  '';

  fixtureKernelParams = [
    "console=ttyS0"
    "reboot=k"
    "panic=1"
    "root=/dev/vda"
    "ro"
    "nosmp"
    "clocksource=tsc"
    "tsc=reliable"
    "no_timer_check"
    "random.trust_bootloader=on"
    "net.ifnames=0"
  ];
in
  (linuxWith extraConfig).overrideAttrs (prev: {
    pname = "linux-crucible";
    passthru =
      (prev.passthru or {})
      // {
        crucibleExtraConfig = extraConfig;
        crucibleFixtureKernelParams = fixtureKernelParams;
        crucibleFixtureKernelCmdline = lib.concatStringsSep " " fixtureKernelParams;
        crucibleDeterminismMechanism = "qemu-seed-icount-plus-bootloader-entropy";
        crucibleFixtureOnly = true;
      };
    meta =
      (prev.meta or {})
      // {
        description = "Linux kernel fixture for Crucible determinism gates";
      };
  })
