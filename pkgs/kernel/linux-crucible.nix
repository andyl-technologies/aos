{
  lib,
  stdenv,
  linuxWith,
}: let
  fixturePlatform =
    {
      "x86_64-linux" = {
        console = "ttyS0";
        serialConfig = ''
          CONFIG_SERIAL_8250=y
          CONFIG_SERIAL_8250_CONSOLE=y
        '';
      };
      "aarch64-linux" = {
        console = "ttyAMA0";
        serialConfig = ''
          CONFIG_SERIAL_AMBA_PL011=y
          CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
        '';
      };
    }
    .${
      stdenv.hostPlatform.system
    }
    or (throw "linux-crucible: unsupported system '${stdenv.hostPlatform.system}'");
  extraConfig = ''
    # Crucible test fixture kernel. This is deliberately a STOCK kernel: it
    # carries only functional additions needed to run the shipped test guests
    # (serial console, virtio transports, 9p, ext4) and a couple of deployment
    # simplifications (built-in-only, no ACPI). It contains NO determinism
    # shaping of any kind. Crucible's determinism is entirely host-side (QEMU
    # icount plus a seeded entropy source); no guest kernel config or cmdline
    # may be load-bearing for reproducibility. User guests keep supplying their
    # own, entirely unmodified, kernels.
    ${fixturePlatform.serialConfig}
    CONFIG_VIRTIO=y
    CONFIG_VIRTIO_PCI=y
    CONFIG_VIRTIO_PCI_LEGACY=y
    CONFIG_VIRTIO_BLK=y
    CONFIG_VIRTIO_NET=y
    CONFIG_VIRTIO_CONSOLE=y
    CONFIG_UEVENT_HELPER=y
    CONFIG_UEVENT_HELPER_PATH=""
    CONFIG_NET_9P=y
    CONFIG_NET_9P_VIRTIO=y
    CONFIG_9P_FS=y
    CONFIG_9P_FS_POSIX_ACL=y
    CONFIG_EXT4_FS=y

    # CONFIG_MODULES is not set
    # CONFIG_KMOD is not set
    # CONFIG_ACPI is not set
  '';

  fixtureKernelParams = [
    "console=${fixturePlatform.console}"
    "reboot=k"
    "panic=1"
    "root=/dev/vda"
    "ro"
    "net.ifnames=0"
  ];
in
  (linuxWith extraConfig).overrideAttrs (prev: {
    pname = "linux-crucible";
    passthru =
      (prev.passthru or {})
      // {
        crucibleExtraConfig = extraConfig;
        crucibleFixtureConsole = fixturePlatform.console;
        crucibleFixtureKernelParams = fixtureKernelParams;
        crucibleFixtureKernelCmdline = lib.concatStringsSep " " fixtureKernelParams;
        crucibleDeterminismMechanism = "host-side-qemu-icount-seeded-entropy";
        crucibleFixtureOnly = true;
      };
    meta =
      (prev.meta or {})
      // {
        description = "Linux kernel fixture for Crucible determinism gates";
      };
  })
