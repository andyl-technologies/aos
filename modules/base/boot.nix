##! modules/base/boot.nix — Boot configuration module
##!
##! Configures kernel command line parameters and the systemd-based
##! initrd. The image builder composes these into a Unified Kernel
##! Image and drops it onto a 512 MiB ESP alongside sd-boot; no
##! per-generation loader entries, no syslinux/grub fallbacks.
##!
##! The UKI's .cmdline section is baked into a signed binary, so
##! changes to `aos.boot.kernelParams` require an image rebuild (not
##! just a config refresh).
{
  config,
  lib,
  pkgs,
  ...
}: let
  hardwareAutoloadedInitrdModules = [
    "ena"
    "gve"
    "hv_netvsc"
    "mlx5_core"
    "mlx4_en"
  ];

  # Base initrd module manifest. Set as a `config` def (below) rather than the
  # option `default`, so other modules (e.g. modules/security/verity.nix adding
  # `dm_verity`) can *append* to it — a list supplied only via `default` is
  # suppressed wholesale by any def, which would silently drop the virtio/ext4
  # drivers. `mkBefore` keeps this base ahead of appended entries for a stable,
  # unchanged ordering on systems that add nothing.
  baseInitrdModules =
    [
      "virtio_blk"
      "virtio_pci"
      "virtio_net"
      "ext4"
      "isofs"
      "usb_storage"
      "uas"
      "overlay"
      "dm-crypt"
      "qemu_fw_cfg"
    ]
    ++ hardwareAutoloadedInitrdModules;
in {
  options.aos.boot = {
    ## Kernel command line parameters.
    ##
    ## Other modules (SELinux, hardening, network tuning, …) append
    ## to this list. The combined string is baked into the UKI's
    ## .cmdline section at image build time.
    ##
    ## # Examples
    ## ```nix
    ## aos.boot.kernelParams = [ "console=ttyS0,115200" "selinux=1" ];
    ## ```
    kernelParams = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = ''
        Kernel command line parameters. These are baked into the
        UKI's .cmdline section at image build time. Base parameters
        (console, cgroup v2, gpt-auto disable) are set in the config
        section below; other modules append their own.
      '';
    };

    ## sd-boot boot-counting tries for durable image rollback.
    ##
    ## When non-null, the UKI staged into the ESP is named with the sd-boot
    ## tries-suffix `aos-generation-<number>+<tries>.efi`. sd-boot decrements the
    ## counter on each boot attempt and auto-demotes (`+0-<tries>`) a UKI that
    ## fails to boot, so a bad new image falls back to the other A/B slot
    ## without operator action. Staging clears any exact persistent default so
    ## the `default aos-*.efi` loader pattern can sort the exhausted entry
    ## behind the known-good slot. Explicit rollback to an older good slot uses
    ## `bootctl set-default` at runtime.
    ##
    ## The default of three attempts enables automatic fallback on every image.
    ## `null` is retained only as an explicit compatibility escape hatch.
    bootCountingTries = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = 3;
      description = ''
        sd-boot boot-counting tries suffix for durable image rollback. When
        set to N, the ESP UKI is named
        `aos-generation-<number>+N.efi`; sd-boot assesses the boot and demotes a
        UKI that fails to start, falling back to the other A/B slot. Staging
        relies on the loader's `aos-*.efi` pattern while explicit rollback uses
        `bootctl set-default`. Set `null` only for compatibility with boot
        managers that lack boot counting.
      '';
    };

    initrd = {
      ## Whether to generate a systemd-based initrd.
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Whether to generate a systemd-based initrd (initial ramdisk).";
      };

      ## Kernel modules to include in the initrd.
      modules = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        # The base set is contributed as a `config` def (`mkBefore`, see
        # `baseInitrdModules` above) so feature modules can append to it.
        default = [];
        description = ''
          Kernel modules to include in the initrd module manifest. The
          initrd builder copies the active kernel's module tree; this
          list records the drivers the image is expected to support and
          feeds `aos.boot.initrd.loadModules` by default.

          The defaults cover virtio (QEMU/KVM block, PCI, net), ext4
          root, ISO9660 metadata channel, USB mass storage
          (usb_storage/uas) for bare-metal IPMI virtual media,
          overlayfs for /etc, dm-crypt for encrypted swap,
          qemu_fw_cfg for the native QEMU metadata reader, and cloud
          NIC drivers (ena/gve/hv_netvsc/mlx5_core/mlx4_en) that
          stage-1 metadata networking may need to DHCP for instance
          metadata. Hardware-specific cloud NICs are left for
          udev/modalias autoload rather than force-loaded on every
          hypervisor. (af_packet is builtin — CONFIG_PACKET=y — so it
          is not listed here.)
        '';
      };

      ## Kernel modules to force-load in the initrd.
      loadModules = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = ''
          Kernel modules to force-load through the initrd's
          `/etc/modules-load.d/initrd.conf`. When this option is left
          at its module default, AOS derives it from
          `aos.boot.initrd.modules` but removes hardware-autoloaded
          cloud NIC drivers (ena/gve/hv_netvsc/mlx5_core/mlx4_en).
          Those drivers remain available in the copied module tree and
          load via udev/modalias only on matching hardware, avoiding
          noisy module insertion failures on unrelated hypervisors.
        '';
      };

      modulePackages = lib.mkOption {
        type = lib.types.listOf lib.types.package;
        default = [];
        description = ''
          External kernel-module packages required before switch-root. Keep
          this list limited to storage and unlock dependencies; runtime-only
          drivers belong in aos.kernel.modulePackages.
        '';
      };

      firmwarePackages = lib.mkOption {
        type = lib.types.listOf lib.types.package;
        default = [pkgs.server-initrd-firmware];
        description = ''
          Firmware packages required before switch-root. The default is a
          focused server storage and network subset. Runtime-only device
          firmware belongs in aos.kernel.firmwarePackages; hardware profiles
          must add any other firmware required to discover or unlock root.
        '';
      };

      ## Extra packages whose full runtime closures are copied into the
      ## initrd's /nix/store, beyond the built-in set. Used by features
      ## that need an extra file or tool available pre-switch-root — e.g.
      ## measured boot ships the PCR-policy public key here so the
      ## first-boot /var sealing service can read it (RFC-0006 phase 3).
      extraPackages = lib.mkOption {
        type = lib.types.listOf lib.types.package;
        default = [];
        description = ''
          Additional packages (derivations) whose closures are included
          in the initrd. Anything an initrd unit references by store path
          must be reachable through this list, since the initrd copies a
          fixed package set rather than the whole toplevel closure.
        '';
      };
    };
  };

  config = {
    # Base initrd module manifest (see `baseInitrdModules` above). Contributed
    # as a def with `mkBefore` so feature modules append after it.
    aos.boot.initrd.modules = lib.mkBefore baseInitrdModules;

    # Base kernel command line — always present.
    aos.boot.kernelParams = [
      "console=ttyS0,115200"
      "console=tty0"
      "systemd.unified_cgroup_hierarchy=1"
      # Turn off systemd-gpt-auto-generator — it synthesises .swap /
      # .mount units at boot with `ExecStart=/usr/sbin/swapon`, a path
      # AOS's rootfs doesn't populate. AOS owns swap (cryptswap.service)
      # and root (root=/dev/disk/by-partlabel/root-a → systemd-fstab-
      # generator) explicitly, so there's nothing for the auto-generator
      # to contribute that's not already covered. Both `systemd.gpt-auto=`
      # (hyphenated) and `systemd.gpt_auto=` (underscored) are accepted
      # by systemd's parameter parser; ship the hyphenated spelling to
      # match the upstream man page.
      "systemd.gpt-auto=0"
      # root= + ro for systemd-fstab-generator. The UKI's baked
      # cmdline is the only cmdline the kernel sees (sd-boot passes
      # no kargs of its own), so without an explicit root= systemd
      # cannot synthesise sysroot.mount. Partition labels are stable
      # across disk renaming (vda vs. nvme0n1) and match what the
      # image builder writes via sfdisk (name="root-a"). Driven off
      # `aos.filesystems.rootDevice` (default = the root-a partlabel, so
      # unchanged) so dm-verity (modules/security/verity.nix) can retarget
      # it to /dev/mapper/root by setting rootDevice — no mkForce surgery.
      "root=${config.aos.filesystems.rootDevice}"
      "ro"
      # Mask systemd-boot-random-seed.service: with efivarfs now built-in
      # (CONFIG_EFIVAR_FS=y, base.config) its ConditionPathExists is met,
      # so it activates and then fails trying to write /loader/random-seed
      # to the read-only ESP. AOS images are immutable and don't maintain
      # an sd-boot random seed, so mask it rather than leave a failed unit
      # on every UEFI boot (RFC-0006).
      "systemd.mask=systemd-boot-random-seed.service"
      # Same immutable-ESP rationale: the image builder owns sd-boot and
      # UKI placement, so the guest must not attempt a runtime bootloader
      # update and leave systemd-boot-update.service failed.
      "systemd.mask=systemd-boot-update.service"
      # The stock blessing service runs as soon as systemd considers boot
      # complete. AOS instead keeps a counted image pending until
      # host policy has evaluated, activated, and produced its attestation;
      # aos-image-boot-commit performs that delayed blessing explicitly.
      "systemd.mask=systemd-bless-boot.service"
    ];

    aos.boot.initrd.loadModules = lib.mkDefault (
      lib.filter (
        module: !(builtins.elem module hardwareAutoloadedInitrdModules)
      )
      config.aos.boot.initrd.modules
    );

    # systemd-initrd kernel modules configuration.
    # Written to /etc/initrd-modules.conf for the image builder.
    environment.etc."initrd-modules.conf" = lib.mkIf config.aos.boot.initrd.enable {
      text = ''
        # Kernel modules to include in the systemd-based initrd.
        # Generated by modules/base/boot.nix
        ${builtins.concatStringsSep "\n" config.aos.boot.initrd.modules}
      '';
    };
  };
}
