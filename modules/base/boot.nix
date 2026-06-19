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
  ...
}: {
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
        default = [
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
          # Cloud NIC drivers — stage-1 ignition brings up DHCP on
          # network-dependent platforms to fetch instance metadata.
          # systemd-modules-load ignores absent/hardware-missing modules,
          # so listing drivers irrelevant to a given platform is safe.
          "ena" # AWS Nitro
          "gve" # GCP gVNIC
          "hv_netvsc" # Azure / Hyper-V
          "mlx5_core" # Azure accelerated networking (ConnectX-5+)
          "mlx4_en" # Mellanox ConnectX-3 (pulls mlx4_core via modprobe)
        ];
        description = ''
          Kernel modules to include in the initrd. These are loaded
          early in boot before the root filesystem is mounted. The
          defaults cover virtio (QEMU/KVM block, PCI, net), ext4
          root, ISO9660 metadata channel, USB mass storage
          (usb_storage/uas) for bare-metal IPMI virtual media,
          overlayfs for /etc, dm-crypt for encrypted swap,
          qemu_fw_cfg for ignition's QEMU platform reader, and the
          cloud NIC drivers (ena/gve/hv_netvsc/mlx5_core/mlx4_en)
          that stage-1 ignition networking needs to DHCP for instance
          metadata. (af_packet is builtin — CONFIG_PACKET=y — so it is
          not listed here.)
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
    assertions = [
      {
        assertion =
          !(lib.any
            (p: lib.hasPrefix "ignition.config.url=" p)
            config.aos.boot.kernelParams);
        message = ''
          aos.boot.kernelParams must not contain `ignition.config.url=…`.

          The UKI's .cmdline is baked into a signed binary; hardcoding a
          config URL there would make every boot from the image fetch
          from that URL, overriding platform detection. Provide per-
          deployment ignition configs via the `aos-metadata` ISO9660
          channel instead (see modules/services/ignition.nix).
        '';
      }
    ];

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
      # image builder writes via sfdisk (name="root-a").
      "root=/dev/disk/by-partlabel/root-a"
      "ro"
      # Mask systemd-boot-random-seed.service: with efivarfs now built-in
      # (CONFIG_EFIVAR_FS=y, base.config) its ConditionPathExists is met,
      # so it activates and then fails trying to write /loader/random-seed
      # to the read-only ESP. AOS images are immutable and don't maintain
      # an sd-boot random seed, so mask it rather than leave a failed unit
      # on every UEFI boot (RFC-0006).
      "systemd.mask=systemd-boot-random-seed.service"
    ];

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
