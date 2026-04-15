##! modules/base/boot.nix — Boot configuration module
##!
##! Configures the boot loader (systemd-boot), kernel command line parameters,
##! systemd-based initrd, Unified Kernel Image (UKI), and Secure Boot support.
##! The initrd uses systemd for service-based boot ordering (no dracut).
##!
##! Absorbed TOML config values:
##!   [boot] loader, kernel_params
##!   [boot.initrd] enable, modules
##!   [boot.uki] enable
##!   [boot.secure_boot] enable
{
  config,
  pkgs,
  lib,
  ...
}:
let
  cfg = config.aos.boot;

  # Build the complete kernel command line string from the list of parameters.
  kernelCmdline = builtins.concatStringsSep " " cfg.kernelParams;
in
{
  options.aos.boot = {
    ## Boot loader to use (currently systemd-boot only).
    loader = lib.mkOption {
      type = lib.types.str;
      default = "systemd-boot";
      description = ''
        Boot loader to use. Currently only "systemd-boot" is supported.
        Future: "grub", "direct" (direct kernel boot for VMs).
      '';
    };

    ## Kernel command line parameters.
    ##
    ## Other modules (e.g. SELinux, hardening) append to this list.
    ##
    ## # Examples
    ## ```nix
    ## aos.boot.kernelParams = [ "console=ttyS0,115200" "selinux=1" ];
    ## ```
    kernelParams = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Kernel command line parameters. These are written to the boot loader
        entry and passed to the kernel at boot time. Base parameters
        (console, cgroup v2) are set in the config section below; other
        modules append their own.
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
          "overlay"
          "dm-crypt"
          "qemu_fw_cfg"
        ];
        description = ''
          Kernel modules to include in the initrd. These are loaded early
          in boot before the root filesystem is mounted. The defaults cover
          virtio (QEMU/KVM block, PCI, net), ext4 root, overlayfs for /etc,
          dm-crypt for encrypted swap, and qemu_fw_cfg so ignition can read
          its config from the QEMU firmware config device.
        '';
      };
    };

    uki = {
      ## Build a Unified Kernel Image (UKI).
      ##
      ## # See Also
      ## - `aos.boot.secureBoot.enable`
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Build a Unified Kernel Image (UKI) that combines the kernel,
          initrd, and command line into a single signed EFI binary.
          Requires Secure Boot infrastructure.
        '';
      };
    };

    secureBoot = {
      ## Enable UEFI Secure Boot support.
      ##
      ## # See Also
      ## - `aos.boot.uki.enable`
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Enable UEFI Secure Boot support. When enabled, the boot loader
          and kernel are signed with the platform key. Requires UKI to be
          enabled for full chain-of-trust.
        '';
      };
    };
  };

  config = {
    # Base kernel command line — always present.
    aos.boot.kernelParams = [
      "console=ttyS0,115200"
      "console=tty0"
      "systemd.unified_cgroup_hierarchy=1"
      # Turn off systemd-gpt-auto-generator — it synthesises .swap /
      # .mount units at boot with `ExecStart=/usr/sbin/swapon`, a path
      # AOS's rootfs doesn't populate. AOS owns swap (cryptswap.service)
      # and root (/etc/fstab → systemd-fstab-generator) explicitly, so
      # there's nothing for the auto-generator to contribute that's
      # not already covered. Both `systemd.gpt-auto=` (hyphenated, the
      # documented form) and `systemd.gpt_auto=` (underscored) are
      # accepted by systemd's parameter parser; ship the hyphenated
      # spelling to match the upstream man page.
      "systemd.gpt-auto=0"
    ];

    # systemd-boot loader entry for the current generation.
    # Written to /boot/loader/entries/aos.conf
    environment.etc."boot/loader/entries/aos.conf" = {
      text = ''
        title   AOS ${config.aos.system.version}
        linux   /vmlinuz
        ${lib.optionalString cfg.initrd.enable "initrd  /initramfs.img"}
        options ${kernelCmdline}
      '';
    };

    # systemd-boot loader configuration.
    # Written to /boot/loader/loader.conf
    environment.etc."boot/loader/loader.conf" = {
      text = ''
        default aos.conf
        timeout 3
        console-mode max
        editor  no
      '';
    };

    # systemd-initrd kernel modules configuration.
    # Written to /etc/initrd-modules.conf for the image builder.
    environment.etc."initrd-modules.conf" = lib.mkIf cfg.initrd.enable {
      text = ''
        # Kernel modules to include in the systemd-based initrd.
        # Generated by modules/base/boot.nix
        ${builtins.concatStringsSep "\n" cfg.initrd.modules}
      '';
    };

    # UKI build configuration — tells systemd-ukify how to combine
    # kernel + initrd + cmdline into a single PE binary.
    environment.etc."kernel/uki.conf" = lib.mkIf cfg.uki.enable {
      text = ''
        # UKI configuration — generated by modules/base/boot.nix
        [UKI]
        Linux=/boot/vmlinuz
        Initrd=/boot/initramfs.img
        Cmdline=${kernelCmdline}
        OSRelease=@/etc/os-release
        ${lib.optionalString cfg.secureBoot.enable "SecureBootSigningTool=${pkgs.sbsigntools}/bin/sbsign"}
      '';
    };
  };
}
