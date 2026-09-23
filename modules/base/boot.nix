##! modules/base/boot.nix — Boot configuration module
##!
##! Configures provider-neutral kernel command line and initial runtime inputs.
##!
##! The UKI's .cmdline section is baked into a signed binary, so
##! changes to `aos.boot.kernelParams` require an image rebuild (not
##! just a config refresh).
{
  config,
  initrdAbilityEvaluation ? null,
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
  uniqueStoreRoots = lib.uniqueBy (root: builtins.toString root);
  initrdPackageArtifacts =
    if initrdAbilityEvaluation == null
    then []
    else
      lib.flatten (
        builtins.attrValues
        initrdAbilityEvaluation.config.aos.initrdRuntime.artifacts
      );
in {
  imports = [
    ./_initrd-runtime-options.nix
    ./_kernel-command-line-options.nix
  ];

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

    ## Maximum attempts before a selected boot implementation demotes an image.
    bootAttemptLimit = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = 3;
      description = ''
        Maximum number of attempts before the selected image and boot manager
        implementation demotes a deployment. Null disables attempt counting.
      '';
    };

    initrd = {
      ## Whether to generate an initial runtime image.
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Whether to generate the selected initial runtime image.";
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

      ## Complete package-root set whose authenticated modules participate in
      ## the initrd ability fixed point and static contract. The selected
      ## initrd manager supplies the base roots; features append their
      ## pre-switch-root package dependencies.
      packageRoots = lib.mkOption {
        type = lib.types.listOf lib.types.package;
        default = [];
        apply = uniqueStoreRoots;
        internal = true;
        extensible = true;
        description = ''
          Exact derivations whose authenticated declarations form the initrd
          static contract. Non-package paths belong in
          `aos.boot.initrd.nonPackageRuntimeArtifacts`.
        '';
      };

      nonPackageRuntimeArtifacts = lib.mkOption {
        type = lib.types.listOf lib.types.pathInStore;
        default = [];
        apply = uniqueStoreRoots;
        internal = true;
        description = ''
          Exact non-package store artifacts required before switch-root. These
          paths are copied into the initrd but do not author package
          declarations in its static ability contract.
        '';
      };

      runtimeRoots = lib.mkOption {
        type = lib.types.listOf lib.types.pathInStore;
        readOnly = true;
        internal = true;
        description = ''
          Canonical store-path union copied into the initrd. It is derived from
          package roots and explicitly authored non-package runtime artifacts.
        '';
      };
    };
  };

  config = {
    # Base initrd module manifest (see `baseInitrdModules` above). Contributed
    # as a def with `mkBefore` so feature modules append after it.
    aos.boot.initrd.modules = lib.mkBefore baseInitrdModules;
    aos.boot.initrd.runtimeRoots = lib.unique (builtins.map builtins.toString (
      config.aos.boot.initrd.packageRoots
      ++ config.aos.boot.initrd.nonPackageRuntimeArtifacts
      ++ initrdPackageArtifacts
    ));

    # Provider-neutral kernel command line intent.
    aos.boot.kernelParams =
      [
        "console=ttyS0,115200"
        "console=tty0"
        "root=${config.aos.filesystems.rootDevice}"
        "ro"
      ]
      ++ lib.concatMap (name: config.aos.kernel.commandLineParts.${name})
      (builtins.attrNames config.aos.kernel.commandLineParts);

    aos.boot.initrd.loadModules = lib.mkDefault (
      lib.filter (
        module: !(builtins.elem module hardwareAutoloadedInitrdModules)
      )
      config.aos.boot.initrd.modules
    );

    # Initial-runtime kernel module manifest consumed by the selected builder.
    environment.etc."initrd-modules.conf" = lib.mkIf config.aos.boot.initrd.enable {
      text = ''
        # Kernel modules to include in the selected initial runtime.
        # Generated by modules/base/boot.nix
        ${builtins.concatStringsSep "\n" config.aos.boot.initrd.modules}
      '';
    };
  };
}
