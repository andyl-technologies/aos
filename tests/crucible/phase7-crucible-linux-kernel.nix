{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleLinuxKernel",
  taskIds ? ["T-PKG-12"],
  linuxCrucible ? pkgs.linux-crucible,
  anyGuestGate ? throw "crucible phase7 linux-crucible check requires checks.crucible.phase2.gates.anyGuest",
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  pkgsDefault = builtins.readFile ../../pkgs/default.nix;
  linuxCrucibleNix = builtins.readFile ../../pkgs/kernel/linux-crucible.nix;
  linuxNix = builtins.readFile ../../pkgs/kernel/linux.nix;
  baseBuildModule = builtins.readFile ../../modules/base/build.nix;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  linuxFixtureWithMetadataProbe = extraConfig: let
    base = {
      pname = "linux";
      version = "6.18.33";
      src = "/stub/linux-source";
      passthru = {};
      meta = {};
      inherit extraConfig;
    };
  in
    base
    // {
      overrideAttrs = f: base // (f base);
    };
  linuxCrucibleMetadata = import ../../pkgs/kernel/linux-crucible.nix {
    inherit lib;
    stdenv.hostPlatform.system = pkgs.stdenv.hostPlatform.system;
    linuxFixtureWith = linuxFixtureWithMetadataProbe;
  };
  linuxCrucibleExtraConfig =
    if linuxCrucibleMetadata ? passthru && linuxCrucibleMetadata.passthru ? crucibleExtraConfig
    then linuxCrucibleMetadata.passthru.crucibleExtraConfig
    else throw "crucible phase7 linux-crucible check requires pkgs.linux-crucible.passthru.crucibleExtraConfig";
  linuxCrucibleCmdline =
    if linuxCrucibleMetadata ? passthru && linuxCrucibleMetadata.passthru ? crucibleFixtureKernelCmdline
    then linuxCrucibleMetadata.passthru.crucibleFixtureKernelCmdline
    else throw "crucible phase7 linux-crucible check requires pkgs.linux-crucible.passthru.crucibleFixtureKernelCmdline";
  linuxCrucibleConsole =
    if linuxCrucibleMetadata ? passthru && linuxCrucibleMetadata.passthru ? crucibleFixtureConsole
    then linuxCrucibleMetadata.passthru.crucibleFixtureConsole
    else "";
  fixtureConsole =
    {
      "x86_64-linux" = "ttyS0";
      "aarch64-linux" = "ttyAMA0";
    }
    .${
      pkgs.stdenv.hostPlatform.system
    }
    or (throw "crucible phase7 linux-crucible check does not support ${pkgs.stdenv.hostPlatform.system}");
  fixtureSerialConsoleConfig =
    {
      "x86_64-linux" = "CONFIG_SERIAL_8250_CONSOLE=y";
      "aarch64-linux" = "CONFIG_SERIAL_AMBA_PL011_CONSOLE=y";
    }
    .${
      pkgs.stdenv.hostPlatform.system
    }
    or (throw "crucible phase7 linux-crucible check does not support ${pkgs.stdenv.hostPlatform.system}");
  linuxCruciblePname = linuxCrucibleMetadata.pname or "(missing)";
  linuxCrucibleFixtureOnly =
    linuxCrucibleMetadata
    ? passthru
    && linuxCrucibleMetadata.passthru ? crucibleFixtureOnly
    && linuxCrucibleMetadata.passthru.crucibleFixtureOnly;
  linuxCrucibleDeterminismMechanism =
    if linuxCrucibleMetadata ? passthru && linuxCrucibleMetadata.passthru ? crucibleDeterminismMechanism
    then linuxCrucibleMetadata.passthru.crucibleDeterminismMechanism
    else "";

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  forbiddenKernelSuppression = [
    {
      label = "nokaslr fixture requirement";
      needle = "nokaslr";
    }
    {
      label = "norandmaps fixture requirement";
      needle = "norandmaps";
    }
    {
      label = "disabled kernel RNG";
      needle = "CONFIG_RANDOM=n";
    }
    {
      label = "disabled kernel RNG canonical Kconfig form";
      needle = "# CONFIG_RANDOM is not set";
    }
    {
      label = "disabled x86 RDRAND";
      needle = "CONFIG_X86_RDRAND=n";
    }
    {
      label = "disabled x86 RDRAND canonical Kconfig form";
      needle = "# CONFIG_X86_RDRAND is not set";
    }
    {
      label = "disabled x86 RDSEED";
      needle = "CONFIG_X86_RDSEED=n";
    }
    {
      label = "disabled x86 RDSEED canonical Kconfig form";
      needle = "# CONFIG_X86_RDSEED is not set";
    }
    {
      label = "disabled architecture RNG";
      needle = "CONFIG_ARCH_RANDOM=n";
    }
    {
      label = "disabled architecture RNG canonical Kconfig form";
      needle = "# CONFIG_ARCH_RANDOM is not set";
    }
    {
      label = "RDRAND clearcpuid";
      needle = "clearcpuid";
    }
    {
      label = "RDRAND-off cmdline";
      needle = "rdrand=off";
    }
  ];

  # Determinism shaping is now forbidden on the shipped fixture cmdline: the
  # fixture kernel is stock and no guest cmdline param may be load-bearing for
  # reproducibility. These are checked against the fixture cmdline only (the
  # host-side QEMU launch, owned elsewhere, is what actually seeds determinism).
  forbiddenCmdlineShaping = [
    {
      label = "KASLR suppression";
      needle = "nokaslr";
    }
    {
      label = "randomized-mmap suppression";
      needle = "norandmaps";
    }
    {
      label = "CPU RNG trust cmdline";
      needle = "random.trust_cpu=";
    }
    {
      label = "bootloader RNG trust cmdline";
      needle = "random.trust_bootloader=";
    }
    {
      label = "pinned clocksource";
      needle = "clocksource=";
    }
    {
      label = "timer check suppression";
      needle = "no_timer_check";
    }
    {
      label = "SMP suppression";
      needle = "nosmp";
    }
  ];

  failures =
    lib.optionals (linuxCruciblePname != "linux-crucible") [
      "pkgs.linux-crucible: expected pname linux-crucible, got ${linuxCruciblePname}"
    ]
    ++ lib.optionals (!linuxCrucibleFixtureOnly) [
      "pkgs.linux-crucible: passthru.crucibleFixtureOnly must be true so it is not mistaken for a user-guest precondition"
    ]
    ++ lib.optionals (linuxCrucibleDeterminismMechanism != "host-side-qemu-icount-seeded-entropy") [
      "pkgs.linux-crucible: passthru.crucibleDeterminismMechanism must name the host-side QEMU-seeded entropy mechanism"
    ]
    ++ lib.optionals (linuxCrucibleConsole != fixtureConsole) [
      "pkgs.linux-crucible: expected native console ${fixtureConsole}, got ${linuxCrucibleConsole}"
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-12 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleLinuxKernel`";
      }
      {
        label = "linux-crucible package reference";
        needle = "`pkgs.linux-crucible`";
      }
    ]
    ++ failuresFor "pkgs/default.nix" pkgsDefault [
      {
        label = "package auto-discovery";
        needle = "discoverPackages ./.";
      }
    ]
    ++ failuresFor "pkgs/kernel/linux-crucible.nix" linuxCrucibleNix [
      {
        label = "linuxFixtureWith package construction";
        needle = "(linuxFixtureWith extraConfig).overrideAttrs";
      }
      {
        label = "distinct package name";
        needle = "pname = \"linux-crucible\";";
      }
      {
        label = "exported extra config";
        needle = "crucibleExtraConfig = extraConfig;";
      }
      {
        label = "fixture-only marker";
        needle = "crucibleFixtureOnly = true;";
      }
      {
        label = "fixture cmdline marker";
        needle = "crucibleFixtureKernelCmdline = lib.concatStringsSep \" \" fixtureKernelParams;";
      }
    ]
    ++ forbiddenFor "pkgs/kernel/linux-crucible.nix" linuxCrucibleNix (
      forbiddenKernelSuppression
      ++ [
        {
          label = "linux.override construction";
          needle = "linux.override";
        }
        {
          label = "nixpkgs import";
          needle = "<nixpkgs>";
        }
        {
          label = "host tools pattern";
          needle = "hostTools";
        }
      ]
    )
    ++ failuresFor "pkgs.linux-crucible.passthru.crucibleExtraConfig" linuxCrucibleExtraConfig [
      {
        label = "serial console";
        needle = fixtureSerialConsoleConfig;
      }
      {
        label = "virtio bus";
        needle = "CONFIG_VIRTIO=y";
      }
      {
        label = "virtio PCI";
        needle = "CONFIG_VIRTIO_PCI=y";
      }
      {
        label = "virtio block";
        needle = "CONFIG_VIRTIO_BLK=y";
      }
      {
        label = "virtio net";
        needle = "CONFIG_VIRTIO_NET=y";
      }
      {
        label = "virtio console";
        needle = "CONFIG_VIRTIO_CONSOLE=y";
      }
      {
        label = "fork-time debug agent uevent helper";
        needle = "CONFIG_UEVENT_HELPER=y";
      }
      {
        label = "fork-time debug agent helper starts disabled";
        needle = ''CONFIG_UEVENT_HELPER_PATH=""'';
      }
      {
        label = "virtio 9p transport";
        needle = "CONFIG_NET_9P_VIRTIO=y";
      }
      {
        label = "9p filesystem built in";
        needle = "CONFIG_9P_FS=y";
      }
      {
        label = "ext4 fixture root image support";
        needle = "CONFIG_EXT4_FS=y";
      }
      {
        label = "no loadable modules";
        needle = "# CONFIG_MODULES is not set";
      }
      {
        label = "no automatic module loading";
        needle = "# CONFIG_KMOD is not set";
      }
      {
        label = "ACPI topology";
        needle = "CONFIG_ACPI=y";
      }
      {
        label = "virtio IOMMU";
        needle = "CONFIG_VIRTIO_IOMMU=y";
      }
      {
        label = "ACPI VIOT topology";
        needle = "CONFIG_ACPI_VIOT=y";
      }
    ]
    ++ forbiddenFor "pkgs.linux-crucible.passthru.crucibleExtraConfig" linuxCrucibleExtraConfig forbiddenKernelSuppression
    ++ failuresFor "pkgs.linux-crucible.passthru.crucibleFixtureKernelCmdline" linuxCrucibleCmdline [
      {
        label = "serial console cmdline";
        needle = "console=${fixtureConsole}";
      }
    ]
    ++ forbiddenFor "pkgs.linux-crucible.passthru.crucibleFixtureKernelCmdline" linuxCrucibleCmdline (
      forbiddenKernelSuppression ++ forbiddenCmdlineShaping
    )
    ++ failuresFor "pkgs/kernel/linux.nix" linuxNix [
      {
        label = "module build guarded by final config";
        needle = "if gawk '/^CONFIG_MODULES=y$/ { found = 1 } END { exit found ? 0 : 1 }' .config; then\n            make -j$NIX_BUILD_CORES ARCH=" + "$" + "{kernelArch.karch} modules\n          fi";
      }
      {
        label = "module install guarded by final config";
        needle = "if gawk '/^CONFIG_MODULES=y$/ { found = 1 } END { exit found ? 0 : 1 }' .config; then\n            make modules_install";
      }
    ]
    ++ failuresFor "modules/base/build.nix" baseBuildModule [
      {
        label = "generic system kernel remains default";
        needle = "system.build.kernel = pkgs.linux;";
      }
    ]
    ++ forbiddenFor "modules/base/build.nix" baseBuildModule [
      {
        label = "linux-crucible as default system kernel";
        needle = "system.build.kernel = pkgs.linux-crucible;";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 linux-crucible check imported";
        needle = "crucibleLinuxKernel = import ./phase7-crucible-linux-kernel.nix";
      }
      {
        label = "phase7 linux-crucible check depends on any-guest proof";
        needle = "anyGuestGate = phase2.gates.anyGuest;";
      }
      {
        label = "phase7 e2e determinism consumes linux-crucible package proof";
        needle = "dependencies = [phase1.gates.licenseBoundary.rawGate perfBench.rawGate phase7.crucibleLinuxKernel phase7.crucibleFixtures phase7.crucibleGateCiWiring phase7.crucibleReleaseManifest phase7.reproductionProvenanceTriple];";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 linux-crucible check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-crucible-linux-kernel";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.findutils
        pkgs.grep
      ];

      passthru.linuxCrucible = linuxCrucibleMetadata;
      passthru.linuxCruciblePackage = linuxCrucible;

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu

            : "${linuxCrucible}"
            : "${anyGuestGate}"

            config_file=$(find "${linuxCrucible}/boot" -maxdepth 1 -type f -name 'config-*' | head -n 1)
            if [ -z "$config_file" ]; then
              echo "linux-crucible: missing installed boot/config-* final kernel config" >&2
              exit 1
            fi

            vmlinuz=$(find "${linuxCrucible}/boot" -maxdepth 1 -type f -name 'vmlinuz-*' | head -n 1)
            if [ -z "$vmlinuz" ]; then
              echo "linux-crucible: missing installed boot/vmlinuz-* kernel image" >&2
              exit 1
            fi

            require_config() {
              if ! grep -q -E "$1" "$config_file"; then
                echo "linux-crucible: final kernel config missing $2 ($1)" >&2
                exit 1
              fi
            }

            forbid_config() {
              if grep -q -E "$1" "$config_file"; then
                echo "linux-crucible: final kernel config contains forbidden $2 ($1)" >&2
                exit 1
              fi
            }

            require_config '^${fixtureSerialConsoleConfig}$' 'serial console'
            require_config '^CONFIG_VIRTIO=y$' 'virtio bus'
            require_config '^CONFIG_VIRTIO_PCI=y$' 'virtio PCI'
            require_config '^CONFIG_VIRTIO_BLK=y$' 'virtio block'
            require_config '^CONFIG_VIRTIO_NET=y$' 'virtio net'
            require_config '^CONFIG_VIRTIO_CONSOLE=y$' 'virtio console'
            require_config '^CONFIG_UEVENT_HELPER=y$' 'debug-agent uevent helper'
            require_config '^CONFIG_UEVENT_HELPER_PATH=""$' 'empty default uevent helper path'
            require_config '^CONFIG_NET_9P_VIRTIO=y$' 'virtio 9p transport'
            require_config '^CONFIG_9P_FS=y$' '9p filesystem built in'
            require_config '^CONFIG_EXT4_FS=y$' 'ext4 fixture root image support'
            require_config '^# CONFIG_MODULES is not set$' 'no loadable modules'
            require_config '^CONFIG_ACPI=y$' 'ACPI topology'
            require_config '^CONFIG_VIRTIO_IOMMU=y$' 'virtio IOMMU'
            require_config '^CONFIG_ACPI_VIOT=y$' 'ACPI VIOT topology'

            forbid_config '^CONFIG_RANDOM=n$' 'disabled kernel RNG'
            forbid_config '^# CONFIG_RANDOM is not set$' 'disabled kernel RNG'
            forbid_config '^CONFIG_X86_RDRAND=n$' 'disabled RDRAND'
            forbid_config '^# CONFIG_X86_RDRAND is not set$' 'disabled RDRAND'
            forbid_config '^CONFIG_X86_RDSEED=n$' 'disabled RDSEED'
            forbid_config '^# CONFIG_X86_RDSEED is not set$' 'disabled RDSEED'
            forbid_config '^CONFIG_ARCH_RANDOM=n$' 'disabled architecture RNG'
            forbid_config '^# CONFIG_ARCH_RANDOM is not set$' 'disabled architecture RNG'

            case " ${linuxCrucibleCmdline} " in
              *" nokaslr "*|*" norandmaps "*|*" clearcpuid "*|*" rdrand=off "*|*" nosmp "*|*" no_timer_check "*|*clocksource=*|*random.trust_cpu=*|*random.trust_bootloader=*)
                echo "linux-crucible: fixture cmdline contains forbidden entropy/KASLR/determinism-shaping suppression" >&2
                exit 1
                ;;
            esac

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${taskList}
            package=linux-crucible
            package_passthru=pkgs.linux-crucible
            kernel_builder=pkgs.linuxWith
            fixture_only=true
            final_config=$config_file
            kernel_image=$vmlinuz
            any_guest_gate=${anyGuestGate}
            stock_kernel=true
            determinism_mechanism=host-side-qemu-icount-seeded-entropy
            module_policy=built-in-only
            acpi=false
            forbids=nokaslr,norandmaps,nosmp,clocksource=,no_timer_check,random.trust_cpu=,random.trust_bootloader=,CONFIG_RANDOM=n,RDRAND-disable
            RESULT
          '';
        }
      ];
    }
