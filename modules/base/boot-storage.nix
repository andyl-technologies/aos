##! modules/base/boot-storage.nix — Immutable boot-storage addressing
##!
##! Separates the A/B image lifecycle from the block devices that carry its
##! immutable EROFS payloads and dm-verity trees. The stock image uses GPT
##! partition labels. Installed systems may instead address fixed-size ZFS
##! zvols while retaining the same signed UKIs, image generations, counted
##! boots, and rollback protocol.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.boot.storage;
  zvolBase = "/dev/zvol/${cfg.zfs.poolName}/${cfg.zfs.dataset}";
  defaultDevices =
    if cfg.backend == "zfs-zvol"
    then {
      rootA = "${zvolBase}/root-a";
      rootAHash = "${zvolBase}/root-a-hash";
      rootB = "${zvolBase}/root-b";
      rootBHash = "${zvolBase}/root-b-hash";
    }
    else {
      rootA = "/dev/disk/by-partlabel/root-a";
      rootAHash = "/dev/disk/by-partlabel/root-a-hash";
      rootB = "/dev/disk/by-partlabel/root-b";
      rootBHash = "/dev/disk/by-partlabel/root-b-hash";
    };
  resolvedDevices =
    lib.mapAttrs (
      name: fallback:
        if cfg.devices.${name} == null
        then fallback
        else cfg.devices.${name}
    )
    defaultDevices;
  zfsPackage = pkgs.zfsForKernel config.system.build.kernel;
  containerDatasets = dataset: let
    segments = lib.splitString "/" dataset;
  in
    lib.genList (
      depth: lib.concatStringsSep "/" (lib.take (depth + 1) segments)
    ) (builtins.length segments);
  deviceOption = name:
    lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Override the stable block-device path for the ${name} image artifact.";
    };
in {
  options.aos.boot.storage = {
    backend = lib.mkOption {
      type = lib.types.enum ["gpt-partitions" "zfs-zvol"];
      default = "gpt-partitions";
      description = ''
        Block-storage backend for immutable A/B image payloads. GPT partitions
        preserve the portable raw-image layout. zfs-zvol addresses fixed-size
        zvols in an imported pool without changing image-generation semantics.
      '';
    };

    espDevices = lib.mkOption {
      type = lib.types.nonEmptyListOf lib.types.str;
      default = ["/dev/disk/by-partlabel/ESP"];
      description = ''
        Stable device paths for independently bootable EFI System Partition
        replicas. Firmware identifies the ESP that actually booted; it becomes
        the authoritative /boot mount, and successful update transactions
        replicate bootloader configuration and UKIs to every other entry.
      '';
    };

    devices = {
      rootA = deviceOption "slot-A root";
      rootAHash = deviceOption "slot-A dm-verity tree";
      rootB = deviceOption "slot-B root";
      rootBHash = deviceOption "slot-B dm-verity tree";
    };

    resolvedDevices = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      readOnly = true;
      internal = true;
      description = "Resolved immutable image block-device paths.";
    };

    zfs = {
      poolName = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z][A-Za-z0-9_.:-]*";
        default = "rpool";
        description = "Pool containing immutable image zvols.";
      };

      dataset = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+)*";
        default = "aos/slots";
        description = "Dataset below the pool containing immutable image zvols.";
      };

      encryptionRoot = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z][A-Za-z0-9_.:-]*(/[A-Za-z0-9_.:-]+)*";
        default = cfg.zfs.poolName;
        description = "Native-encryption root containing immutable zvols and mutable datasets.";
      };

      rootSlotSizeMiB = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value > 0);
        default = config.aos.image.rootPartitionMiB;
        description = "Fixed capacity of each immutable root zvol in MiB.";
      };

      veritySlotSizeMiB = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value > 0);
        default = config.aos.image.budgets.maxVerityMiB;
        description = "Fixed capacity of each dm-verity hash zvol in MiB.";
      };

      sealedKeyPath = lib.mkOption {
        type = lib.types.strMatching "aos/[A-Za-z0-9_.+-]+";
        default = "aos/zfs-key.cred";
        description = "ESP-relative TPM-sealed native ZFS key path.";
      };

      compatibility = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9_.,-]+";
        default = "openzfs-2.3";
        description = ''
          Pool feature set retained across rollback slots. Raise this only
          after every bootable image can import the resulting feature set.
        '';
      };
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = lib.all (device: lib.hasPrefix "/dev/" device) cfg.espDevices;
          message = "aos.boot.storage.espDevices entries must be absolute /dev paths";
        }
        {
          assertion = lib.all (device: lib.hasPrefix "/dev/" device) (builtins.attrValues resolvedDevices);
          message = "resolved immutable boot-storage devices must be absolute /dev paths";
        }
        {
          assertion = !lib.hasInfix ".." cfg.zfs.sealedKeyPath;
          message = "aos.boot.storage.zfs.sealedKeyPath must be a normalized path under aos/";
        }
        {
          assertion = cfg.zfs.rootSlotSizeMiB >= config.aos.image.budgets.maxRootMiB;
          message = "ZFS root slot capacity must be at least the image root artifact budget";
        }
        {
          assertion = cfg.zfs.veritySlotSizeMiB >= config.aos.image.budgets.maxVerityMiB;
          message = "ZFS verity slot capacity must be at least the image verity artifact budget";
        }
      ];

      aos.boot.storage.resolvedDevices = resolvedDevices;
      aos.filesystems.espDevice = lib.mkDefault (builtins.head cfg.espDevices);
      environment.systemPackages = [pkgs.aos-boot-storage];
      aos.boot.initrd.packageRoots = [
        pkgs.aos-boot-storage
        pkgs.aos-boot-transaction-storage-provider
      ];
      aos.abilities.stages.initrd = {
        modules = [
          {aos.boot.storageServices.espDevices = cfg.espDevices;}
        ];
      };
    }
    (lib.mkIf (cfg.backend == "zfs-zvol") {
      aos.boot.initrd.modulePackages = [zfsPackage];
      aos.boot.initrd.packageRoots = [zfsPackage];
      aos.boot.initrd.loadModules = ["zfs"];
      aos.abilities.stages.initrd = {
        modules = [
          {
            aos.boot.storageServices = {
              zfs = {
                enable = true;
                inherit (cfg.zfs) poolName encryptionRoot sealedKeyPath;
                expectedDevices = builtins.attrValues resolvedDevices;
              };
            };
          }
        ];
      };
      aos.filesystems.zfs = {
        enable = true;
        poolName = cfg.zfs.poolName;
        package = zfsPackage;
        datasets = lib.genAttrs (containerDatasets cfg.zfs.dataset) (_: {
          mountPoint = null;
          snapshot = false;
        });
      };
    })
  ];
}
