##! Portable immutable boot-storage addressing shared by image and native replay.
{
  config,
  lib,
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
  deviceOption = name:
    lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Override the stable block-device path for the ${name} image artifact.";
    };
in {
  imports = [./policy-options.nix];
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

  config.aos.boot.storage.resolvedDevices = resolvedDevices;
}
