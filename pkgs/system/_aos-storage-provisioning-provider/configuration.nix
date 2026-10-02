##! Package-owned one-time host provisioning configuration.
##!
##! Declares the closed `aos.provisioning` subtree that the initrd may evaluate
##! from authenticated `host.nix`. Normal runtime configuration does not belong
##! here: this namespace is reserved for state committed once during initial
##! provisioning and frozen until factory reset.
{lib, ...}: let
  partitionType = lib.types.submodule ({name, ...}: {
    _module.strict = true;
    options = {
      device = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Stable target device path. null selects the disk containing root-a;
          explicit paths must use /dev/disk/by-id.
        '';
      };

      label = lib.mkOption {
        type = lib.types.str;
        default = name;
        description = "GPT partition label; defaults to the logical partition name.";
      };

      type = lib.mkOption {
        type = lib.types.str;
        default = "linux-generic";
        description = "Partition type: linux-generic, swap, or an allowed raw GPT GUID.";
      };

      sizeMin = lib.mkOption {
        type = lib.types.str;
        description = "Minimum partition size in systemd size syntax.";
      };

      sizeMax = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Maximum partition size, or null for an unbounded partition.";
      };

      weight = lib.mkOption {
        type = lib.types.int;
        default = 1000;
        description = "Relative allocation weight for available free space.";
      };

      format = lib.mkOption {
        type = lib.types.nullOr (lib.types.enum ["ext4" "xfs" "vfat" "swap"]);
        default = null;
        description = ''
          Initial filesystem format. null leaves the partition raw; on an
          unmeasured image the renderer formats the reserved var partition
          ext4 when this remains null.
        '';
      };

      encryption = lib.mkOption {
        type = lib.types.nullOr (lib.types.enum ["none" "tpm2"]);
        default = null;
        description = "Volume encryption; null follows measured-boot policy. Array members must leave this unset.";
      };

      uuid = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Optional deterministic GPT partition UUID.";
      };

      grow = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Whether the partition consumes remaining free space.";
      };

      growFs = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Whether systemd-repart may grow an existing filesystem.";
      };

      priority = lib.mkOption {
        type = lib.types.int;
        default = 1000;
        description = "Deterministic placement order within the target device.";
      };
    };
  });
  arrayType = lib.types.submodule {
    _module.strict = true;
    options = {
      level = lib.mkOption {
        type = lib.types.enum ["raid0" "raid1" "raid5" "raid6" "raid10"];
        description = "Linux MD RAID level; member counts are checked before provisioning.";
      };
      members = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        description = "Logical partition names used exclusively by this array.";
      };
      format = lib.mkOption {
        type = lib.types.nullOr (lib.types.enum ["ext4" "xfs"]);
        default = null;
        description = "Initial array filesystem; null retains a raw array.";
      };
      encryption = lib.mkOption {
        type = lib.types.nullOr (lib.types.enum ["none" "tpm2"]);
        default = null;
        description = "Array encryption; null follows measured-boot policy.";
      };
    };
  };
in {
  options.aos.provisioning = {
    storage.arrays = lib.mkOption {
      type = lib.types.attrsOf arrayType;
      default = {};
      description = "MD arrays committed with the one-time storage transaction.";
    };
    storage.partitions = lib.mkOption {
      type = lib.types.attrsOf partitionType;
      default = {};
      description = ''
        Partitions committed exactly once during initial host provisioning.
        Subsequent changes are reported as drift and require factory reset.
      '';
    };
  };

  config.aos.provisioning.storage.partitions = {
    swap = {
      type = lib.mkDefault "swap";
      label = lib.mkDefault "swap";
      sizeMin = lib.mkDefault "2G";
      sizeMax = lib.mkDefault "2G";
      format = lib.mkDefault "swap";
      priority = lib.mkDefault 500;
    };

    var = {
      # root-a uses its architecture-specific DPS type, leaving the generic
      # Linux data type exclusively for operator partitions.
      type = lib.mkDefault "linux-generic";
      label = lib.mkDefault "var";
      sizeMin = lib.mkDefault "4G";
      grow = lib.mkDefault true;
      priority = lib.mkDefault 9000;
    };
  };
}
