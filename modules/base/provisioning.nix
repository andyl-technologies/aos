##! modules/base/provisioning.nix — one-time host provisioning schema
##!
##! Declares the closed `aos.provisioning` subtree that the initrd may evaluate
##! from authenticated `host.nix`. Normal runtime configuration does not belong
##! here: this namespace is reserved for state committed once during initial
##! provisioning and frozen until factory reset.
{
  lib,
  ...
}: let
  partitionType = lib.types.submodule ({name, ...}: {
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
        type = lib.types.nullOr (lib.types.enum ["ext4" "vfat" "swap"]);
        default = null;
        description = ''
          Initial filesystem format. null leaves the partition raw; on an
          unmeasured image the renderer formats the reserved var partition
          ext4 when this remains null.
        '';
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
in {
  options.aos.provisioning = {
    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/aos-provisioning";
      internal = true;
      readOnly = true;
      description = "Durable provisioning evidence and manual definition state.";
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
