##! modules/base/provisioning.nix — one-time host provisioning schema
##!
##! Declares the closed `aos.provisioning` subtree that the initrd may evaluate
##! from authenticated `host.nix`. Normal runtime configuration does not belong
##! here: this namespace is reserved for state committed once during initial
##! provisioning and frozen until factory reset.
##!
##! The storage schema has two layers. `partitions` carve GPT space with
##! systemd-repart; `arrays` bind declared partitions into Linux MD arrays.
##! Either layer can carry a volume: a filesystem, optionally inside a LUKS2
##! container whose key is sealed to the TPM. The `var` partition or array is
##! the system-state volume; every other volume is mounted through
##! `aos.filesystems.volumes` in stage 2.
{lib, ...}: let
  encryptionType = lib.types.nullOr (lib.types.enum ["none" "tpm2"]);

  encryptionDescription = ''
    Encryption applied to the volume this entry carries.

    `tpm2` wraps the filesystem in a LUKS2 container whose key is sealed
    to the measured-boot PCR policy and unlocked unattended by the initrd.
    It requires a measured-boot image. `none` leaves the filesystem on the
    raw device. `null` selects the image policy: the `var` system-state
    volume is `tpm2` on a measured-boot image and `none` otherwise; every
    other volume defaults to `none`.
  '';

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
        description = ''
          Partition type: linux-generic, linux-raid, swap, or an allowed raw
          GPT GUID. A partition named as an array member is always created
          with the linux-raid type.
        '';
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
          Filesystem the partition carries. null leaves the partition raw,
          except for the root-disk `var` partition, which is always ext4. An
          array member must remain null: the filesystem belongs to the array.
          An xfs label is at most 12 bytes; an ext4 label at most 16.
        '';
      };

      encryption = lib.mkOption {
        type = encryptionType;
        default = null;
        description = encryptionDescription;
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
    options = {
      level = lib.mkOption {
        type = lib.types.enum ["raid0" "raid1" "raid10" "raid5" "raid6"];
        description = ''
          MD RAID level. raid1 needs at least two members, raid10 and raid5
          at least three, raid6 at least four.
        '';
      };

      members = lib.mkOption {
        type = lib.types.nonEmptyListOf lib.types.str;
        description = ''
          Logical names of the `aos.provisioning.storage.partitions` entries
          that form the array. Each member is created as a raw linux-raid
          partition; the array named `var` must include the root-disk `var`
          partition.
        '';
      };

      format = lib.mkOption {
        type = lib.types.nullOr (lib.types.enum ["ext4" "xfs"]);
        default = "ext4";
        description = ''
          Filesystem created on the assembled array. null leaves the array
          raw for an operator-managed consumer. The `var` array is always
          ext4. An xfs array name is at most 12 bytes; ext4 allows 16.
        '';
      };

      encryption = lib.mkOption {
        type = encryptionType;
        default = null;
        description = encryptionDescription;
      };
    };
  };
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

    storage.arrays = lib.mkOption {
      type = lib.types.attrsOf arrayType;
      default = {};
      description = ''
        Linux MD arrays created exactly once from declared partitions during
        initial host provisioning and assembled by the initrd on every later
        boot. An array is exposed as `/dev/md/<name>`; its filesystem carries
        the array name as its label.
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
