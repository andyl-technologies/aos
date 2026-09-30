##! Native OpenZFS configuration with pool and dataset effect ownership.
{
  config,
  options,
  lib,
  package,
  dependencies,
  packageName,
  ...
}: let
  cfg = config.aos.filesystems.zfs;
  size = lib.types.strMatching "[0-9]+[KMGTP]?";
  optionalSize = lib.types.nullOr size;
  propertyMap = lib.types.attrsOf lib.types.str;
  recordSizes = ["4K" "8K" "16K" "32K" "64K" "128K" "256K" "512K" "1M" "2M" "4M" "8M" "16M"];
  safeRecordSizes = ["4K" "8K" "16K" "32K" "64K" "128K"];
  option = type: default: description: lib.mkOption {inherit type default description;};
  datasetType = lib.types.submodule {
    options = {
      mountPoint = option (lib.types.nullOr lib.types.str) null "Absolute mount point, or null for an unmounted dataset.";
      recordSize = option (lib.types.enum recordSizes) "128K" "Dataset block record size.";
      compression = option (lib.types.strMatching "[a-z0-9-]+") "zstd-3" "Compression algorithm and optional level.";
      atime = option lib.types.bool false "Record file access timestamps.";
      quota = option optionalSize null "Dataset space quota.";
      reservation = option optionalSize null "Space reserved exclusively for the dataset.";
      deduplicate = option lib.types.bool false "Enable deduplication within the bounded pool policy.";
      snapshot = option lib.types.bool true "Participate in automatic snapshots.";
      mountOptions = option (lib.types.listOf lib.types.str) ["nosuid" "nodev"] "Mount flags applied when mounting the dataset.";
      extraProperties = option propertyMap {} "Additional exact OpenZFS dataset properties.";
    };
  };
  datasetMap = lib.types.attrsOf datasetType;
  program = mainProgram: package // {meta = (package.meta or {}) // {inherit mainProgram;};};
  poolOperation = config.aos.abilities.zfsPool.operations.import;
  datasetOperation = config.aos.abilities.zfsDataset.operations.mount;
  reservedDatasetName = builtins.unsafeDiscardStringContext cfg.reservedSpace.dataset;
  configuredDatasets =
    cfg.datasets
    // lib.optionalAttrs cfg.reservedSpace.enable {
      ${reservedDatasetName} = {
        mountPoint = null;
        recordSize = "128K";
        compression = "zstd-3";
        atime = false;
        quota = null;
        snapshot = false;
        deduplicate = false;
        reservation = cfg.reservedSpace.size;
        mountOptions = [];
        extraProperties = {};
      };
    };
  propertiesOf = attributes:
    {
      recordsize = attributes.recordSize;
      compression = attributes.compression;
      atime =
        if attributes.atime
        then "on"
        else "off";
      dedup =
        if attributes.deduplicate
        then "on"
        else "off";
      "com.sun:auto-snapshot" =
        if attributes.snapshot
        then "true"
        else "false";
    }
    // lib.optionalAttrs (attributes.quota != null) {quota = attributes.quota;}
    // lib.optionalAttrs (attributes.reservation != null) {refreservation = attributes.reservation;}
    // attributes.extraProperties;
  readinessResources =
    [poolOperation.effects.system.outputs.resource]
    ++ lib.mapAttrsToList (name: _: datasetOperation.effects.${name}.outputs.resource) configuredDatasets;
  largeRecordDatasets = builtins.filter (name: !(builtins.elem cfg.datasets.${name}.recordSize safeRecordSizes)) (builtins.attrNames cfg.datasets);
  deduplicatedDatasets = builtins.filter (name: cfg.datasets.${name}.deduplicate) (builtins.attrNames cfg.datasets);
in {
  imports = [./maintenance.nix ./policy.nix];
  options.aos.filesystems.zfs = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Use native pool and dataset resources for persistent mutable state.";
    };
    poolName = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z][A-Za-z0-9_.:-]*";
      default = "aos-pool";
      description = "Name of the storage pool for persistent data.";
    };
    systemState = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Place the system's mutable state below /var on the selected ZFS pool.";
    };
    datasets = lib.mkOption {
      type = datasetMap;
      default = {};
      description = "Typed ZFS datasets and their exact desired properties.";
    };
    allowLargeRecords = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Permit dataset record sizes above 128 KiB.";
    };
    allowDeduplication = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Permit datasets to enable memory-intensive ZFS deduplication.";
    };
    deduplicationTableQuota = lib.mkOption {
      type = optionalSize;
      default = null;
      description = "Hard pool-wide limit on the ZFS deduplication table.";
    };
    reservedSpace = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Reserve recoverable pool space in an otherwise empty dataset.";
      };
      dataset = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9_.:/-]+";
        default = "reserved";
        description = "Dataset below the pool that carries the recovery reservation.";
      };
      size = lib.mkOption {
        type = size;
        default = "2G";
        description = "Space held by the recovery reservation dataset.";
      };
    };
    reportUndeclaredDatasets = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Report datasets outside the package-owned declared dataset set.";
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion =
            !(cfg.enable && cfg.systemState)
            || config.aos.boot.storage.backend == "zfs-zvol";
          message = "aos.filesystems.zfs.systemState requires the zfs-zvol boot backend so /var can be unlocked before switch-root; set systemState = false for a data-only pool";
        }
        {
          assertion = cfg.allowLargeRecords || largeRecordDatasets == [];
          message = "ZFS datasets ${lib.concatStringsSep ", " largeRecordDatasets} use records above 128 KiB without allowLargeRecords";
        }
        {
          assertion = cfg.allowDeduplication || deduplicatedDatasets == [];
          message = "ZFS datasets ${lib.concatStringsSep ", " deduplicatedDatasets} enable deduplication without allowDeduplication";
        }
        {
          assertion = !cfg.allowDeduplication || cfg.deduplicationTableQuota != null;
          message = "allowDeduplication requires a bounded deduplicationTableQuota";
        }
        {
          assertion = !cfg.reservedSpace.enable || !(builtins.hasAttr reservedDatasetName cfg.datasets);
          message = "the ZFS reservation dataset must not collide with a data-bearing declared dataset";
        }
      ];
      aos.filesystems.zfs.datasets = lib.mkIf cfg.systemState {
        var.mountPoint = "/var";
        "var/log" = {
          mountPoint = "/var/log";
          quota = lib.mkDefault "8G";
          extraProperties.logbias = "throughput";
        };
        "var/lib".mountPoint = "/var/lib";
      };
      aos.storage.mountPointsByProvider.${packageName} = lib.mkIf cfg.enable (
        builtins.filter (mountPoint: mountPoint != null) (
          builtins.map (dataset: dataset.mountPoint or null) (builtins.attrValues configuredDatasets)
        )
      );
      aos.storage.policyByProvider.${packageName} = lib.mkIf cfg.enable {
        compressedSwapRecommended = true;
        hardwareMonitoringRecommended = true;
      };
      aos.storage.readinessByProvider.${packageName} = lib.mkIf cfg.enable readinessResources;
      aos.kernel.commandLineParts.${packageName} = lib.mkIf cfg.enable cfg.moduleParameters;
    }

    {
      aos.abilities.zfsPool.operations.import = {
        input.options = {
          pool = lib.mkOption {
            type = lib.types.strMatching "[A-Za-z][A-Za-z0-9_.:-]*";
            description = "Existing OpenZFS pool to import and configure.";
          };
          properties = option propertyMap {} "Exact pool properties, including deduplication table quota.";
          zpool = option lib.types.str "${dependencies.zfs}/sbin/zpool" "Retained OpenZFS pool executable.";
        };
        result.options = {
          pool = lib.mkOption {
            type = lib.types.str;
            description = "Imported pool name.";
          };
          resource = lib.mkOption {
            type = lib.types.str;
            description = "Logical identity of the pool import lease.";
          };
        };
        handler.program = program "aos-zfs-pool-provider";
        effects.system = lib.mkIf cfg.enable {
          input = {
            pool = cfg.poolName;
            properties = lib.optionalAttrs (cfg.deduplicationTableQuota != null) {dedup_table_quota = cfg.deduplicationTableQuota;};
          };
          after = [config.aos.abilities.serviceManagement.operations.realize.effects."zfs-storage.zfs-memory-policy".outputs.resource];
        };
      };
      aos.abilities.zfsDataset.operations.mount = {
        input.options = {
          pool = lib.mkOption {
            type = lib.types.deferred lib.types.str;
            description = "Pool name produced by its import lease.";
          };
          dataset = lib.mkOption {
            type = lib.types.strMatching "[A-Za-z0-9_.:/-]+";
            description = "Dataset path below the pool.";
          };
          mountpoint = option (lib.types.nullOr lib.types.str) null "Mount point, or null to retain an unmounted dataset.";
          mountOptions = option (lib.types.listOf lib.types.str) [] "Canonical mount flags.";
          properties = option propertyMap {} "Exact dataset property values.";
          zfs = option lib.types.str "${dependencies.zfs}/sbin/zfs" "Retained OpenZFS dataset executable.";
        };
        result.options = {
          path = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            description = "Realized mount point, or null for an unmounted dataset.";
          };
          dataset = lib.mkOption {
            type = lib.types.str;
            description = "Full dataset name retained after lease removal.";
          };
          resource = lib.mkOption {
            type = lib.types.str;
            description = "Logical identity of the dataset mount lease.";
          };
        };
        handler.program = program "aos-zfs-dataset-provider";
        effects = lib.mkIf cfg.enable (lib.mapAttrs (name: attributes: {
            input = {
              pool = poolOperation.effects.system.outputs.pool;
              dataset = name;
              mountpoint = attributes.mountPoint;
              mountOptions = builtins.sort builtins.lessThan (lib.unique attributes.mountOptions);
              properties = propertiesOf attributes;
            };
          })
          configuredDatasets);
      };
    }
    (lib.mkIf cfg.enable {aos.filesystems.zfs.maintenance.enable = lib.mkDefault true;})
    (lib.optionalAttrs ((options.aos.kernel or {}) ? externalPackages) {
      aos.kernel.externalPackages.${packageName} = lib.mkIf cfg.enable [dependencies.zfs];
    })
    (lib.optionalAttrs ((options.aos.boot or {}) ? storageServices) {
      aos.boot.storageServices.zfs.packagePath = toString dependencies.zfs;
    })
  ];
}
