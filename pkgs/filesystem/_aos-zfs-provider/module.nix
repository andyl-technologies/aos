##! OpenZFS implementations and system storage-resource composition.
{
  config,
  lib,
  packageName,
  ...
}: let
  storage = lib.abilities.interfaces.blockStorage.interfaces;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  artifact = lib.abilities.packageOutput {};
  moduleArtifact = lib.abilities.packageOutput {output = "module";};
  cfg = config.aos.filesystems.zfs;
  consumerInstance = "zfs-storage";
  resultOf = lib.abilities.resultOf;
  packageResultOf = request: resultOf "${packageName}:${request}";
  abilityTypes = lib.abilities.types;
  zfsSelector = lib.abilities.packageOutput {package = "zfs";};

  size = abilityTypes.refined {
    name = "ZFS size";
    description = "a non-negative integer with an optional K/M/G/T/P suffix";
    type = abilityTypes.string {
      maxLength = 32;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[0-9]+[KMGTP]?";
      }
    ];
  };
  optionalSize = abilityTypes.optional size;
  compression = abilityTypes.refined {
    name = "ZFS compression algorithm";
    description = "a bounded lower-case ZFS compression algorithm and optional level";
    type = abilityTypes.string {
      maxLength = 64;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[a-z0-9-]+";
      }
    ];
  };
  propertyValue = abilityTypes.string {
    maxLength = 4096;
    syntax = null;
  };
  propertyMap = abilityTypes.map {
    keyMaxLength = 255;
    maxEntries = 256;
    value = propertyValue;
  };
  recordSizes = [
    "4K"
    "8K"
    "16K"
    "32K"
    "64K"
    "128K"
    "256K"
    "512K"
    "1M"
    "2M"
    "4M"
    "8M"
    "16M"
  ];
  safeRecordSizes = builtins.filter (value: builtins.elem value ["4K" "8K" "16K" "32K" "64K" "128K"]) recordSizes;
  datasetType = abilityTypes.record {
    fields = {
      mountPoint = {
        type = abilityTypes.optional abilityTypes.executionPath;
        default = null;
      };
      recordSize = {
        type = abilityTypes.enum recordSizes;
        default = "128K";
      };
      compression = {
        type = compression;
        default = "zstd-3";
      };
      atime = {
        type = abilityTypes.boolean;
        default = false;
      };
      quota = {
        type = optionalSize;
        default = null;
      };
      reservation = {
        type = optionalSize;
        default = null;
      };
      deduplicate = {
        type = abilityTypes.boolean;
        default = false;
      };
      snapshot = {
        type = abilityTypes.boolean;
        default = true;
      };
      mountOptions = {
        type = abilityTypes.list {
          element = propertyValue;
          maxItems = 64;
        };
        default = ["nosuid" "nodev"];
      };
      extraProperties = {
        type = propertyMap;
        default = {};
      };
    };
  };
  datasetMap = abilityTypes.map {
    keyMaxLength = 1024;
    maxEntries = 1024;
    value = datasetType;
  };

  terminal = {
    alias,
    interface,
    interfaceName,
    description,
    entryPoint,
    realizationType,
  }: let
    declaration = lib.abilities.declareInterface {
      name = interfaceName;
      inherit description;
      abi = 1;
      inherit (interface.declaration) requestType methods lifecycle;
      outputs = {};
      guarantees = [];
      aggregation = interface.declaration.aggregation // {controllerGroup = alias;};
    };
    identity = lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration declaration
    );
  in {
    inherit alias declaration identity realizationType;
    implementation = {
      inherit description artifact;
      interface = alias;
      inherit (interface) methods;
      guarantees = [];
      handlerDescriptor = {
        inherit artifact;
        entryPoint = entryPoint;
        arguments = interface.requestType;
        result = interface.observationType;
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
  poolTerminal = terminal {
    alias = "storage-pool-effects";
    interface = storage.pool;
    interfaceName = "aos.zfs.storage-pool-effects";
    description = "Executes admitted OpenZFS pool operations.";
    entryPoint = "bin/aos-zfs-pool-provider";
    realizationType = lib.abilities.types.record {
      fields = {
        schema = lib.abilities.types.enum ["aos.storage.pool-realization/v1"];
        zpool = lib.abilities.types.executableReference;
      };
    };
  };
  datasetTerminal = terminal {
    alias = "storage-dataset-effects";
    interface = storage.dataset;
    interfaceName = "aos.zfs.storage-dataset-effects";
    description = "Executes admitted OpenZFS dataset operations.";
    entryPoint = "bin/aos-zfs-dataset-provider";
    realizationType = lib.abilities.types.record {
      fields = {
        schema = lib.abilities.types.enum ["aos.storage.dataset-realization/v1"];
        zfs = lib.abilities.types.executableReference;
      };
    };
  };
  controller = interface: terminalValue: providerPath: description: {
    inherit description artifact;
    artifacts = [zfsSelector];
    interface = interface.identity;
    inherit (interface) methods;
    guarantees = [];
    requirements.effects = {
      alias = "effects";
      description = "Invokes the package-owned terminal OpenZFS handler.";
      accepted_interfaces = [terminalValue.identity];
      inherit (interface) methods;
      guarantees = [];
      strength = "required";
      fallback = null;
    };
    providerModule = {
      artifact = moduleArtifact;
      path = providerPath;
    };
    desiredType = terminalValue.realizationType;
    requiredFeatures = [];
  };
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      inherit consumerInstance key interface parameters;
    };
  pool = producer "pool" storage.pool {
    name = "system-pool";
    enabled = true;
    pool = cfg.poolName;
    import_policy = "force";
    properties = lib.optionalAttrs (cfg.deduplicationTableQuota != null) {
      dedup_table_quota = cfg.deduplicationTableQuota;
    };
    prerequisites = [(resultOf "zfs-memory-policy-lifecycle" "resource")];
  };
  datasetKey = name: "dataset-${lib.abilities.identityKeyFor "aos.zfs.dataset-request/v1" {
    pool = cfg.poolName;
    dataset = name;
  }}";
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
    // lib.optionalAttrs ((attributes.quota or null) != null) {quota = attributes.quota;}
    // lib.optionalAttrs ((attributes.reservation or null) != null) {refreservation = attributes.reservation;}
    // attributes.extraProperties;
  datasetEntries =
    lib.mapAttrsToList (name: attributes: let
      key = datasetKey name;
      mountpoint = attributes.mountPoint or null;
    in {
      inherit key;
      fragment = producer key storage.dataset {
        name = key;
        enabled = true;
        pool = resultOf "pool" "pool-name";
        dataset = name;
        inherit mountpoint;
        mount_options = attributes.mountOptions;
        properties = propertiesOf attributes;
        prerequisites = [(resultOf "pool" "resource")];
      };
      readiness = packageResultOf key "resource";
    })
    configuredDatasets;
  datasets = builtins.map (entry: entry.fragment) datasetEntries;
  readinessResources =
    [(packageResultOf "pool" "resource")]
    ++ builtins.map (entry: entry.readiness) datasetEntries;
  largeRecordDatasets = builtins.filter (
    name: !(builtins.elem cfg.datasets.${name}.recordSize safeRecordSizes)
  ) (builtins.attrNames cfg.datasets);
  deduplicatedDatasets = builtins.filter (
    name: cfg.datasets.${name}.deduplicate
  ) (builtins.attrNames cfg.datasets);
  fragments = [pool] ++ datasets;
  definitions = builtins.map serviceManagement.splitDefinition fragments;
in {
  imports = [
    ./maintenance.nix
    ./policy.nix
  ];

  options.aos.filesystems.zfs = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Use native pool and dataset resources for persistent mutable state.";
    };
    poolName = lib.mkOption {
      type = lib.abilities.interfaces.blockStorage.types.poolName;
      default = "aos-pool";
      description = "Name of the storage pool for persistent data.";
    };
    systemState = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Place the system's mutable state below /var on the selected ZFS pool.";
    };
    datasets = lib.mkOption {
      type = datasetMap;
      default = {};
      description = "Typed ZFS datasets and their exact desired properties.";
    };
    allowLargeRecords = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Permit dataset record sizes above 128 KiB.";
    };
    allowDeduplication = lib.mkOption {
      type = abilityTypes.boolean;
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
        type = abilityTypes.boolean;
        default = true;
        description = "Reserve recoverable pool space in an otherwise empty dataset.";
      };
      dataset = lib.mkOption {
        type = lib.abilities.interfaces.blockStorage.types.datasetName;
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
      type = abilityTypes.boolean;
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
      aos.kernel.externalPackages.${packageName} = lib.mkIf cfg.enable [zfsSelector];
      aos.kernel.commandLineParts.${packageName} = lib.mkIf cfg.enable cfg.moduleParameters;
    }
    {
      aos.abilities = lib.mkMerge ([
          {
            interfaces.${poolTerminal.alias} = poolTerminal.declaration;
            interfaces.${datasetTerminal.alias} = datasetTerminal.declaration;
            implementations.storage-pool = controller storage.pool poolTerminal "pool-provider.nix" "Converges storage pools through the OpenZFS controller.";
            implementations.storage-dataset = controller storage.dataset datasetTerminal "dataset-provider.nix" "Converges storage datasets through the OpenZFS controller.";
            implementations.${poolTerminal.alias} = poolTerminal.implementation;
            implementations.${datasetTerminal.alias} = datasetTerminal.implementation;
          }
        ]
        ++ builtins.map (definition: definition.declarations) definitions
        ++ lib.optional cfg.enable (lib.mkMerge (
          [{instances.${consumerInstance} = {};}]
          ++ builtins.map (definition: definition.configured) definitions
        )));
    }
    (lib.mkIf cfg.enable {
      aos.services.zfsMaintenance.enable = lib.mkDefault true;
    })
  ];
}
