##! OpenZFS implementations and system storage-resource composition.
{
  config,
  lib,
  packageName,
  ...
}: let
  storage = lib.abilities.interfaces.blockStorage.interfaces;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  abilityTypes = lib.abilities.types;
  artifact = lib.abilities.packageOutput {};
  cfg = config.aos.filesystems.zfs;
  consumerInstance = "zfs-storage";
  resultOf = lib.abilities.resultOf;
  qualifiedResultOf = request: output: {
    _type = "aos-request-output-reference";
    request = "${packageName}:${request}";
    inherit output;
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
      inherit artifact;
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
    prerequisites = [];
  };
  datasetKey = name: "dataset-${builtins.substring 0 32 (builtins.hashString "sha256" name)}";
  datasetConfiguration = abilityTypes.record {
    fields = {
      mountpoint = {
        type = abilityTypes.optional abilityTypes.executionPath;
        optional = true;
        description = "Absolute mountpoint, defaulting to the dataset name below root.";
      };
      properties = {
        type = abilityTypes.map {
          keyMaxLength = 255;
          keySyntax = null;
          maxEntries = 256;
          value = abilityTypes.string {
            maxLength = 4096;
            syntax = null;
          };
        };
        default = {};
        description = "Exact provider-neutral property values applied to the dataset.";
      };
    };
  };
  datasetEntries =
    lib.mapAttrsToList (name: attributes: let
      key = datasetKey name;
      mountpoint = attributes.mountpoint or "/${name}";
    in {
      inherit key;
      fragment = producer key storage.dataset {
        name = key;
        enabled = true;
        pool = resultOf "pool" "pool-name";
        dataset = name;
        inherit mountpoint;
        inherit (attributes) properties;
        prerequisites = [(resultOf "pool" "readiness-resource")];
      };
      readiness = qualifiedResultOf key "readiness-resource";
    })
    cfg.datasets;
  datasets = builtins.map (entry: entry.fragment) datasetEntries;
  readinessResources =
    [(qualifiedResultOf "pool" "readiness-resource")]
    ++ builtins.map (entry: entry.readiness) datasetEntries;
  fragments = [pool] ++ datasets;
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.filesystems.zfs = {
    enable = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      description = "Use native pool and dataset resources for persistent mutable state.";
    };
    poolName = lib.mkOption {
      type = lib.abilities.interfaces.blockStorage.types.poolName;
      default = "aos-pool";
      description = "Name of the storage pool for persistent data.";
    };
    datasets = lib.mkOption {
      type = abilityTypes.map {
        keyMaxLength = 1024;
        keySyntax = null;
        maxEntries = 1024;
        value = datasetConfiguration;
      };
      default = {};
      description = "Datasets and their exact desired properties.";
    };
    readinessResources = lib.mkOption {
      type = lib.abilities.types.list {
        element = lib.abilities.types.deferredResult lib.abilities.types.resourceReference;
        maxItems = 1025;
      };
      default = [];
      readOnly = true;
      internal = true;
      description = "Derived readiness outputs for the configured pool and datasets.";
    };
  };

  config = {
    aos.filesystems.zfs.readinessResources = lib.mkIf cfg.enable readinessResources;
    aos.abilities = lib.mkMerge ([
        {
          interfaces.${poolTerminal.alias} = poolTerminal.declaration;
          interfaces.${datasetTerminal.alias} = datasetTerminal.declaration;
          implementations.storage-pool = controller storage.pool poolTerminal "share/aos/providers/storage-pool.nix" "Converges storage pools through the OpenZFS controller.";
          implementations.storage-dataset = controller storage.dataset datasetTerminal "share/aos/providers/storage-dataset.nix" "Converges storage datasets through the OpenZFS controller.";
          implementations.${poolTerminal.alias} = poolTerminal.implementation;
          implementations.${datasetTerminal.alias} = datasetTerminal.implementation;
        }
      ]
      ++ builtins.map (contribution: contribution.declarations) contributions
      ++ lib.optional cfg.enable (lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (contribution: contribution.configured) contributions
      )));
  };
}
