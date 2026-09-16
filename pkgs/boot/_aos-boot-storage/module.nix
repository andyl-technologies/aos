##! Package-owned EFI System Partition and initrd ZFS services.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.boot.storageServices;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "boot-storage";
  transactionStorageAlias = "boot-transaction-storage-view";
  transactionStorageEffectsAlias = "boot-transaction-storage-view-effects";
  transactionStorageInterfaceName = "aos.boot.transaction-storage-view";
  transactionStorageRoot = "/run/aos-boot-transaction-storage";
  transactionStoragePath = "${transactionStorageRoot}/aos/initrd-stage-journal";
  stage =
    if config.aos.abilities.environment == null
    then null
    else config.aos.abilities.environment.stage;

  protectedOutput = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  transactionStorageRequest = lib.abilities.types.record {
    fields = {
      name = lib.abilities.types.localKey;
      purpose = lib.abilities.types.enum ["initrd-stage-journal"];
    };
  };
  transactionStorageObservation = lib.abilities.types.record {
    fields = {
      schema = lib.abilities.types.enum ["aos.boot.transaction-storage-observation/v1"];
      expected = transactionStorageRequest;
      realized = {
        type = lib.abilities.types.optional lib.abilities.types.executionPath;
        optional = true;
      };
      state = lib.abilities.types.enum ["absent" "ready" "unknown"];
    };
  };
  transactionStorageMethod = {
    description = "Materializes the selected ESP-backed initrd stage journal.";
    semantics = {
      requiredTargetAccess = "exclusive-write";
      stopsProvider = false;
    };
    parameters = transactionStorageRequest;
    targetResource = transactionStorageInterfaceName;
    permittedOperations = ["materialize"];
    guarantees = [];
    outputs = {
      observation = protectedOutput "runtime" "attempt" "Reports the exact ESP transaction view state." transactionStorageObservation;
      retained-resource = protectedOutput "runtime" "transaction" "References the exact retained ESP transaction view." lib.abilities.types.resourceReference;
      storage-path = protectedOutput "runtime" "transaction" "Returns the exact materialized journal path." lib.abilities.types.executionPath;
    };
    outcome = {
      completionEvidence = transactionStorageObservation;
      observationEvidence = transactionStorageObservation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  transactionStorageDeclaration = lib.abilities.declareInterface {
    name = transactionStorageInterfaceName;
    description = "Materializes an ESP-backed transaction journal before mutable storage is available.";
    abi = 1;
    requestType = transactionStorageRequest;
    methods.materialize = transactionStorageMethod;
    outputs = {
      storage-path = protectedOutput "planning" "transaction" "Returns the selected ESP journal path." lib.abilities.types.executionPath;
      storage-resource = protectedOutput "planning" "transaction" "References the exact ESP journal resource." lib.abilities.types.resourceReference;
    };
    lifecycle.persistentDeleteMethod = null;
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = transactionStorageAlias;
    };
    guarantees = [];
  };
  transactionStorageIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration transactionStorageDeclaration
  );
  transactionStorageEffectsDeclaration =
    transactionStorageDeclaration
    // {
      name = "aos.boot.transaction-storage-view-effects";
      outputs = {};
      aggregation =
        transactionStorageDeclaration.aggregation
        // {
          controllerGroup = transactionStorageEffectsAlias;
        };
    };
  transactionStorageEffectsIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration transactionStorageEffectsDeclaration
  );
  transactionStorageRealization = lib.abilities.types.record {
    fields = {
      schema = lib.abilities.types.enum ["aos.boot.transaction-storage-realization/v1"];
      path = lib.abilities.types.executionPath;
    };
  };

  bootCommit = {
    _type = "aos-request-output-reference";
    request = "aos:image-boot-commit-lifecycle";
    output = "service-resource";
  };

  command = entryPoint: arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/${entryPoint}";
      inherit arguments;
    };
    ignore_failure = false;
  };
  earlySystem = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "early-system";
    interface = interfaces.activationMilestone;
    parameters.milestone = "early-system";
  };
  earlySystemReadiness = resultOf "early-system" "readiness-resource";
  systemMilestone = key: milestone:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = interfaces.systemMilestoneReadiness;
      parameters = {inherit milestone;};
    };
  localFilesystems = systemMilestone "local-filesystems" "local-filesystems";
  multiUser = systemMilestone "multi-user" "multi-user";
  sysroot = systemMilestone "sysroot" "sysroot";
  deviceSettle = systemMilestone "device-settle" "device-settle";
  kernelModules = systemMilestone "kernel-modules" "kernel-modules";
  localFilesystemsReadiness = resultOf "local-filesystems" "readiness-resource";
  multiUserReadiness = resultOf "multi-user" "readiness-resource";
  sysrootReadiness = resultOf "sysroot" "readiness-resource";
  deviceSettleReadiness = resultOf "device-settle" "readiness-resource";
  kernelModulesReadiness = resultOf "kernel-modules" "readiness-resource";
  service = {
    key,
    description,
    entryPoint,
    arguments ? [],
    dependencies,
    conditions ? null,
    environment ? null,
    logging ? null,
  }:
    serviceManagement.forService {
      inherit serviceTypes consumerInstance;
      declaration =
        {
          service = key;
          enabled = true;
          lifecycle = {
            inherit description;
            execution_model = "oneshot";
            environment_files = [];
            condition = [];
            pre_start = [];
            start = [(command entryPoint arguments)];
            post_start = [];
            stop = [];
            post_stop = [];
            restart = "never";
            restart_delay_millis = 0;
            configuration_change_action = "restart";
            remain_after_exit = true;
            start_timeout_millis = 90000;
            stop_timeout_millis = 90000;
          };
          inherit dependencies;
          readiness = {
            mechanism = "successful-exit";
            signal_scope = "none";
            timeout_millis = 90000;
          };
        }
        // lib.optionalAttrs (conditions != null) {inherit conditions;}
        // lib.optionalAttrs (environment != null) {inherit environment;}
        // lib.optionalAttrs (logging != null) {inherit logging;};
    };

  mountEsp = service {
    key = "aos-mount-esp";
    description = "Mount an available booted EFI System Partition";
    entryPoint = "aos-mount-esp";
    dependencies = {
      prerequisites = [];
      after = [];
      before = [localFilesystemsReadiness bootCommit];
      requires = [];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [];
      wanted_by = [localFilesystemsReadiness];
      required_mounts = [];
      implicit_dependencies = false;
    };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = "/sys/firmware/efi";
        negated = false;
      }
    ];
  };
  syncEsps = service {
    key = "aos-sync-esps";
    description = "Replicate the primary EFI System Partition";
    entryPoint = "aos-sync-esps";
    dependencies = {
      prerequisites = [];
      after = [bootCommit];
      before = [];
      requires = [bootCommit];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [];
      wanted_by = [multiUserReadiness];
      required_mounts = [];
      implicit_dependencies = true;
    };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = "/sys/firmware/efi";
        negated = false;
      }
    ];
  };
  unlockArguments =
    [
      cfg.zfs.poolName
      cfg.zfs.encryptionRoot
      cfg.zfs.sealedKeyPath
      (toString (builtins.length cfg.espDevices))
    ]
    ++ cfg.espDevices ++ cfg.zfs.expectedDevices;
  zfsUnlock = service {
    key = "aos-zfs-unlock";
    description = "Import and unlock immutable ZFS boot storage";
    entryPoint = "aos-zfs-unlock";
    arguments = unlockArguments;
    dependencies = {
      prerequisites = [];
      after = [deviceSettleReadiness kernelModulesReadiness];
      before = [sysrootReadiness earlySystemReadiness];
      requires = [deviceSettleReadiness kernelModulesReadiness];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [earlySystemReadiness];
      wanted_by = [];
      required_mounts = [];
      implicit_dependencies = false;
    };
    environment = {
      variables = {};
      search_path = builtins.map lib.abilities.packageOutput [
        {package = "coreutils";}
        {package = "systemd";}
        {package = "util-linux";}
        {package = "zfs";}
      ];
    };
    logging = {
      standard_output = "structured-and-console";
      standard_error = "structured-and-console";
      namespace = null;
      directories = [];
      directory_mode = "0755";
    };
  };
  transactionStorageMount = service {
    key = "aos-boot-transaction-storage";
    description = "Materialize the ESP-backed initrd transaction journal";
    entryPoint = "aos-mount-transaction-storage";
    arguments = [transactionStorageRoot] ++ cfg.espDevices;
    dependencies = {
      prerequisites = [];
      after = [deviceSettleReadiness];
      before = [sysrootReadiness];
      requires = [deviceSettleReadiness];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [sysrootReadiness];
      wanted_by = [];
      required_mounts = [];
      implicit_dependencies = false;
    };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = "/sys/firmware/efi";
        negated = false;
      }
    ];
  };
  fragments = [
    earlySystem
    localFilesystems
    multiUser
    sysroot
    deviceSettle
    kernelModules
    mountEsp
    syncEsps
    zfsUnlock
    transactionStorageMount
  ];
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.boot.storageServices = {
    espDevices = lib.mkOption {
      type = lib.abilities.types.list {
        element = lib.abilities.types.executionPath;
        maxItems = 64;
      };
      default = ["/dev/disk/by-partlabel/ESP"];
      internal = true;
      description = "Stable EFI System Partition device paths available during early boot.";
    };

    zfs = {
      enable = lib.mkOption {
        type = lib.abilities.types.boolean;
        default = false;
        internal = true;
        description = "Whether initrd boot storage requires native ZFS pool import and key loading.";
      };

      poolName = lib.mkOption {
        type = lib.abilities.types.string {
          maxLength = 255;
          syntax = null;
        };
        default = "rpool";
        internal = true;
        description = "Pool containing immutable image zvols.";
      };

      encryptionRoot = lib.mkOption {
        type = lib.abilities.types.string {
          maxLength = 4096;
          syntax = null;
        };
        default = "rpool";
        internal = true;
        description = "Native-encryption root unlocked before zvol discovery.";
      };

      sealedKeyPath = lib.mkOption {
        type = lib.abilities.types.relativePath;
        default = "aos/zfs-key.cred";
        internal = true;
        description = "ESP-relative TPM-sealed native ZFS key path.";
      };

      expectedDevices = lib.mkOption {
        type = lib.abilities.types.list {
          element = lib.abilities.types.executionPath;
          maxItems = 64;
        };
        default = [];
        internal = true;
        description = "Zvol device paths that must appear after the encryption root is unlocked.";
      };
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge [
        (lib.mkMerge (builtins.map (contribution: contribution.declarations) contributions))
        {
          interfaces = {
            ${transactionStorageAlias} = transactionStorageDeclaration;
            ${transactionStorageEffectsAlias} = transactionStorageEffectsDeclaration;
          };
          implementations = {
            ${transactionStorageAlias} = {
              description = "Selects the exact ESP-backed initrd transaction journal.";
              interface = transactionStorageIdentity;
              artifact = lib.abilities.packageOutput {};
              methods = ["materialize"];
              guarantees = [];
              requirements.effects = {
                alias = "effects";
                description = "Invokes the checked ESP transaction-view terminal.";
                accepted_interfaces = [transactionStorageEffectsIdentity];
                methods = ["materialize"];
                guarantees = [];
                strength = "required";
                fallback = null;
              };
              providerModule = {
                artifact = lib.abilities.packageOutput {};
                path = "share/aos/providers/boot-transaction-storage.nix";
              };
              desiredType = transactionStorageRealization;
              requiredFeatures = [];
            };
            ${transactionStorageEffectsAlias} = {
              description = "Authenticates the package-materialized ESP transaction journal.";
              interface = transactionStorageEffectsIdentity;
              artifact = lib.abilities.packageOutput {};
              methods = ["materialize"];
              guarantees = [];
              handlerDescriptor = {
                artifact = lib.abilities.packageOutput {};
                entryPoint = "bin/aos-boot-transaction-storage-provider";
                arguments = transactionStorageRequest;
                result = transactionStorageObservation;
              };
              providerModule = null;
              desiredType = null;
              requiredFeatures = [];
            };
          };
          requirementTemplates.${transactionStorageAlias} = {
            description = "Requires the selected ESP-backed initrd transaction journal.";
            inherit (transactionStorageIdentity) abi descriptor;
            interface = transactionStorageIdentity.name;
            methods = ["materialize"];
            guarantees = [];
            strength = "required";
            fallback = null;
          };
        }
      ];
    }
    (lib.mkIf (stage == "host") {
      aos.abilities = lib.mkMerge [
        {instances.${consumerInstance} = {};}
        (serviceManagement.splitContribution localFilesystems).configured
        (serviceManagement.splitContribution multiUser).configured
        (serviceManagement.splitContribution mountEsp).configured
        (serviceManagement.splitContribution syncEsps).configured
      ];
    })
    (lib.mkIf (stage == "initrd" && cfg.zfs.enable) {
      aos.abilities = lib.mkMerge [
        {instances.${consumerInstance} = {};}
        (serviceManagement.splitContribution earlySystem).configured
        (serviceManagement.splitContribution sysroot).configured
        (serviceManagement.splitContribution deviceSettle).configured
        (serviceManagement.splitContribution kernelModules).configured
        (serviceManagement.splitContribution zfsUnlock).configured
      ];
    })
    (lib.mkIf (stage == "initrd") {
      aos.abilities = lib.mkMerge [
        {instances.${consumerInstance} = {};}
        {
          requests.${transactionStorageAlias} = {
            requirement = transactionStorageAlias;
            consumer = consumerInstance;
            scope = ["initrd-stage-journal"];
            parameters = {
              name = "initrd-stage-journal";
              purpose = "initrd-stage-journal";
            };
          };
        }
        (serviceManagement.splitContribution deviceSettle).configured
        (serviceManagement.splitContribution sysroot).configured
        (serviceManagement.splitContribution transactionStorageMount).configured
      ];
    })
  ];
}
