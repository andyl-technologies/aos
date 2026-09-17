##! Package-owned EFI System Partition and initrd ZFS services.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.boot.storageServices;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  milestones = serviceManagement.milestones;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "boot-storage";
  transactionStorage = lib.abilities.interfaces.bootTransactionStorage.interfaces.view;
  transactionStorageAlias = transactionStorage.alias;
  transactionStorageRoot = "/run/aos-boot-transaction-storage";
  stagedZfsCredential = "/run/aos/boot-credentials/zfs-key.cred";
  stage =
    if config.aos.abilities.environment == null
    then null
    else config.aos.abilities.environment.stage;

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
  earlySystemReadiness = resultOf "early-system" "resource";
  systemMilestone = key: milestone:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = interfaces.systemMilestoneReadiness;
      parameters = {inherit milestone;};
    };
  localFilesystems = systemMilestone "local-filesystems" milestones.localFilesystems;
  multiUser = systemMilestone "multi-user" milestones.multiUser;
  sysroot = systemMilestone "sysroot" milestones.sysroot;
  deviceSettle = systemMilestone "device-settle" milestones.deviceSettle;
  kernelModules = systemMilestone "kernel-modules" milestones.kernelModules;
  bootIdentity = systemMilestone "boot-identity" milestones.bootIdentityValidated;
  initrdStage = systemMilestone "initrd-stage" milestones.initrdStageExecuted;
  espReady = systemMilestone "esp-ready" milestones.espReady;
  imageBootCommitted = systemMilestone "image-boot-committed" milestones.imageBootCommitted;
  localFilesystemsReadiness = resultOf "local-filesystems" "resource";
  multiUserReadiness = resultOf "multi-user" "resource";
  sysrootReadiness = resultOf "sysroot" "resource";
  deviceSettleReadiness = resultOf "device-settle" "resource";
  kernelModulesReadiness = resultOf "kernel-modules" "resource";
  bootIdentityReadiness = resultOf "boot-identity" "resource";
  initrdStageReadiness = resultOf "initrd-stage" "resource";
  espReadyReadiness = resultOf "esp-ready" "resource";
  imageBootCommittedReadiness = resultOf "image-boot-committed" "resource";
  service = {
    key,
    description,
    entryPoint,
    arguments ? [],
    dependencies,
    conditions ? null,
    credentials ? null,
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
        // lib.optionalAttrs (credentials != null) {inherit credentials;}
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
      before = [localFilesystemsReadiness espReadyReadiness];
      requires = [];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [espReadyReadiness];
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
      after = [imageBootCommittedReadiness];
      before = [];
      requires = [imageBootCommittedReadiness];
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
  stageZfsCredential = service {
    key = "aos-stage-zfs-credential";
    description = "Materialize the sealed native ZFS credential from an available ESP";
    entryPoint = "aos-stage-zfs-credential";
    arguments = [cfg.zfs.sealedKeyPath stagedZfsCredential] ++ cfg.espDevices;
    dependencies = {
      prerequisites = [];
      after = [deviceSettleReadiness];
      before = [];
      requires = [deviceSettleReadiness];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [];
      wanted_by = [];
      required_mounts = [];
      implicit_dependencies = false;
    };
    environment = {
      variables = {};
      search_path = builtins.map lib.abilities.packageOutput [
        {package = "coreutils";}
        {package = "util-linux";}
      ];
    };
  };
  stagedZfsCredentialReadiness = resultOf "aos-stage-zfs-credential-lifecycle" "resource";
  unlockArguments = [cfg.zfs.poolName cfg.zfs.encryptionRoot] ++ cfg.zfs.expectedDevices;
  zfsUnlock = service {
    key = "aos-zfs-unlock";
    description = "Import and unlock immutable ZFS boot storage";
    entryPoint = "aos-zfs-unlock";
    arguments = unlockArguments;
    dependencies = {
      prerequisites = [];
      after = [deviceSettleReadiness kernelModulesReadiness stagedZfsCredentialReadiness];
      before = [sysrootReadiness earlySystemReadiness];
      requires = [deviceSettleReadiness kernelModulesReadiness stagedZfsCredentialReadiness];
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
    credentials.views = [
      {
        name = "aos-zfs-key";
        reference = stagedZfsCredential;
        encrypted = true;
        optional = false;
        environment_variable = "AOS_ZFS_KEY";
      }
    ];
    environment = {
      variables = {};
      search_path = builtins.map lib.abilities.packageOutput [
        {package = "coreutils";}
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
      after = [deviceSettleReadiness sysrootReadiness bootIdentityReadiness];
      before = [initrdStageReadiness];
      requires = [deviceSettleReadiness sysrootReadiness bootIdentityReadiness];
      wants = [];
      requisite = [];
      conflicts = [];
      binds_to = [];
      part_of = [];
      upholds = [];
      required_by = [initrdStageReadiness];
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
    bootIdentity
    initrdStage
    espReady
    imageBootCommitted
    mountEsp
    syncEsps
    zfsUnlock
    stageZfsCredential
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
          requirementTemplates.${transactionStorageAlias} = {
            description = "Requires the selected ESP-backed initrd transaction journal.";
            abi = transactionStorage.identity.abi;
            descriptor = null;
            interface = transactionStorage.identity.name;
            inherit (transactionStorage) methods;
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
        (serviceManagement.splitContribution stageZfsCredential).configured
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
        (serviceManagement.splitContribution bootIdentity).configured
        (serviceManagement.splitContribution deviceSettle).configured
        (serviceManagement.splitContribution initrdStage).configured
        (serviceManagement.splitContribution sysroot).configured
        (serviceManagement.splitContribution transactionStorageMount).configured
      ];
    })
  ];
}
