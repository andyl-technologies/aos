##! Package-owned initrd credential recovery and configuration seeding.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.boot.substrateServices;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "boot-preparations";
  initrdStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "initrd";

  packageArtifact = lib.abilities.packageOutput {};
  artifact = package: lib.abilities.packageOutput {inherit package;};

  command = operation: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/aos-boot-preparations";
      arguments = [operation];
    };
    ignore_failure = false;
  };
  substrateCommand = entryPoint: {
    executable = {
      artifact = packageArtifact;
      entry_point = "bin/${entryPoint}";
      arguments = [];
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
  switchRoot = systemMilestone "switch-root" "switch-root";
  sysroot = systemMilestone "sysroot" "sysroot";
  var = systemMilestone "var" "var";
  nixOverlay = systemMilestone "nix-overlay" "nix-overlay";
  etcOverlay = systemMilestone "etc-overlay" "etc-overlay";
  runEtc = systemMilestone "run-etc" "run-etc";
  initrdFilesystems = systemMilestone "initrd-filesystems" "initrd-filesystems";
  initrdRootFilesystems = systemMilestone "initrd-root-filesystems" "initrd-root-filesystems";
  deviceSettle = systemMilestone "device-settle" "device-settle";
  initrdStageExecution = systemMilestone "initrd-stage" "initrd-stage-executed";
  bootIdentity = systemMilestone "boot-identity" "boot-identity-validated";
  bootStorageUnlocked = systemMilestone "boot-storage-unlocked" "boot-storage-unlocked";
  switchRootReadiness = resultOf "switch-root" "readiness-resource";
  sysrootReadiness = resultOf "sysroot" "readiness-resource";
  varReadiness = resultOf "var" "readiness-resource";
  nixOverlayReadiness = resultOf "nix-overlay" "readiness-resource";
  etcOverlayReadiness = resultOf "etc-overlay" "readiness-resource";
  runEtcReadiness = resultOf "run-etc" "readiness-resource";
  initrdFilesystemsReadiness = resultOf "initrd-filesystems" "readiness-resource";
  initrdRootFilesystemsReadiness = resultOf "initrd-root-filesystems" "readiness-resource";
  deviceSettleReadiness = resultOf "device-settle" "readiness-resource";
  initrdStageReadiness = resultOf "initrd-stage" "readiness-resource";
  bootIdentityReadiness = resultOf "boot-identity" "readiness-resource";
  bootStorageUnlockedReadiness = resultOf "boot-storage-unlocked" "readiness-resource";
  service = {
    key,
    description,
    operation,
    dependencies,
  }:
    serviceManagement.forService {
      inherit serviceTypes consumerInstance;
      declaration = {
        service = key;
        enabled = true;
        lifecycle = {
          inherit description;
          execution_model = "oneshot";
          environment_files = [];
          condition = [];
          pre_start = [];
          start = [(command operation)];
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
      };
    };

  credentialRecovery = service {
    key = "aos-credential-recovery";
    description = "Recover interrupted AOS credential publication";
    operation = "recover-credentials";
    dependencies = {
      prerequisites = [];
      after = [sysrootReadiness varReadiness nixOverlayReadiness];
      before = [
        (resultOf "aos-config-seed-lifecycle" "service-resource")
        etcOverlayReadiness
        earlySystemReadiness
        switchRootReadiness
      ];
      requires = [sysrootReadiness varReadiness nixOverlayReadiness];
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
  };
  configurationSeed = service {
    key = "aos-config-seed";
    description = "Seed the per-generation /etc lower for on-host configuration";
    operation = "seed-configuration";
    dependencies = {
      prerequisites = [];
      after = [
        varReadiness
        (resultOf "aos-credential-recovery-lifecycle" "service-resource")
        runEtcReadiness
      ];
      before = [etcOverlayReadiness earlySystemReadiness switchRootReadiness];
      requires = [
        varReadiness
        (resultOf "aos-credential-recovery-lifecycle" "service-resource")
        runEtcReadiness
      ];
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
  };
  baseFragments = [
    earlySystem
    switchRoot
    sysroot
    var
    nixOverlay
    etcOverlay
    runEtc
    credentialRecovery
    configurationSeed
  ];
  baseContributions = builtins.map serviceManagement.splitContribution baseFragments;

  emptyDependencies = {
    prerequisites = [];
    after = [];
    before = [];
    requires = [];
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
  serviceResource = key: resultOf "${key}-lifecycle" "service-resource";
  substrateEnvironment = {
    variables = {
      AOS_DB_CERT = cfg.dbCertificate;
      AOS_ESP_DEVICE = cfg.espDevice;
      AOS_RECOVERY_ABI = builtins.toString cfg.recoveryAbi;
      AOS_RECOVERY_ENABLED =
        if cfg.recoveryEnabled
        then "true"
        else "false";
      AOS_ZFS_POOL = cfg.zfsPool;
      AOS_ZFS_STATE =
        if cfg.zfsEnabled
        then "true"
        else "false";
    };
    search_path = builtins.map lib.abilities.packageOutput (
      [
        {package = "coreutils";}
        {package = "jq";}
        {package = "sbsigntools";}
        {package = "tpm2-tools";}
        {package = "util-linux";}
        {
          package = "aos";
          output = "packageRuntime";
        }
      ]
      ++ lib.optional cfg.zfsEnabled {package = "zfs";}
    );
  };
  substrateLogging = {
    standard_output = "structured-and-console";
    standard_error = "structured-and-console";
    namespace = null;
    directories = [];
    directory_mode = "0755";
  };
  substrateService = {
    key,
    description,
    dependencies,
    conditions ? null,
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
            start = [(substrateCommand key)];
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
          environment = substrateEnvironment;
        }
        // lib.optionalAttrs (conditions != null) {inherit conditions;}
        // lib.optionalAttrs (logging != null) {inherit logging;};
    };

  mountVarPrerequisite =
    if cfg.zfsEnabled
    then bootStorageUnlockedReadiness
    else initrdStageReadiness;
  mountVar = substrateService {
    key = "mount-var";
    description = "Mount /var Partition";
    dependencies =
      emptyDependencies
      // {
        after =
          [sysrootReadiness mountVarPrerequisite deviceSettleReadiness]
          ++ lib.optional cfg.verityEnabled bootIdentityReadiness;
        before = [
          (serviceResource "aos-config-seed")
          (serviceResource "etc-overlay-setup")
          initrdFilesystemsReadiness
        ];
        requires =
          [sysrootReadiness mountVarPrerequisite]
          ++ lib.optional cfg.verityEnabled bootIdentityReadiness;
        required_by = [initrdFilesystemsReadiness];
      };
    conditions =
      if cfg.zfsEnabled
      then null
      else {
        all = [
          {
            kind = "path";
            predicate = "exists";
            path = "/dev/disk/by-partlabel/var";
            negated = false;
          }
        ];
      };
    logging = substrateLogging;
  };
  nixOverlaySetup = substrateService {
    key = "nix-overlay-setup";
    description = "Set Up /nix Overlay Filesystem";
    dependencies =
      emptyDependencies
      // {
        after = [sysrootReadiness (serviceResource "mount-var") initrdRootFilesystemsReadiness];
        before = [initrdFilesystemsReadiness switchRootReadiness];
        requires = [sysrootReadiness (serviceResource "mount-var")];
        required_by = [initrdFilesystemsReadiness];
      };
  };
  seedProfiles = substrateService {
    key = "aos-seed-profiles";
    description = "Seed apm system-profile state on first boot";
    dependencies =
      emptyDependencies
      // {
        after = [sysrootReadiness (serviceResource "mount-var") (serviceResource "nix-overlay-setup")];
        before = [
          (serviceResource "aos-config-seed")
          (serviceResource "run-etc-setup")
          (serviceResource "aos-machine-id")
          initrdFilesystemsReadiness
        ];
        requires = [sysrootReadiness (serviceResource "mount-var") (serviceResource "nix-overlay-setup")];
        required_by = [initrdFilesystemsReadiness];
      };
  };
  runEtcSetup = substrateService {
    key = "run-etc-setup";
    description = "Mount /run/etc tmpfs";
    dependencies =
      emptyDependencies
      // {
        before = [
          (serviceResource "aos-config-seed")
          (serviceResource "etc-overlay-setup")
          initrdFilesystemsReadiness
        ];
        required_by = [initrdFilesystemsReadiness];
      };
    conditions.all = [
      {
        kind = "path";
        predicate = "is-mount-point";
        path = "/run/etc";
        negated = true;
      }
    ];
  };
  machineId = substrateService {
    key = "aos-machine-id";
    description = "Seed /var/etc/machine-id on first boot";
    dependencies =
      emptyDependencies
      // {
        after = [sysrootReadiness (serviceResource "mount-var")];
        before = [(serviceResource "etc-overlay-setup") initrdFilesystemsReadiness];
        requires = [sysrootReadiness (serviceResource "mount-var")];
        required_by = [initrdFilesystemsReadiness];
      };
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = "/sysroot/var/etc/machine-id";
        negated = true;
      }
    ];
  };
  etcOverlaySetup = substrateService {
    key = "etc-overlay-setup";
    description = "Set Up /etc Overlay Filesystem";
    dependencies =
      emptyDependencies
      // {
        after = [
          sysrootReadiness
          (serviceResource "mount-var")
          (serviceResource "aos-config-seed")
          (serviceResource "aos-seed-profiles")
          (serviceResource "run-etc-setup")
          (serviceResource "nix-overlay-setup")
          (serviceResource "aos-machine-id")
          initrdRootFilesystemsReadiness
        ];
        before = [initrdFilesystemsReadiness switchRootReadiness];
        requires = [
          sysrootReadiness
          (serviceResource "mount-var")
          (serviceResource "aos-config-seed")
          (serviceResource "aos-seed-profiles")
          (serviceResource "run-etc-setup")
          (serviceResource "nix-overlay-setup")
          (serviceResource "aos-machine-id")
        ];
        required_by = [initrdFilesystemsReadiness];
      };
  };
  systemdPackagedUnitAlias = "systemd-packaged-unit";
  networkWaitOnline = {
    requirementTemplates.${systemdPackagedUnitAlias} =
      lib.abilities.interfaceSelector {
        name = "aos.systemd.packaged-unit";
        abi = 1;
      }
      // {
        description = "Retains the initrd wait-online service with any-link readiness semantics.";
        methods = ["observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
    requests."network-wait-online-unit" = {
      requirement = systemdPackagedUnitAlias;
      consumer = consumerInstance;
      scope = ["network-wait-online-unit"];
      parameters = {
        source = {
          artifact = packageArtifact;
          unit_file = "lib/systemd/system/systemd-networkd-wait-online.service";
        };
        activation = "reference";
        prerequisites = [];
        dependencies = {
          after = [];
          before = [];
          requires = [];
          wants = [];
        };
        drop_in = {
          accepted_exit_statuses = [];
          reload_triggers = [];
          search_path = [];
        };
      };
    };
  };
  substrateFragments = [
    initrdFilesystems
    initrdRootFilesystems
    deviceSettle
    initrdStageExecution
    bootIdentity
    bootStorageUnlocked
    mountVar
    nixOverlaySetup
    seedProfiles
    runEtcSetup
    machineId
    etcOverlaySetup
    networkWaitOnline
  ];
  substrateContributions = builtins.map serviceManagement.splitContribution substrateFragments;
in {
  options.aos.boot.substrateServices = {
    enable = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      internal = true;
      description = "Whether the package-owned initrd substrate services are active.";
    };
    verityEnabled = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      internal = true;
      description = "Whether mounting persistent state requires validated boot identity.";
    };
    zfsEnabled = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      internal = true;
      description = "Whether persistent state is backed by the unlocked ZFS boot pool.";
    };
    zfsPool = lib.mkOption {
      type = lib.abilities.types.string {
        maxLength = 255;
        syntax = null;
      };
      default = "rpool";
      internal = true;
      description = "ZFS pool containing persistent state datasets.";
    };
    recoveryEnabled = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      internal = true;
      description = "Whether image profile seeding verifies a paired recovery image.";
    };
    recoveryAbi = lib.mkOption {
      type = lib.abilities.types.integer {
        minimum = 0;
        maximum = 4294967295;
      };
      default = 0;
      internal = true;
      description = "Recovery image ABI accepted by profile seeding.";
    };
    espDevice = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/dev/disk/by-partlabel/ESP";
      internal = true;
      description = "EFI System Partition read while verifying recovery state.";
    };
    dbCertificate = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/nonexistent/aos-secure-boot-db.pem";
      internal = true;
      description = "Secure Boot database certificate used to verify the recovery image.";
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        builtins.map (contribution: contribution.declarations) (baseContributions ++ substrateContributions)
      );
    }
    (lib.mkIf initrdStage {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (contribution: contribution.configured) baseContributions
      );
    })
    (lib.mkIf (initrdStage && cfg.enable) {
      aos.abilities = lib.mkMerge (
        builtins.map (contribution: contribution.configured) substrateContributions
      );
    })
  ];
}
