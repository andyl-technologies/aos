##! Package-owned initrd configuration seeding.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.boot.substrateServices;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  milestones = serviceManagement.milestones;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "boot-preparations";
  stage =
    if config.aos.abilities.environment == null
    then null
    else config.aos.abilities.environment.stage;
  initrdStage = stage == "initrd";
  hostStage = stage == "host";

  packageArtifact = lib.abilities.packageOutput {};
  artifact = package: lib.abilities.packageOutput {inherit package;};
  runtimeArtifact = lib.abilities.packageOutput {
    package = "aos";
    output = "packageRuntime";
  };

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
  earlySystemReadiness = resultOf "early-system" "resource";
  systemMilestone = key: milestone:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = interfaces.systemMilestoneReadiness;
      parameters = {inherit milestone;};
    };
  switchRoot = systemMilestone "switch-root" milestones.switchRoot;
  sysroot = systemMilestone "sysroot" milestones.sysroot;
  var = systemMilestone "var" milestones.var;
  nixOverlay = systemMilestone "nix-overlay" milestones.nixOverlay;
  etcOverlay = systemMilestone "etc-overlay" milestones.etcOverlay;
  runEtc = systemMilestone "run-etc" milestones.runEtc;
  initrdFilesystems = systemMilestone "initrd-filesystems" milestones.initrdFilesystems;
  initrdRootFilesystems = systemMilestone "initrd-root-filesystems" milestones.initrdRootFilesystems;
  deviceSettle = systemMilestone "device-settle" milestones.deviceSettle;
  initrdStageExecution = systemMilestone "initrd-stage" milestones.initrdStageExecuted;
  bootIdentity = systemMilestone "boot-identity" milestones.bootIdentityValidated;
  bootStorageUnlocked = systemMilestone "boot-storage-unlocked" milestones.bootStorageUnlocked;
  localFilesystems = systemMilestone "local-filesystems" milestones.localFilesystems;
  hostStageReceived = systemMilestone "host-stage-received" milestones.hostStageReceived;
  switchRootReadiness = resultOf "switch-root" "resource";
  sysrootReadiness = resultOf "sysroot" "resource";
  varReadiness = resultOf "var" "resource";
  nixOverlayReadiness = resultOf "nix-overlay" "resource";
  etcOverlayReadiness = resultOf "etc-overlay" "resource";
  runEtcReadiness = resultOf "run-etc" "resource";
  initrdFilesystemsReadiness = resultOf "initrd-filesystems" "resource";
  initrdRootFilesystemsReadiness = resultOf "initrd-root-filesystems" "resource";
  deviceSettleReadiness = resultOf "device-settle" "resource";
  initrdStageReadiness = resultOf "initrd-stage" "resource";
  bootIdentityReadiness = resultOf "boot-identity" "resource";
  bootStorageUnlockedReadiness = resultOf "boot-storage-unlocked" "resource";
  localFilesystemsReadiness = resultOf "local-filesystems" "resource";
  hostStageReceivedReadiness = resultOf "host-stage-received" "resource";
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

  configurationSeed = service {
    key = "aos-config-seed";
    description = "Seed the per-generation /etc lower for on-host configuration";
    operation = "seed-configuration";
    dependencies = {
      prerequisites = [];
      after = [
        varReadiness
        runEtcReadiness
      ];
      before = [etcOverlayReadiness earlySystemReadiness switchRootReadiness];
      requires = [
        varReadiness
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
    configurationSeed
  ];
  baseContributions = builtins.map serviceManagement.splitDefinition baseFragments;
  networkConfiguration = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "bootstrap-network";
    interface = lib.abilities.interfaces.networkConfiguration.interface;
    methods = ["apply" "observe" "remove"];
    parameters = {
      authority = "image";
      links = [
        {
          kind = "ethernet";
          name = "dhcp";
          selector.kind = "ethernet";
          addressing = {
            dhcp = true;
            addresses = [];
            dns = [];
            link_local = "ipv4";
            ipv4_link_local_route = true;
          };
        }
      ];
      resolver = {
        enabled = false;
        nameservers = [];
        search = [];
        dnssec = "no";
      };
      prerequisites = [];
    };
  };
  networkContribution = serviceManagement.splitDefinition networkConfiguration;

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
  serviceResource = key: resultOf "${key}-lifecycle" "resource";
  handoffCommand = arguments: {
    executable = {
      artifact = runtimeArtifact;
      entry_point = "bin/.aos-package-runtime-unwrapped";
      inherit arguments;
    };
    ignore_failure = false;
  };
  handoffService = {
    key,
    description,
    arguments,
    dependencies,
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
            start = [(handoffCommand arguments)];
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
        // lib.optionalAttrs (logging != null) {inherit logging;};
    };

  initrdController = handoffService {
    key = "aos-ability-initrd-controller";
    description = "Execute and release initrd-stage ability ownership";
    arguments = [
      "__ability-stage-run"
      "--stage"
      "initrd"
      "--root"
      "/sysroot"
      "--resolved-stage"
      "/lib/aos/initrd/resolved-ability-stage.json"
    ];
    dependencies =
      emptyDependencies
      // {
        after = [
          sysrootReadiness
          initrdStageReadiness
        ];
        before = [
          (serviceResource "mount-var")
          initrdFilesystemsReadiness
          switchRootReadiness
        ];
        requires = [
          sysrootReadiness
          initrdStageReadiness
        ];
        required_by = [initrdFilesystemsReadiness];
        implicit_dependencies = false;
      };
  };
  initrdHandoffBarrier = handoffService {
    key = "aos-ability-initrd-handoff-barrier";
    description = "Authenticate released initrd ability ownership";
    arguments = [
      "__ability-stage-validate"
      "--from-stage"
      "initrd"
      "--root"
      "/sysroot"
    ];
    dependencies =
      emptyDependencies
      // {
        after = [(serviceResource "aos-ability-initrd-controller")];
        before = [
          (serviceResource "mount-var")
          initrdFilesystemsReadiness
          switchRootReadiness
        ];
        requires = [(serviceResource "aos-ability-initrd-controller")];
        required_by = [
          (serviceResource "mount-var")
          initrdFilesystemsReadiness
        ];
        implicit_dependencies = false;
      };
    logging = substrateLogging;
  };
  hostReceiver = handoffService {
    key = "aos-ability-host-receiver";
    description = "Revalidate and receive initrd ability ownership";
    arguments = [
      "__ability-stage-receive"
      "--from-stage"
      "initrd"
      "--image-profile"
      "/var/lib/profiles/image"
    ];
    dependencies =
      emptyDependencies
      // {
        after = [localFilesystemsReadiness];
        before = [hostStageReceivedReadiness];
        requires = [localFilesystemsReadiness];
        required_by = [hostStageReceivedReadiness];
      };
  };
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
  handoffInterface = lib.abilities.interfaces.bootPreparation.interfaces.handoff;
  handoffDeclaration = {
    requirementTemplates.boot-preparation-handoff =
      lib.abilities.interfaceSelector {
        name = handoffInterface.name;
        abi = 1;
      }
      // {
        description = "Transfers exact successful initrd preparation evidence to the host stage.";
        methods = handoffInterface.methods;
        guarantees = [];
        strength = "required";
        fallback = null;
      };
  };
  handoffRequest = {
    requests.boot-preparation-handoff = {
      requirement = "boot-preparation-handoff";
      consumer = consumerInstance;
      scope = ["initrd-to-host"];
      parameters = {
        source_stage = "initrd";
        receiver_stage = "host";
        completion = initrdFilesystemsReadiness;
        preparations = handoffPreparationResources;
        preserved_mounts = [
          {
            initrd_path = "/run";
            host_path = "/run";
          }
          {
            initrd_path = "/sysroot/etc";
            host_path = "/etc";
          }
          {
            initrd_path = "/sysroot/nix";
            host_path = "/nix";
          }
          {
            initrd_path = "/sysroot/var";
            host_path = "/var";
          }
        ];
        durable_state_roots = [
          {
            initrd_path = "/sysroot/var/lib/profiles/image";
            host_path = "/var/lib/profiles/image";
          }
          {
            initrd_path = "/sysroot/var/lib/profiles/system";
            host_path = "/var/lib/profiles/system";
          }
        ];
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
  ];
  handoffInitrdFragments = [initrdController initrdHandoffBarrier];
  handoffHostFragments = [localFilesystems hostStageReceived hostReceiver];
  lifecycleResourceFor = fragment: let
    requests = (serviceManagement.splitDefinition fragment).configured.requests or {};
    lifecycleRequests =
      builtins.filter
      (requestName: requests.${requestName}.requirement == interfaces.lifecycle.alias)
      (builtins.attrNames requests);
  in
    if lifecycleRequests == []
    then null
    else if builtins.length lifecycleRequests == 1
    then resultOf (builtins.head lifecycleRequests) "resource"
    else throw "one package-owned service fragment emitted several lifecycle requests";
  handoffPreparationResources =
    builtins.sort
    (left: right: builtins.toJSON left < builtins.toJSON right)
    (builtins.filter
      (resource: resource != null)
      (builtins.map lifecycleResourceFor (
        baseFragments ++ substrateFragments ++ handoffInitrdFragments
      )));
  substrateContributions = builtins.map serviceManagement.splitDefinition substrateFragments;
  handoffInitrdContributions = builtins.map serviceManagement.splitDefinition handoffInitrdFragments;
  handoffHostContributions = builtins.map serviceManagement.splitDefinition handoffHostFragments;
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
    handoffEnabled = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      internal = true;
      description = "Whether checked initrd-to-host ability ownership transfer is active.";
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        [handoffDeclaration networkContribution.declarations]
        ++ builtins.map (definition: definition.declarations) (
          baseContributions
          ++ substrateContributions
          ++ handoffInitrdContributions
          ++ handoffHostContributions
        )
      );
    }
    (lib.mkIf initrdStage {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (definition: definition.configured) baseContributions
      );
    })
    (lib.mkIf (initrdStage && cfg.enable) {
      aos.abilities = lib.mkMerge (
        [networkContribution.configured]
        ++ builtins.map (definition: definition.configured) substrateContributions
      );
    })
    (lib.mkIf (initrdStage && cfg.handoffEnabled) {
      aos.abilities = lib.mkMerge (
        [handoffRequest]
        ++ builtins.map (definition: definition.configured) handoffInitrdContributions
      );
    })
    (lib.mkIf (hostStage && cfg.handoffEnabled) {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (definition: definition.configured) handoffHostContributions
      );
    })
  ];
}
