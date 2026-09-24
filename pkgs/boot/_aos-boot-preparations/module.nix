##! Package-owned initrd configuration seeding.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.boot.substrateServices;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  milestones = serviceManagement.milestones;
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
  }: {
    inherit consumerInstance;
    service = key;
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
  baseProducers = [
    earlySystem
    switchRoot
    sysroot
    var
    nixOverlay
    etcOverlay
    runEtc
  ];
  baseServices = [configurationSeed];
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
    environment ? null,
  }:
    {
      inherit consumerInstance;
      service = key;
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
    // lib.optionalAttrs (environment != null) {inherit environment;}
    // lib.optionalAttrs (logging != null) {inherit logging;};

  stageInputPathType = lib.abilities.types.record {
    fields = {
      bundle = lib.abilities.types.executionPath;
      identity = lib.abilities.types.executionPath;
      contract = lib.abilities.types.executionPath;
    };
  };
  stageInputPathsType = lib.abilities.types.record {
    fields = {
      initrd = stageInputPathType;
      host = stageInputPathType;
    };
  };
  stageInputPaths = {
    initrd = {
      bundle = "/lib/aos/initrd/source-stage-bundle.json";
      identity = "/lib/aos/initrd/static-ability-contract-identity";
      contract = "/lib/aos/initrd/static-ability-contract.json";
    };
    host = {
      bundle = "/usr/lib/aos/initrd/source-stage-bundle.json";
      identity = "/usr/lib/aos/initrd/static-ability-contract-identity";
      contract = "/usr/lib/aos/initrd/static-ability-contract.json";
    };
  };
  stageInputs = stage: let
    paths = config.aos.boot.stageInputPaths.${stage};
  in [
    "--source-stage-bundle"
    paths.bundle
    "--static-contract-identity-file"
    paths.identity
    "--static-contract"
    paths.contract
  ];

  initrdController = handoffService {
    key = "aos-ability-initrd-controller";
    description = "Execute and release initrd-stage ability ownership";
    environment = {
      variables = {
        AOS_NIX_INSTANTIATE = "/bin/nix-instantiate";
        AOS_PRLIMIT = "/bin/prlimit";
        AOS_ABILITY_EVALUATOR_CACHE = "/run/aos/ability-evaluator";
      };
      search_path = [];
    };
    arguments =
      [
        "__ability-stage-run"
        "--stage"
        "initrd"
        "--root"
        "/sysroot"
      ]
      ++ stageInputs "initrd";
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
    arguments =
      [
        "__ability-stage-validate"
        "--from-stage"
        "initrd"
        "--root"
        "/sysroot"
      ]
      ++ stageInputs "initrd";
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
    arguments =
      [
        "__ability-stage-receive"
        "--from-stage"
        "initrd"
        "--image-profile"
        "/var/lib/profiles/image"
      ]
      ++ stageInputs "host";
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
    {
      inherit consumerInstance;
      service = key;
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
  handoffPathMapping = lib.abilities.types.record {
    fields = {
      initrd_path = lib.abilities.types.executionPath;
      host_path = lib.abilities.types.executionPath;
    };
  };
  handoffPathMappings = lib.abilities.types.list {
    element = handoffPathMapping;
    maxItems = 16;
    unique = true;
    canonicalOrder = true;
  };
  handoffParametersType = lib.abilities.types.record {
    fields = {
      source_stage = lib.abilities.types.enum ["initrd"];
      receiver_stage = lib.abilities.types.enum ["host"];
      completion = lib.abilities.types.deferredResult lib.abilities.types.resourceReference;
      preparations = lib.abilities.types.list {
        element = lib.abilities.types.deferredResult lib.abilities.types.resourceReference;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      preserved_mounts = handoffPathMappings;
      durable_state_roots = handoffPathMappings;
    };
  };
  # Values outside aos.abilities do not receive its local-name qualification.
  handoffReference = reference:
    reference // {request = "aos-boot-preparations:${reference.request}";};
  handoffParameters = {
    source_stage = "initrd";
    receiver_stage = "host";
    completion = handoffReference initrdFilesystemsReadiness;
    preparations = builtins.map handoffReference handoffPreparationResources;
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
  substrateProducers = [
    initrdFilesystems
    initrdRootFilesystems
    deviceSettle
    initrdStageExecution
    bootIdentity
    bootStorageUnlocked
  ];
  substrateServices = [
    mountVar
    nixOverlaySetup
    seedProfiles
    runEtcSetup
    machineId
    etcOverlaySetup
  ];
  handoffInitrdServices = [initrdController initrdHandoffBarrier];
  handoffHostProducers = [localFilesystems hostStageReceived];
  handoffHostServices = [hostReceiver];
  handoffPreparationResources =
    builtins.sort
    (left: right: builtins.toJSON left < builtins.toJSON right)
    (builtins.map
      (serviceDefinition: serviceResource serviceDefinition.service)
      (baseServices ++ substrateServices ++ handoffInitrdServices));
  serviceConfigsFor = enabled: services:
    builtins.listToAttrs (builtins.map
      (serviceDefinition: {
        name = "boot-preparations.${serviceDefinition.service}";
        value = serviceDefinition // {enable = enabled;};
      })
      services);
in {
  options.aos.boot.stageInputPaths = lib.mkOption {
    type = stageInputPathsType;
    default = stageInputPaths;
    readOnly = true;
    internal = true;
    description = "Stage-visible locations of the exact source bundle and static contract inputs.";
  };

  options.aos.boot.handoffParameters = lib.mkOption {
    type = lib.types.nullOr handoffParametersType;
    default = null;
    internal = true;
    description = "Typed initrd-to-host journal handoff plan owned by the boot substrate.";
  };

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
      aos.services =
        (serviceConfigsFor initrdStage baseServices)
        // (serviceConfigsFor (initrdStage && cfg.enable) substrateServices)
        // (serviceConfigsFor (initrdStage && cfg.handoffEnabled) handoffInitrdServices)
        // (serviceConfigsFor (hostStage && cfg.handoffEnabled) handoffHostServices);
    }
    (serviceManagement.producerModule {
      inherit config lib;
      producers = baseProducers;
      enabled = initrdStage;
    })
    (serviceManagement.producerModule {
      inherit config lib;
      producers = substrateProducers;
      enabled = initrdStage && cfg.enable;
    })
    (serviceManagement.producerModule {
      inherit config lib;
      producers = [networkConfiguration];
      enabled = initrdStage && cfg.enable;
    })
    (serviceManagement.producerModule {
      inherit config lib;
      producers = handoffHostProducers;
      enabled = hostStage && cfg.handoffEnabled;
    })
    (lib.mkIf (initrdStage && cfg.handoffEnabled) {
      aos.boot.handoffParameters = handoffParameters;
    })
  ];
}
