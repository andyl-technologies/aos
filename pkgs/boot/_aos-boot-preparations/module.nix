##! Package-owned initrd configuration seeding.
{
  config,
  lib,
  package,
  dependencies,
  options,
  ...
}: let
  cfg = config.aos.boot.substrateServices;
  managerIdentity = name: {
    inherit name;
    aliases = [];
  };
  stage = config.aos.boot.stage;
  initrdStage = stage == "initrd";
  hostStage = stage == "host";
  controlPlaneEnabled = ((options.aos.config.unitGraph or {}) ? enable) && config.aos.config.unitGraph.enable;
  hostActivatorService =
    if !hostStage
    then null
    else if controlPlaneEnabled
    then "control-plane.aos-activate"
    else if cfg.handoffEnabled
    then "boot-preparations.aos-ability-host-controller"
    else null;
  command = operation: {
    executable = {
      path = "${package}/bin/aos-boot-preparations";
      arguments = [operation];
    };
    ignore_failure = false;
  };
  substrateCommand = entryPoint: {
    executable = {
      path = "${package}/bin/${entryPoint}";
      arguments = [];
    };
    ignore_failure = false;
  };
  earlySystemReadiness = "initrd-fs.target";
  switchRootReadiness = "initrd-switch-root.target";
  sysrootReadiness = "sysroot.mount";
  varReadiness = "mount-var.service";
  nixOverlayReadiness = "nix-overlay-setup.service";
  etcOverlayReadiness = "etc-overlay-setup.service";
  runEtcReadiness = "run-etc-setup.service";
  initrdFilesystemsReadiness = "initrd-fs.target";
  initrdRootFilesystemsReadiness = "initrd-root-fs.target";
  deviceSettleReadiness = "systemd-udev-settle.service";
  initrdStageReadiness = "aos-ability-initrd-controller.service";
  bootIdentityReadiness = "aos-boot-identity-guard.service";
  bootStorageUnlockedReadiness = "aos-zfs-unlock.service";
  localFilesystemsReadiness = "local-fs.target";
  hostStoreReadiness = "aos-host-store-seed.service";
  hostStageReceivedReadiness = "aos-ability-host-receiver.service";
  multiUserReadiness = "multi-user.target";
  service = {
    key,
    description,
    operation,
    dependencies,
  }: {
    activationOwner = "manager";
    autoStart = false;
    service = key;
    manager_identity = managerIdentity key;
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
  baseServices = [configurationSeed];
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
  serviceResource = key: "${key}.service";
  handoffCommand = arguments: {
    executable = {
      path = "${package}/bin/aos-boot-preparations";
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
    activationOwner ? "ability",
    readinessMechanism ? "successful-exit",
    startTimeoutMillis ? 90000,
  }:
    {
      inherit activationOwner;
      autoStart = false;
      service = key;
      manager_identity = managerIdentity key;
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
        start_timeout_millis = startTimeoutMillis;
        stop_timeout_millis = 90000;
      };
      inherit dependencies;
      readiness = {
        mechanism = readinessMechanism;
        signal_scope = "none";
        timeout_millis = startTimeoutMillis;
      };
    }
    // lib.optionalAttrs (environment != null) {inherit environment;}
    // lib.optionalAttrs (logging != null) {inherit logging;};

  stageInputPathsType = lib.types.attrsOf (lib.types.submodule {
    options.bundle = lib.mkOption {
      type = lib.types.str;
      description = "Immutable native package deployment bundle directory.";
    };
  });
  stageInputPaths = {
    initrd.bundle = "/lib/aos/initrd/deployment";
    receivedInitrd.bundle = "/usr/lib/aos/initrd/deployment";
    host.bundle = "/usr/lib/aos/host/deployment";
  };
  stageInputs = stageName: stateDirectory: [
    "--input"
    config.aos.boot.stageInputPaths.${stageName}.bundle
    "--state-directory"
    stateDirectory
    "--nix-store"
    "${dependencies.nix.path}/bin/nix-store"
  ];
  initrdController = handoffService {
    key = "aos-ability-initrd-controller";
    description = "Execute and release initrd-stage ability ownership";
    activationOwner = "image";
    readinessMechanism = "successful-exit";
    arguments = ["apply-deployment"] ++ stageInputs "initrd" cfg.initrdStateDirectory;
    dependencies =
      emptyDependencies
      // {
        after = [
          sysrootReadiness
          "aos-boot-transaction-storage.service"
        ];
        # The manager-owned mount-var unit orders after the handoff barrier.
        before = [
          initrdFilesystemsReadiness
          switchRootReadiness
        ];
        requires = [
          sysrootReadiness
          "aos-boot-transaction-storage.service"
        ];
        required_by = [initrdFilesystemsReadiness];
        implicit_dependencies = false;
      };
  };
  initrdHandoffBarrier = handoffService {
    key = "aos-ability-initrd-handoff-barrier";
    description = "Authenticate released initrd ability ownership";
    activationOwner = "manager";
    arguments = ["verify-deployment"] ++ stageInputs "initrd" cfg.initrdStateDirectory;
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
  hostStoreSeed =
    (substrateService {
      key = "aos-host-store-seed";
      description = "Hydrate the immutable image store before host verification";
      dependencies =
        emptyDependencies
        // {
          after = [localFilesystemsReadiness];
          requires = [localFilesystemsReadiness];
          before = [hostStageReceivedReadiness];
          required_by = [hostStageReceivedReadiness];
          implicit_dependencies = false;
        };
      logging = substrateLogging;
    })
    // {activationOwner = "image";};
  initrdStoreHandoff = handoffService {
    key = "aos-initrd-store-handoff";
    description = "Retain committed provisioning receipts in the host store";
    activationOwner = "manager";
    arguments = ["handoff-initrd-store"] ++ stageInputs "initrd" cfg.initrdStateDirectory;
    dependencies =
      emptyDependencies
      // {
        after = [(serviceResource "nix-overlay-setup") (serviceResource "aos-ability-initrd-controller")];
        requires = [(serviceResource "nix-overlay-setup") (serviceResource "aos-ability-initrd-controller")];
        before = [initrdFilesystemsReadiness switchRootReadiness];
        required_by = [initrdFilesystemsReadiness];
        implicit_dependencies = false;
      };
    logging = substrateLogging;
  };
  hostReceiver = handoffService {
    key = "aos-ability-host-receiver";
    description = "Revalidate and receive initrd ability ownership";
    activationOwner = "image";
    arguments = ["verify-deployment"] ++ stageInputs "receivedInitrd" cfg.initrdStateDirectory;
    dependencies =
      emptyDependencies
      // {
        after = [localFilesystemsReadiness hostStoreReadiness];
        requires = [localFilesystemsReadiness hostStoreReadiness];
      };
  };
  hostController = handoffService {
    key = "aos-ability-host-controller";
    description = "Execute the sealed host-stage ability plan";
    activationOwner = "image";
    readinessMechanism = "successful-exit";
    startTimeoutMillis = 600000;
    arguments = ["apply-deployment"] ++ stageInputs "host" cfg.hostStateDirectory;
    dependencies =
      emptyDependencies
      // {
        after = [hostStageReceivedReadiness localFilesystemsReadiness];
        before = [multiUserReadiness];
        requires = [hostStageReceivedReadiness localFilesystemsReadiness];
        required_by = [multiUserReadiness];
      };
  };
  substrateEnvironment = {
    variables = {
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
    search_path =
      builtins.map (name: dependencies.${name}.path)
      ["coreutils" "jq" "sbsigntools" "tpm2-tools" "util-linux"]
      ++ [dependencies.aos.outputs.packageRuntime]
      ++ lib.optional cfg.zfsEnabled cfg.zfsPackagePath;
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
      activationOwner = "manager";
      autoStart = false;
      service = key;
      manager_identity = managerIdentity key;
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
          ++ lib.optional (!cfg.zfsEnabled) (serviceResource "aos-storage-topology")
          ++ lib.optional cfg.verityEnabled bootIdentityReadiness;
        before = [
          (serviceResource "aos-config-seed")
          (serviceResource "etc-overlay-setup")
          initrdFilesystemsReadiness
        ];
        requires =
          [sysrootReadiness mountVarPrerequisite]
          ++ lib.optional (!cfg.zfsEnabled) (serviceResource "aos-storage-topology")
          ++ lib.optional cfg.verityEnabled bootIdentityReadiness;
        required_by = [initrdFilesystemsReadiness];
      };
    # A mapper, MD array, or raw partition can appear late. The script waits
    # and checks its filesystem; a raw-partition condition would skip it.
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
  handoffPathMapping = lib.types.submodule {
    options = {
      initrd_path = lib.mkOption {
        type = lib.types.str;
        description = "Path before switch-root.";
      };
      host_path = lib.mkOption {
        type = lib.types.str;
        description = "Preserved path after switch-root.";
      };
    };
  };
  handoffParametersType = lib.types.submodule {
    options = {
      source_stage = lib.mkOption {
        type = lib.types.enum ["initrd"];
        description = "Source boot scope.";
      };
      receiver_stage = lib.mkOption {
        type = lib.types.enum ["host"];
        description = "Receiving boot scope.";
      };
      completion = lib.mkOption {
        type = lib.types.str;
        description = "Bootstrap completion unit.";
      };
      preparations = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        description = "Bootstrap units completed before switch-root.";
      };
      preserved_mounts = lib.mkOption {
        type = lib.types.listOf handoffPathMapping;
        description = "Mount mappings preserved across switch-root.";
      };
      durable_state_roots = lib.mkOption {
        type = lib.types.listOf handoffPathMapping;
        description = "Durable journal and profile mappings.";
      };
    };
  };
  handoffParameters = {
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
  substrateServices = [
    mountVar
    nixOverlaySetup
    seedProfiles
    runEtcSetup
    machineId
    etcOverlaySetup
  ];
  handoffInitrdServices = [initrdController initrdHandoffBarrier initrdStoreHandoff];
  handoffHostServices = [hostStoreSeed hostReceiver] ++ lib.optional (!controlPlaneEnabled) hostController;
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
  imports = [./policy.nix ./source-authorization/module.nix];

  options.aos.boot.stageInputPaths = lib.mkOption {
    type = stageInputPathsType;
    default = stageInputPaths;
    readOnly = true;
    internal = true;
    description = "Stage-visible directories retaining the exact native package transaction and resolution.";
  };

  options.aos.boot.hostActivatorService = lib.mkOption {
    type = lib.types.nullOr lib.types.str;
    readOnly = true;
    internal = true;
    visible = false;
    description = "Selected package-owned service that applies the host deployment.";
  };

  options.aos.boot.handoffParameters = lib.mkOption {
    type = lib.types.nullOr handoffParametersType;
    default = null;
    internal = true;
    description = "Typed initrd-to-host journal handoff plan owned by the boot substrate.";
  };

  options.aos.boot.preparationExecutable = lib.mkOption {
    type = lib.types.str;
    readOnly = true;
    internal = true;
    description = "Admitted immutable executable for verified-image boot transactions.";
  };

  options.aos.boot.substrateServices = {
    initrdStateDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/run/aos-boot-transaction-storage/aos/initrd-stage-journal";
      internal = true;
      description = "Preserved durable generation and effect journals for the initrd scope.";
    };
    hostStateDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/profiles/system/deployment";
      internal = true;
      description = "Private generation and effect journals for the host scope.";
    };
    zfsPackagePath = lib.mkOption {
      type = lib.types.str;
      default = "";
      internal = true;
      description = "Kernel-compatible ZFS runtime output selected by the image.";
    };
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      description = "Whether the package-owned initrd substrate services are active.";
    };
    verityEnabled = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      description = "Whether mounting persistent state requires validated boot identity.";
    };
    zfsEnabled = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      description = "Whether persistent state is backed by the unlocked ZFS boot pool.";
    };
    zfsPool = lib.mkOption {
      type = lib.types.str;
      default = "rpool";
      internal = true;
      description = "ZFS pool containing persistent state datasets.";
    };
    recoveryEnabled = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      description = "Whether image profile seeding verifies a paired recovery image.";
    };
    recoveryAbi = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 0;
      internal = true;
      description = "Recovery image ABI accepted by profile seeding.";
    };
    espDevice = lib.mkOption {
      type = lib.types.str;
      default = "/dev/disk/by-partlabel/ESP";
      internal = true;
      description = "EFI System Partition read while verifying recovery state.";
    };
    handoffEnabled = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      description = "Whether checked initrd-to-host ability ownership transfer is active.";
    };
  };

  config = lib.mkMerge [
    {
      aos.boot.preparationExecutable = "${package}/bin/aos-boot-preparations";
      aos.boot.hostActivatorService = hostActivatorService;
      aos.services =
        (serviceConfigsFor initrdStage baseServices)
        // (serviceConfigsFor (initrdStage && cfg.enable) substrateServices)
        // (serviceConfigsFor (initrdStage && cfg.handoffEnabled) handoffInitrdServices)
        // (serviceConfigsFor (hostStage && cfg.handoffEnabled) handoffHostServices);
    }
    (lib.mkIf (hostStage && cfg.handoffEnabled && controlPlaneEnabled) {
      aos.services."control-plane.aos-activate".dependencies = {
        after = lib.mkAfter [hostStageReceivedReadiness localFilesystemsReadiness];
        requires = lib.mkAfter [hostStageReceivedReadiness localFilesystemsReadiness];
        before = lib.mkAfter [multiUserReadiness];
        required_by = lib.mkAfter [multiUserReadiness];
      };
    })
    (lib.mkIf (initrdStage && cfg.enable) {
      aos.abilities.network.operations.configure.effects.bootstrap.input = {
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
      };
    })
    (lib.mkIf (initrdStage && cfg.handoffEnabled) {
      aos.boot.handoffParameters = handoffParameters;
    })
  ];
}
