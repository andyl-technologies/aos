##! Package-owned boot configuration evaluation service.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.packageRuntime.configurationEvaluation;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  milestones = serviceManagement.milestones;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "configuration-evaluation";
  hostStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host";

  producer = key: interface: parameters:
    serviceManagement.forProducer {
      inherit consumerInstance key interface parameters;
    };
  localFilesystems = producer "local-filesystems" interfaces.filesystemReadiness {
    scope = "local-filesystems";
  };
  runtimeEntryPopulation = producer "runtime-entry-population" interfaces.runtimeEntryPopulation {
    entries = [];
  };
  networkReadiness = producer "network-readiness" interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = ["ipv4" "ipv6"];
  };
  userSessions = producer "user-sessions-ready" interfaces.activationMilestone {
    milestone = "user-sessions-ready";
  };
  multiUser = producer "multi-user" interfaces.systemMilestoneReadiness {
    milestone = milestones.multiUser;
  };
  espReady = producer "esp-ready" interfaces.systemMilestoneReadiness {
    milestone = milestones.espReady;
  };
  hostStageReceived = producer "host-stage-received" interfaces.systemMilestoneReadiness {
    milestone = milestones.hostStageReceived;
  };
  hostStageReceivedReadiness = resultOf "host-stage-received" "resource";
  storeDatabase = {
    requests.nix-store-database = {
      requirement = "nix-store-database";
      consumer = consumerInstance;
      scope = ["database"];
      parameters = {
        scope = "local";
        registration = {
          path = "/aos-registration";
          required = false;
        };
        prerequisites = [];
      };
    };
  };
  storeView = {
    requirementTemplates.package-store-read-view =
      lib.abilities.interfaceSelector {
        name = "aos.package-store.read-view";
        abi = 1;
      }
      // {
        description = "Require the selected immutable package-store view for host evaluation.";
        methods = ["observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
    requests.package-store-read-view = {
      requirement = "package-store-read-view";
      consumer = consumerInstance;
      scope = ["boot-image"];
      parameters.scope = "boot-image";
    };
  };
  storeViewInterface = lib.abilities.interfaces.packageStoreReadView.interfaces.readView;
  storeViewLocator = lib.abilities.canonicalJsonOf {
    type = storeViewInterface.locatorType;
    value = resultOf "package-store-read-view" "locator";
    maxBytes = 4096;
  };
  storeViewResource = resultOf "package-store-read-view" "resource";
  registrySynchronization = serviceManagement.forService {
    featureRequests = [
      (serviceManagement.featureRequest {
        key = "hardening";
        requirementAlias = "service-hardening";
        description = "Requires the selected service-management provider to enforce the declared service hardening policy.";
        interface = "aos.service.hardening";
        abi = 1;
        parameters = {
          allow_privilege_escalation = false;
          ambient_privileges = [];
          privilege_bounds = {
            kind = "restricted";
            privileges = [];
          };
          resource_control_delegation = false;
          resource_control_access = "read-only";
          device_access_scope = "private";
          host_clock_mutation = false;
          host_name_mutation = false;
          operating_system_log_access = false;
          operating_system_extension_access = false;
          operating_system_tunable_access = false;
          lock_execution_personality = false;
          writable_executable_memory = false;
          remove_interprocess_communication = false;
          isolation_domains = [];
          isolation_domain_creation = "denied";
          network_families = ["ipv4" "ipv6" "local"];
          memory_pressure_adjustment = 0;
          permit_realtime = false;
          permit_elevated_file_identity = false;
          process_visibility = "all";
          operation_architectures = [];
          operation_allow = [];
          operation_deny = [];
          denied_operation_action = "return-permission-denied";
          operation_profile = "system-service";
          isolated_identity_mapping = "none";
        };
      })
    ];
    inherit serviceTypes consumerInstance;
    declaration = {
      service = "registry-synchronization";
      enabled = true;
      lifecycle = {
        description = "Refresh signed registry metadata for host evaluation";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {output = "apm";};
              entry_point = "bin/apm";
              arguments = ["update" "--system"];
            };
            ignore_failure = false;
          }
        ];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "never";
        restart_delay_millis = 0;
        configuration_change_action = "restart";
        remain_after_exit = true;
        start_timeout_millis = 120000;
        stop_timeout_millis = 90000;
      };
      dependencies = {
        prerequisites = [];
        after = [
          (resultOf "local-filesystems" "resource")
          (resultOf "network-readiness" "resource")
        ];
        before = [];
        requires = [
          (resultOf "local-filesystems" "resource")
        ];
        wants = [(resultOf "network-readiness" "resource")];
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
      manager_identity = {
        name = "aos-registry-sync";
        aliases = [];
      };
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 120000;
      };
      environment = {
        variables = {};
        search_path = [];
      };
      isolation = {
        privilege = "privileged";
        filesystem = "read-only-system";
        home_access = "inaccessible";
        network = "host";
        process_visibility = "host";
        termination_scope = "all-processes";
        temporary_directory = "private";
        devices = [];
        host_paths = [
          {
            source = "/var/lib/apm";
            mode = "read-write";
          }
        ];
        permit_core_dumps = false;
      };
      resources = {
        memory_high_bytes = {kind = "unbounded";};
        memory_max_bytes = {kind = "unbounded";};
        tasks = {kind = "unbounded";};
      };
    };
  };
  registryReadiness = resultOf "registry-synchronization-lifecycle" "resource";
  packageRuntimeCommand = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {output = "packageRuntime";};
      entry_point = "libexec/aos-image-rollout-boot";
      inherit arguments;
    };
    ignore_failure = false;
  };
  dependencies = {
    after ? [],
    before ? [],
    requires ? [],
    wants ? [],
    wantedBy ? [],
  }: {
    prerequisites = [];
    inherit after before requires wants;
    requisite = [];
    conflicts = [];
    binds_to = [];
    part_of = [];
    upholds = [];
    required_by = [];
    wanted_by = wantedBy;
    required_mounts = [];
    implicit_dependencies = false;
  };
  oneshot = {
    serviceName,
    managerName,
    description,
    command,
    serviceDependencies,
    enabled,
    conditions ? null,
    failurePolicy ? null,
    searchPath ? [],
  }:
    serviceManagement.forService {
      inherit serviceTypes consumerInstance;
      declaration =
        {
          service = serviceName;
          inherit enabled;
          lifecycle = {
            inherit description;
            execution_model = "oneshot";
            environment_files = [];
            condition = [];
            pre_start = [];
            start = [command];
            post_start = [];
            stop = [];
            post_stop = [];
            restart = "never";
            restart_delay_millis = 0;
            configuration_change_action = "restart";
            remain_after_exit = true;
            start_timeout_millis = 300000;
            stop_timeout_millis = 90000;
          };
          dependencies = serviceDependencies;
          manager_identity = {
            name = managerName;
            aliases = [];
          };
          readiness = {
            mechanism = "successful-exit";
            signal_scope = "none";
            timeout_millis = 300000;
          };
          environment = {
            variables = {};
            search_path = searchPath;
          };
        }
        // lib.optionalAttrs (conditions != null) {inherit conditions;}
        // lib.optionalAttrs (failurePolicy != null) {failure_policy = failurePolicy;};
    };
  mountEsp = resultOf "esp-ready" "resource";
  activationPreflight = resultOf "aos-graph-compile-lifecycle" "resource";
  activation = resultOf "aos-activate-lifecycle" "resource";
  configurationReady = resultOf "aos-config" "resource";
  multiUserReadiness = resultOf "multi-user" "resource";
  bootCommit = oneshot {
    serviceName = "image-boot-commit";
    managerName = "aos-image-boot-commit";
    description = "Commit a successful image transition";
    command = packageRuntimeCommand (
      ["commit"]
      ++ lib.optional cfg.measuredBoot "--require-attestation-quote"
    );
    serviceDependencies = dependencies {
      after = [mountEsp activationPreflight activation configurationReady];
      before = [multiUserReadiness];
      requires = [mountEsp activationPreflight];
      wantedBy = [multiUserReadiness];
    };
    enabled = true;
    conditions.all = [
      {
        kind = "path";
        predicate = "exists";
        path = "/run/aos/image-reeval-required";
        negated = false;
      }
      {
        kind = "path";
        predicate = "exists";
        path = "/sys/firmware/efi";
        negated = false;
      }
    ];
  };
  service = serviceManagement.forService {
    featureRequests = [
      (serviceManagement.featureRequest {
        key = "hardening";
        requirementAlias = "service-hardening";
        description = "Requires the selected service-management provider to enforce the declared service hardening policy.";
        interface = "aos.service.hardening";
        abi = 1;
        parameters = {
          allow_privilege_escalation = false;
          ambient_privileges = [];
          privilege_bounds = {
            kind = "restricted";
            privileges = [];
          };
          resource_control_delegation = false;
          resource_control_access = "read-only";
          device_access_scope = "private";
          host_clock_mutation = false;
          host_name_mutation = false;
          operating_system_log_access = false;
          operating_system_extension_access = false;
          operating_system_tunable_access = false;
          lock_execution_personality = false;
          writable_executable_memory = false;
          remove_interprocess_communication = false;
          isolation_domains = [];
          isolation_domain_creation = "denied";
          network_families = ["ipv4" "ipv6" "local"];
          memory_pressure_adjustment = 0;
          permit_realtime = false;
          permit_elevated_file_identity = false;
          process_visibility = "all";
          operation_architectures = [];
          operation_allow = [];
          operation_deny = ["clock" "cpu-emulation" "debug" "keyring" "mount" "obsolete" "privileged" "raw-io" "reboot" "resource-control" "swap"];
          denied_operation_action = "return-permission-denied";
          operation_profile = "system-service";
          isolated_identity_mapping = "none";
        };
      })
    ];
    inherit serviceTypes consumerInstance;
    declaration = {
      service = consumerInstance;
      enabled = true;
      lifecycle = {
        description = "Evaluate host configuration to a converged manifest";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {output = "packageRuntime";};
              entry_point = "bin/aos-package-runtime";
              arguments = [
                "__eval-service"
                "--store-view"
                storeViewLocator
                "--base-lib"
                cfg.baseLib
                "--module-abi"
                (toString cfg.moduleAbi)
                "--desired"
                cfg.desired
                "--out"
                cfg.manifest
                "--eval-root"
                cfg.evalRoot
              ];
            };
            ignore_failure = false;
          }
        ];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "never";
        restart_delay_millis = 0;
        configuration_change_action = "restart";
        remain_after_exit = true;
        start_timeout_millis = 300000;
        stop_timeout_millis = 90000;
      };
      dependencies = {
        prerequisites = [
          (resultOf "nix-store-database" "resource")
          storeViewResource
        ];
        after = [
          hostStageReceivedReadiness
          (resultOf "local-filesystems" "resource")
          (resultOf "network-readiness" "resource")
          registryReadiness
        ];
        before = [(resultOf "user-sessions-ready" "resource")];
        requires = [
          hostStageReceivedReadiness
          (resultOf "local-filesystems" "resource")
        ];
        wants = [
          (resultOf "network-readiness" "resource")
          registryReadiness
        ];
        requisite = [];
        conflicts = [];
        binds_to = [];
        part_of = [];
        upholds = [];
        required_by = [];
        wanted_by = [(resultOf "user-sessions-ready" "resource")];
        required_mounts = [];
        implicit_dependencies = false;
      };
      manager_identity = {
        name = "aos-eval";
        aliases = [];
      };
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 300000;
      };
      directories.managed = [
        {
          path = "aos/nix-eval";
          purpose = "cache";
          mode = "0700";
          retention = "persistent";
        }
        {
          path = "aos";
          purpose = "runtime";
          mode = "0755";
          retention = "service-lifetime";
        }
        {
          path = "aos-eval";
          purpose = "runtime";
          mode = "0700";
          retention = "service-lifetime";
        }
      ];
      environment = {
        variables.XDG_CACHE_HOME = "/var/cache/aos/nix-eval";
        search_path = [];
      };
      isolation = {
        privilege = "privileged";
        filesystem = "read-only-system";
        home_access = "inaccessible";
        network = "host";
        process_visibility = "host";
        termination_scope = "all-processes";
        temporary_directory = "private";
        devices = [];
        host_paths = [
          {
            source = "/nix";
            mode = "read-write";
          }
          {
            source = "/run/aos";
            mode = "read-write";
          }
          {
            source = "/run/aos-eval";
            mode = "read-write";
          }
          {
            source = "/var/cache/aos/nix-eval";
            mode = "read-write";
          }
        ];
        permit_core_dumps = false;
      };
      resources = {
        memory_high_bytes = {
          kind = "maximum";
          value = 1610612736;
        };
        memory_max_bytes = {
          kind = "maximum";
          value = 2147483648;
        };
        tasks = {
          kind = "maximum";
          value = 4096;
        };
      };
    };
  };
  coreFragments = [
    localFilesystems
    networkReadiness
    userSessions
    multiUser
    espReady
    hostStageReceived
    registrySynchronization
    service
    bootCommit
  ];
  measurementFragments = [runtimeEntryPopulation];
  declaredFragments = coreFragments ++ measurementFragments;
  configuredFragments =
    coreFragments
    ++ lib.optionals cfg.measuredBoot (
      if cfg.pcrPublicKey == null
      then throw "measured boot requires aos.packageRuntime.configurationEvaluation.pcrPublicKey"
      else measurementFragments
    );
  baseContributions = builtins.map serviceManagement.splitDefinition declaredFragments;
  storeDatabaseContribution = serviceManagement.splitDefinition storeDatabase;
  storeViewContribution = serviceManagement.splitDefinition storeView;
  definitions = builtins.map serviceManagement.splitDefinition (configuredFragments ++ [storeDatabase storeView]);
in {
  options.aos.packageRuntime.configurationEvaluation = {
    enable = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      internal = true;
      description = "Whether this host runs boot configuration evaluation.";
    };
    baseLib = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/aos-toplevel/base-lib";
      internal = true;
      description = "Immutable image base module library path.";
    };
    moduleAbi = lib.mkOption {
      type = lib.abilities.types.integer {
        minimum = 1;
        maximum = 4294967295;
      };
      default = 1;
      internal = true;
      description = "Fallback module ABI when the running image omits it.";
    };
    desired = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/etc/aos/packages.d/desired.toml";
      internal = true;
      description = "Optional desired package selection file.";
    };
    manifest = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/run/aos/manifest.json";
      internal = true;
      description = "Converged manifest output path.";
    };
    evalRoot = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/run/aos-eval";
      internal = true;
      description = "Private evaluation scratch directory.";
    };
    measuredBoot = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      internal = true;
      description = "Whether boot finalization imports and verifies measured-boot evidence.";
    };
    pcrPublicKey = lib.mkOption {
      type = lib.abilities.types.optional lib.abilities.types.executionPath;
      default = null;
      internal = true;
      description = "Authoritative PCR policy public key used to verify image measurement metadata.";
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        builtins.map (definition: definition.declarations) baseContributions
        ++ lib.optionals cfg.enable [
          storeDatabaseContribution.declarations
          storeViewContribution.declarations
        ]
      );
    }
    (lib.mkIf (hostStage && cfg.enable) {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (definition: definition.configured) definitions
      );
    })
  ];
}
