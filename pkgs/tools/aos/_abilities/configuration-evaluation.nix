##! Package-owned boot configuration evaluation service.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.packageRuntime.configurationEvaluation;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "configuration-evaluation";
  hostStage =
    config.aos.abilities.environment != null
    && config.aos.abilities.environment.stage == "host";

  producer = key: interface: parameters:
    serviceManagement.forProducer {
      inherit consumerInstance key interface parameters;
    };
  localFilesystems = producer "local-filesystems" interfaces.filesystemReadiness {
    scope = "local-filesystems";
  };
  runtimeEntryPopulation = producer "runtime-entry-population" interfaces.runtimeEntryPopulation {
    scope = "runtime-entries";
  };
  networkReadiness = producer "network-readiness" interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = ["ipv4" "ipv6"];
  };
  userSessions = producer "user-sessions-ready" interfaces.activationMilestone {
    milestone = "user-sessions-ready";
  };
  multiUser = producer "multi-user" interfaces.systemMilestoneReadiness {
    milestone = "multi-user";
  };
  storeDatabase = {
    requirementTemplates.nix-store-database =
      lib.abilities.interfaceSelector {
        name = "aos.nix.store-database";
        abi = 1;
      }
      // {
        description = "Require the booted image closure in the local Nix store database.";
        methods = ["converge" "observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
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
  registrySynchronization = serviceManagement.forService {
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
          (resultOf "local-filesystems" "readiness-resource")
          (resultOf "network-readiness" "readiness-resource")
          (resultOf "aos-credential-recovery-lifecycle" "service-resource")
        ];
        before = [];
        requires = [
          (resultOf "local-filesystems" "readiness-resource")
          (resultOf "aos-credential-recovery-lifecycle" "service-resource")
        ];
        wants = [(resultOf "network-readiness" "readiness-resource")];
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
      conditions.all = [
        {
          kind = "path";
          predicate = "exists";
          path = cfg.hostNix;
          negated = false;
        }
      ];
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
      linux_isolation = {
        allow_privilege_escalation = false;
        ambient_capabilities = [];
        capability_bounds = {
          kind = "restricted";
          capabilities = [];
        };
        control_group_delegation = false;
        control_group_access = "read-only";
        device_namespace = "private";
        kernel_clock_mutation = false;
        kernel_hostname_mutation = false;
        kernel_log_access = false;
        kernel_module_access = false;
        kernel_tunable_access = false;
        lock_personality = false;
        memory_write_execute = false;
        remove_ipc = false;
        namespace_isolation = [];
        namespace_creation = "denied";
        network_address_families = ["ipv4" "ipv6" "unix"];
        oom_score_adjust = 0;
        permit_realtime = false;
        permit_suid_sgid = false;
        process_visibility = "all";
        syscall_architectures = [];
        syscall_allow = [];
        syscall_deny = [];
        syscall_denial_action = "return-permission-denied";
        syscall_profile = "system-service";
        user_namespace_ownership = "none";
      };
      resources = {
        memory_high_bytes = {kind = "unbounded";};
        memory_max_bytes = {kind = "unbounded";};
        tasks = {kind = "unbounded";};
      };
    };
  };
  registryReadiness = resultOf "registry-synchronization-lifecycle" "service-resource";
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
  mountEsp = {
    _type = "aos-request-output-reference";
    request = "aos-boot-storage:aos-mount-esp-lifecycle";
    output = "service-resource";
  };
  activationPreflight = resultOf "aos-graph-compile-lifecycle" "service-resource";
  activation = resultOf "aos-activate-lifecycle" "service-resource";
  configurationReady = resultOf "aos-config" "activation-resource";
  multiUserReadiness = resultOf "multi-user" "readiness-resource";
  runtimeEntriesReady = resultOf "runtime-entry-population" "lifecycle-resource";
  evaluationReady = resultOf "configuration-evaluation-lifecycle" "service-resource";
  fallback = oneshot {
    serviceName = "image-rollout-fallback";
    managerName = "aos-image-rollout-fallback";
    description = "Continue counted-boot fallback after qualified rollout failure";
    command = packageRuntimeCommand ["fallback"];
    serviceDependencies = dependencies {
      after = [(resultOf "image-boot-commit-lifecycle" "service-resource")];
    };
    enabled = false;
    searchPath = [(lib.abilities.packageOutput {package = "systemd";})];
  };
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
    failurePolicy = {
      handlers = [(resultOf "image-rollout-fallback-lifecycle" "service-resource")];
      dispatch = "replace-active-goal";
    };
    searchPath = builtins.map lib.abilities.packageOutput [
      {package = "aos-boot-storage";}
      {package = "systemd";}
      {package = "util-linux";}
    ];
  };
  imageMeasurement = oneshot {
    serviceName = "image-measurement-index";
    managerName = "aos-image-measurement-index";
    description = "Import authenticated UKI PCR 11 measurement metadata";
    command = packageRuntimeCommand (
      ["measurement-index"]
      ++ lib.optionals (cfg.pcrPublicKey != null) ["--pcr-public-key" cfg.pcrPublicKey]
    );
    serviceDependencies = dependencies {
      after = [mountEsp (resultOf "local-filesystems" "readiness-resource") runtimeEntriesReady];
      before = [evaluationReady multiUserReadiness];
      requires = [mountEsp (resultOf "local-filesystems" "readiness-resource") runtimeEntriesReady];
      wantedBy = [multiUserReadiness];
    };
    enabled = true;
    searchPath = [(lib.abilities.packageOutput {package = "openssl";})];
  };
  service = serviceManagement.forService {
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
                "--host-nix"
                cfg.hostNix
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
                "--provisioning-state"
                cfg.provisioningState
                "--image-version"
                cfg.imageVersion
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
        prerequisites = [(resultOf "nix-store-database" "readiness-resource")];
        after = [
          (resultOf "local-filesystems" "readiness-resource")
          (resultOf "network-readiness" "readiness-resource")
          (resultOf "aos-credential-recovery-lifecycle" "service-resource")
          registryReadiness
        ];
        before = [(resultOf "user-sessions-ready" "readiness-resource")];
        requires = [
          (resultOf "local-filesystems" "readiness-resource")
          (resultOf "aos-credential-recovery-lifecycle" "service-resource")
        ];
        wants = [
          (resultOf "network-readiness" "readiness-resource")
          registryReadiness
        ];
        requisite = [];
        conflicts = [];
        binds_to = [];
        part_of = [];
        upholds = [];
        required_by = [];
        wanted_by = [(resultOf "user-sessions-ready" "readiness-resource")];
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
      linux_isolation = {
        allow_privilege_escalation = false;
        ambient_capabilities = [];
        capability_bounds = {
          kind = "restricted";
          capabilities = [];
        };
        control_group_delegation = false;
        control_group_access = "read-only";
        device_namespace = "private";
        kernel_clock_mutation = false;
        kernel_hostname_mutation = false;
        kernel_log_access = false;
        kernel_module_access = false;
        kernel_tunable_access = false;
        lock_personality = false;
        memory_write_execute = false;
        remove_ipc = false;
        namespace_isolation = [];
        namespace_creation = "denied";
        network_address_families = ["ipv4" "ipv6" "unix"];
        oom_score_adjust = 0;
        permit_realtime = false;
        permit_suid_sgid = false;
        process_visibility = "all";
        syscall_architectures = [];
        syscall_allow = [];
        syscall_deny = ["@clock" "@cpu-emulation" "@debug" "@keyring" "@mount" "@obsolete" "@privileged" "@raw-io" "@reboot" "@resources" "@swap"];
        syscall_denial_action = "return-permission-denied";
        syscall_profile = "system-service";
        user_namespace_ownership = "none";
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
    registrySynchronization
    service
    fallback
    bootCommit
  ];
  measurementFragments = [runtimeEntryPopulation imageMeasurement];
  declaredFragments = coreFragments ++ measurementFragments;
  configuredFragments =
    coreFragments
    ++ lib.optionals cfg.measuredBoot (
      if cfg.pcrPublicKey == null
      then throw "measured boot requires aos.packageRuntime.configurationEvaluation.pcrPublicKey"
      else measurementFragments
    );
  baseContributions = builtins.map serviceManagement.splitContribution declaredFragments;
  storeDatabaseContribution = serviceManagement.splitContribution storeDatabase;
  contributions = builtins.map serviceManagement.splitContribution (configuredFragments ++ [storeDatabase]);
in {
  options.aos.packageRuntime.configurationEvaluation = {
    enable = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      internal = true;
      description = "Whether this host runs boot configuration evaluation.";
    };
    hostNix = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/run/aos-metadata/host.nix";
      internal = true;
      description = "Authenticated host module path released by initrd metadata authorization.";
    };
    baseLib = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/aos-toplevel/base-lib";
      internal = true;
      description = "Immutable image base module library path.";
    };
    moduleAbi = lib.mkOption {
      type = lib.abilities.types.integer {minimum = 1; maximum = 4294967295;};
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
    provisioningState = lib.mkOption {
      type = lib.abilities.types.executionPath;
      default = "/var/lib/aos-provisioning";
      internal = true;
      description = "Durable provisioning evidence and last-known-good input directory.";
    };
    imageVersion = lib.mkOption {
      type = lib.abilities.types.string {
        maxLength = 256;
        syntax = null;
      };
      default = "unknown";
      internal = true;
      description = "Immutable image version recorded with provisioning evidence.";
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
        builtins.map (contribution: contribution.declarations) baseContributions
        ++ lib.optional cfg.enable storeDatabaseContribution.declarations
      );
    }
    (lib.mkIf (hostStage && cfg.enable) {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (contribution: contribution.configured) contributions
      );
    })
  ];
}
