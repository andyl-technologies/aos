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
  networkReadiness = producer "network-readiness" interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = ["ipv4" "ipv6"];
  };
  userSessions = producer "user-sessions-ready" interfaces.activationMilestone {
    milestone = "user-sessions-ready";
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
        ];
        before = [(resultOf "user-sessions-ready" "readiness-resource")];
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
  baseFragments = [localFilesystems networkReadiness userSessions service];
  baseContributions = builtins.map serviceManagement.splitContribution baseFragments;
  storeDatabaseContribution = serviceManagement.splitContribution storeDatabase;
  fragments = baseFragments ++ [storeDatabase];
  contributions = builtins.map serviceManagement.splitContribution fragments;
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
