##! Package-owned Docker daemon configuration and service requirements.
##!
##! Runs the source-built Docker daemon with persistent graph storage under
##! `/var/lib/docker` and its local API socket under `/run/docker.sock`.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.services.docker;
  dataRoot = cfg.dataRoot;
  runtimeRoot = "/run/docker";
  socketPath = "${builtins.dirOf runtimeRoot}/docker.sock";
  processIdPath = "${runtimeRoot}/docker.pid";
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;
  resultOf = lib.abilities.resultOf;
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "docker";
      inherit key interface parameters;
    };
  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/dockerd";
      inherit arguments;
    };
    ignore_failure = false;
  };
  dataStorage = producer "docker-data-storage" serviceManagement.interfaces.persistentStorageAllocation {
    name = "docker-data";
    purpose = "state";
    mode = "0710";
    requested_path = dataRoot;
  };
  runtimeStorage = producer "docker-runtime-storage" serviceManagement.interfaces.storageAllocation {
    name = "docker-runtime";
    purpose = "runtime";
    mode = "0755";
    requested_path = runtimeRoot;
  };
  networkReadiness = producer "docker-network-readiness" serviceManagement.interfaces.networkReadiness {
    scope = "stack-prepared";
    address_families = ["ipv4" "ipv6"];
  };
  service = serviceManagement.forService {
    featureContributions = [
      (serviceManagement.featureContribution {
        key = "linux_isolation";
        requirementAlias = "linux-service-isolation";
        description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
        interface = "aos.platform.linux.service-isolation";
        abi = 1;
        parameters = {
          allow_privilege_escalation = true;
          ambient_capabilities = [];
          capability_bounds.kind = "unrestricted";
          control_group_delegation = true;
          control_group_access = "host";
          device_namespace = "shared";
          kernel_clock_mutation = true;
          kernel_hostname_mutation = true;
          kernel_log_access = true;
          kernel_module_access = true;
          kernel_tunable_access = true;
          lock_personality = false;
          memory_write_execute = true;
          namespace_isolation = [];
          network_address_families = ["ipv4" "ipv6" "netlink" "packet" "unix"];
          oom_score_adjust = -500;
          permit_realtime = true;
          permit_suid_sgid = true;
          process_visibility = "all";
          syscall_architectures = [];
          syscall_allow = [];
          syscall_deny = [];
          syscall_profile = "privileged";
          user_namespace_ownership = "none";
        };
      })
    ];
    inherit serviceTypes;
    consumerInstance = "docker";
    declaration = {
      service = "docker";
      enabled = true;
      lifecycle = {
        description = "Docker container engine";
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          (command (
            [
              "--host=unix://${socketPath}"
              "--data-root=${dataRoot}"
              "--exec-root=${runtimeRoot}"
              "--pidfile=${processIdPath}"
              "--group=root"
              "--storage-driver=${cfg.storageDriver}"
            ]
            ++ lib.optional cfg.liveRestore "--live-restore"
            ++ cfg.extraOptions
          ))
        ];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "on-failure";
        restart_delay_millis = 2000;
        remain_after_exit = false;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
      dependencies = {
        after = [
          (resultOf "docker-network-readiness" "readiness-resource")
          (resultOf "docker-data-storage" "retained-resource")
          (resultOf "docker-runtime-storage" "retained-resource")
        ];
        before = [];
        requires = [
          (resultOf "docker-data-storage" "retained-resource")
          (resultOf "docker-runtime-storage" "retained-resource")
        ];
        wants = [(resultOf "docker-network-readiness" "readiness-resource")];
      };
      supervision = {
        startup_protocol = "notification";
        notification_access = "main-process";
      };
      readiness = {
        mechanism = "process-signal";
        signal_scope = "main-process";
        timeout_millis = 90000;
      };
      reload = {
        strategy = "signal";
        commands = [];
        signal = "HUP";
        completion = "command-exit";
      };
      termination = {
        signal = "TERM";
        final_signal = "KILL";
        process_id_file = processIdPath;
        send_to_all_processes = false;
      };
      resources = {
        open_files.kind = "unbounded";
        processes.kind = "unbounded";
        tasks.kind = "unbounded";
      };
      storage.mounts = [
        {
          name = "data";
          source = resultOf "docker-data-storage" "planned-path";
          access = "read-write";
        }
        {
          name = "runtime";
          source = resultOf "docker-runtime-storage" "planned-path";
          access = "read-write";
        }
      ];
      logging = {
        standard_output = "structured";
        standard_error = "structured";
        directories = [];
        directory_mode = "0750";
      };
      isolation = {
        privilege = "privileged";
        filesystem = "host";
        network = "host";
        process_visibility = "host";
        termination_scope = "main-process";
        temporary_directory = "shared";
        devices = [];
        host_paths = [];
        permit_core_dumps = true;
      };
    };
  };
  abilityFragments = [dataStorage runtimeStorage networkReadiness service];
  contributions = builtins.map serviceManagement.splitContribution abilityFragments;
in {
  options.aos.services.docker = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Run the Docker container engine.";
    };

    dataRoot = lib.mkOption {
      type = serviceTypes.executionPath;
      default = "/var/lib/docker";
      description = "Absolute directory used for persistent Docker data.";
    };

    storageDriver = lib.mkOption {
      type = abilityTypes.enum ["overlay2" "btrfs" "fuse-overlayfs"];
      default = "overlay2";
      description = "Storage driver used for container layers.";
    };

    liveRestore = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Keep containers running while the daemon is unavailable.";
    };

    extraOptions = lib.mkOption {
      type = abilityTypes.list {
        element = abilityTypes.string {
          maxLength = abilityTypes.limits.maxStringLength;
          syntax = null;
        };
        maxItems = abilityTypes.limits.maxCollectionItems;
      };
      default = [];
      description = "Additional command-line options passed to dockerd.";
    };
  };

  config = lib.mkMerge [
    (lib.mkMerge (
      builtins.map (contribution: {aos.abilities = contribution.declarations;}) contributions
    ))
    (lib.mkIf cfg.enable (lib.mkMerge (
      [{aos.abilities.instances.docker = {};}]
      ++ builtins.map (contribution: {aos.abilities = contribution.configured;}) contributions
    )))
  ];
}
