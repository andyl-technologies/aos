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
    featureRequests = [
      (serviceManagement.featureRequest {
        key = "hardening";
        requirementAlias = "service-hardening";
        description = "Requires the selected service-management provider to enforce the declared service hardening policy.";
        interface = "aos.service.hardening";
        abi = 1;
        parameters = {
          allow_privilege_escalation = true;
          ambient_privileges = [];
          privilege_bounds.kind = "unrestricted";
          resource_control_delegation = true;
          resource_control_access = "host";
          device_access_scope = "shared";
          host_clock_mutation = true;
          host_name_mutation = true;
          operating_system_log_access = true;
          operating_system_extension_access = true;
          operating_system_tunable_access = true;
          lock_execution_personality = false;
          writable_executable_memory = true;
          isolation_domains = [];
          network_families = ["ipv4" "ipv6" "route-control" "raw-packet" "local"];
          memory_pressure_adjustment = -500;
          permit_realtime = true;
          permit_elevated_file_identity = true;
          process_visibility = "all";
          operation_architectures = [];
          operation_allow = [];
          operation_deny = [];
          operation_profile = "privileged";
          isolated_identity_mapping = "none";
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
          (resultOf "docker-network-readiness" "resource")
          (resultOf "docker-data-storage" "resource")
          (resultOf "docker-runtime-storage" "resource")
        ];
        before = [];
        requires = [
          (resultOf "docker-data-storage" "resource")
          (resultOf "docker-runtime-storage" "resource")
        ];
        wants = [(resultOf "docker-network-readiness" "resource")];
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
  definitions = builtins.map serviceManagement.splitDefinition abilityFragments;
in {
  options.aos.serviceOptionModules.docker = lib.mkOption {
    type = lib.types.deferredModule;
    default.options = {
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
  };

  config = lib.mkMerge [
    (lib.mkMerge (
      builtins.map (definition: {aos.abilities = definition.declarations;}) definitions
    ))
    (lib.mkIf cfg.enable (lib.mkMerge (
      [
        {
          aos.abilities.instances.docker = {};
          aos.abilities.runtimeChecks.docker = {
            description = "Docker service checks";
            checks = [
              {
                name = "docker-api";
                description = "The Docker CLI reaches the local daemon and plugins";
                script = ''
                  vm.wait_until_succeeds(
                      "docker version --format '{{.Server.Version}}'", timeout=60
                  )
                  vm.succeed("docker info --format '{{.Driver}}' | grep -Fx '${cfg.storageDriver}'")
                  vm.succeed("docker buildx version")
                  vm.succeed("docker compose version")
                '';
              }
            ];
          };
        }
      ]
      ++ builtins.map (definition: {aos.abilities = definition.configured;}) definitions
    )))
  ];
}
