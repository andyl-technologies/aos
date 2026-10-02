##! Package-owned Docker daemon configuration and service requirements.
##!
##! Runs the source-built Docker daemon with persistent graph storage under
##! `/var/lib/docker` and its local API socket under `/run/docker.sock`.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.services.docker;
  dataRoot = cfg.dataRoot;
  runtimeRoot = "/run/docker";
  socketPath = "${builtins.dirOf runtimeRoot}/docker.sock";
  processIdPath = "${runtimeRoot}/docker.pid";
  directories = config.aos.abilities.filesystem.operations.directory.effects;
  network = config.aos.abilities.network.operations.ready.effects;

  command = arguments: {
    executable = {
      path = "${package}/bin/dockerd";
      inherit arguments;
    };
    ignore_failure = false;
  };
  service = {
    policy.hardening = {
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
        network.docker.outputs.resource
        directories.docker-data.outputs.resource
        directories.docker-runtime.outputs.resource
      ];
      before = [];
      requires = [
        directories.docker-data.outputs.resource
        directories.docker-runtime.outputs.resource
      ];
      wants = [network.docker.outputs.resource];
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
        source = directories.docker-data.outputs.path;
        access = "read-write";
      }
      {
        name = "runtime";
        source = directories.docker-runtime.outputs.path;
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
in {
  options.aos.services = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.submodule ({name, ...}: {
      options = lib.optionalAttrs (name == "docker") {
        dataRoot = lib.mkOption {
          type = lib.types.strMatching "/.*";
          default = "/var/lib/docker";
          description = "Absolute directory used for persistent Docker data.";
        };

        storageDriver = lib.mkOption {
          type = lib.types.enum ["overlay2" "btrfs" "fuse-overlayfs"];
          default = "overlay2";
          description = "Storage driver used for container layers.";
        };

        liveRestore = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Keep containers running while the daemon is unavailable.";
        };

        extraOptions = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [];
          description = "Additional command-line options passed to dockerd.";
        };
      };
    }));
    default = {};
  };

  config = lib.mkMerge [
    {aos.services.docker = lib.mkDefault service;}
    (lib.mkIf cfg.enable {
      system.checks.docker = import ./runtime-tests.nix {inherit cfg;};
      aos.abilities = {
        filesystem.operations.directory.effects = {
          docker-data = {
            lifetime = "persistent";
            input = {
              path = dataRoot;
              mode = "0710";
            };
          };
          docker-runtime.input = {
            path = runtimeRoot;
            mode = "0755";
          };
        };
        network.operations.ready.effects.docker.input = {
          scope = "address-configured";
          families = ["ipv4" "ipv6"];
        };
      };
    })
  ];
}
