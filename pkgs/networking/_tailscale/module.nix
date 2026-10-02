##! Package-owned Tailscale mesh VPN service declaration.
{
  config,
  lib,
  package,
  dependencies,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.services.tailscale;
  network = config.aos.abilities.network.operations.ready.effects.tailscale;
  tunnel = config.aos.abilities.device.operations.present.effects.tailscale;
  command = arguments: {
    executable = {
      path = "${package}/bin/tailscaled";
      inherit arguments;
    };
    ignore_failure = false;
  };
  serviceDefinition = {
    service = "tailscaled";
    policy.hardening = {
      allow_privilege_escalation = false;
      ambient_privileges = ["administer-network" "raw-network"];
      privilege_bounds = {
        kind = "restricted";
        privileges = ["administer-network" "raw-network"];
      };
      resource_control_delegation = false;
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
      memory_pressure_adjustment = 0;
      permit_realtime = true;
      permit_elevated_file_identity = false;
      process_visibility = "all";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      operation_profile = "privileged";
      isolated_identity_mapping = "none";
    };
    lifecycle = {
      description = "Tailscale mesh VPN daemon (${packageName} ${packageVersion})";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        (command ([
            "--state=/var/lib/tailscale/tailscaled.state"
            "--socket=/run/tailscale/tailscaled.sock"
            "--port=${toString cfg.port}"
          ]
          ++ cfg.extraArgs))
      ];
      post_start = [];
      stop = [];
      post_stop = [(command ["--cleanup"])];
      restart = "on-failure";
      restart_delay_millis = 100;
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = [network.outputs.resource];
      before = [];
      requires = [];
      wants = [network.outputs.resource];
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
    environment = {
      variables = {};
      search_path =
        builtins.map
        (name: dependencies.${name}.path)
        ["getent" "iproute2" "iptables" "procps-ng"];
    };
    directories.managed = [
      {
        path = "tailscale";
        purpose = "runtime";
        mode = "0755";
        retention = "restart";
      }
      {
        path = "tailscale";
        purpose = "state";
        mode = "0700";
        retention = "persistent";
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
      filesystem = "read-only-system";
      home_access = "inaccessible";
      network = "host";
      process_visibility = "host";
      termination_scope = "all-processes";
      temporary_directory = "private";
      devices = [
        {
          source = tunnel.outputs.resource;
          read = true;
          write = true;
          create_node = false;
        }
      ];
      host_paths = [];
      permit_core_dumps = false;
    };
  };
in {
  options.aos.services = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.submodule ({name, ...}: {
      options = lib.optionalAttrs (name == "tailscale") {
        port = lib.mkOption {
          type = lib.types.ints.between 0 65535;
          default = 41641;
          description = "UDP port used for direct WireGuard peer connections.";
        };

        extraArgs = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [];
          description = "Additional command-line arguments passed to tailscaled.";
        };
      };
    }));
    default = {};
  };

  config = lib.mkMerge [
    {aos.services.tailscale = lib.mkDefault serviceDefinition;}
    (lib.mkIf cfg.enable {
      system.checks.tailscale = import ./runtime-tests.nix {inherit cfg;};
      aos.abilities = {
        network.operations.ready.effects.tailscale.input = {
          scope = "stack-prepared";
          families = ["ipv4" "ipv6"];
        };
        device.operations.present.effects.tailscale.input.path = "/dev/net/tun";
      };
    })
  ];
}
