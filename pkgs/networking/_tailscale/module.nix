##! Package-owned Tailscale mesh VPN service declaration.
{
  config,
  lib,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.services.tailscale;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  abilityTypes = lib.abilities.types;
  resultOf = lib.abilities.resultOf;
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "service";
      inherit key interface parameters;
    };
  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/tailscaled";
      inherit arguments;
    };
    ignore_failure = false;
  };
  networkReadiness = producer "network-readiness" serviceManagement.interfaces.networkReadiness {
    scope = "stack-prepared";
    address_families = ["ipv4" "ipv6"];
  };
  tunnelDevice = producer "tunnel-device" serviceManagement.interfaces.devicePresence {
    name = "tunnel";
    device = "/dev/net/tun";
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
      after = [(resultOf "network-readiness" "resource")];
      before = [];
      requires = [];
      wants = [(resultOf "network-readiness" "resource")];
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
        (package: lib.abilities.packageOutput {inherit package;})
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
      network = "host";
      process_visibility = "host";
      termination_scope = "all-processes";
      temporary_directory = "private";
      devices = [
        {
          source = resultOf "tunnel-device" "device-node";
          read = true;
          write = true;
          create_node = false;
        }
      ];
      host_paths = [];
      permit_core_dumps = false;
    };
  };
  producers = [networkReadiness tunnelDevice];
in {
  options.aos.serviceOptionModules.tailscale = lib.mkOption {
    type = lib.types.deferredModule;
    default.options = {
      enable = lib.mkOption {
        type = abilityTypes.boolean;
        default = false;
        description = "Run the Tailscale mesh VPN daemon.";
      };

      port = lib.mkOption {
        type = abilityTypes.integer {
          minimum = 0;
          maximum = 65535;
        };
        default = 41641;
        description = "UDP port used for direct WireGuard peer connections.";
      };

      extraArgs = lib.mkOption {
        type = abilityTypes.list {
          element = abilityTypes.runtimeString;
          maxItems = 256;
        };
        default = [];
        description = "Additional command-line arguments passed to tailscaled.";
      };
    };
  };

  config = lib.mkMerge [
    {aos.services.tailscale = serviceDefinition;}
    (serviceManagement.projectService {
      inherit config lib;
      name = "tailscale";
      consumerInstance = "service";
    })
    (serviceManagement.producerModule {
      inherit config lib producers;
      enabled = cfg.enable;
    })
    (lib.mkIf cfg.enable {
      aos.abilities.runtimeChecks.tailscale = {
        description = "Tailscale service checks";
        checks = [
          {
            name = "tailscale-local-api";
            description = "tailscaled creates its protected local API socket";
            script = ''
              vm.succeed("test -S /run/tailscale/tailscaled.sock")
              vm.wait_until_succeeds(
                  "tailscale --socket=/run/tailscale/tailscaled.sock debug prefs "
                  "| grep -F '\"LoggedOut\": true'",
                  timeout=30,
              )
            '';
          }
        ];
      };
    })
  ];
}
