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
  serviceTypes = serviceManagement.types;
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
  service = serviceManagement.forService {
    featureContributions = [
      (serviceManagement.featureContribution {
        key = "linux_isolation";
        requirementAlias = "linux-service-isolation";
        description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
        interface = "aos.platform.linux.service-isolation";
        abi = 1;
        parameters = {
          allow_privilege_escalation = false;
          ambient_capabilities = ["CAP_NET_ADMIN" "CAP_NET_RAW"];
          capability_bounds = {
            kind = "restricted";
            capabilities = ["CAP_NET_ADMIN" "CAP_NET_RAW"];
          };
          control_group_delegation = false;
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
          oom_score_adjust = 0;
          permit_realtime = true;
          permit_suid_sgid = false;
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
    consumerInstance = "service";
    declaration = {
      service = "tailscaled";
      enabled = true;
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
  };
  contributions = builtins.map serviceManagement.splitContribution [
    networkReadiness
    tunnelDevice
    service
  ];
in {
  options.aos.services.tailscale = {
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

  config = lib.mkMerge [
    (lib.mkMerge (builtins.map
      (contribution: {aos.abilities = contribution.declarations;})
      contributions))
    (lib.mkIf cfg.enable (lib.mkMerge (
      [{aos.abilities.instances.service = {};}]
      ++ builtins.map
      (contribution: {aos.abilities = contribution.configured;})
      contributions
    )))
  ];
}
