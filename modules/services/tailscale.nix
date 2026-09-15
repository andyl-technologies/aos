##! modules/services/tailscale.nix — Tailscale mesh VPN service
##!
##! Runs tailscaled with persistent node identity under /var/lib/tailscale and
##! its local API socket under /run/tailscale. Enrollment remains an explicit
##! operator action through the tailscale up command.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.services.tailscale;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "system:tailscale";
      inherit key interface parameters;
    };
  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {package = "tailscale";};
      entry_point = "bin/tailscaled";
      inherit arguments;
    };
    ignore_failure = false;
  };
  abilityFragments = [
    (producer "tailscale-network-readiness" serviceManagement.interfaces.networkReadiness {
      scope = "stack-prepared";
      address_families = ["ipv4" "ipv6"];
    })
    (producer "tailscale-tun-device" serviceManagement.interfaces.devicePresence {
      name = "tunnel";
      device = "/dev/net/tun";
    })
    (serviceManagement.forService {
      inherit serviceTypes;
      consumerInstance = "system:tailscale";
      declaration = {
        service = "tailscaled";
        enabled = true;
        lifecycle = {
          description = "Tailscale mesh VPN daemon";
          execution_model = "foreground";
          environment_files = [];
          condition = [];
          pre_start = [];
          start = [(command ([
              "--state=/var/lib/tailscale/tailscaled.state"
              "--socket=/run/tailscale/tailscaled.sock"
              "--port=${toString cfg.port}"
            ]
            ++ cfg.extraArgs))];
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
          after = [(resultOf "tailscale-network-readiness" "readiness-resource")];
          before = [];
          requires = [];
          wants = [(resultOf "tailscale-network-readiness" "readiness-resource")];
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
          search_path = builtins.map
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
          devices = [{
            source = resultOf "tailscale-tun-device" "device-node";
            read = true;
            write = true;
            create_node = false;
          }];
          host_paths = [];
          permit_core_dumps = false;
        };
        linux_isolation = {
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
      };
    })
  ];
in {
  options.aos.services.tailscale = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Run the Tailscale mesh VPN daemon.";
    };

    port = lib.mkOption {
      type = lib.types.int;
      default = 41641;
      description = "UDP port used for direct WireGuard peer connections.";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Additional command-line arguments passed to tailscaled.";
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge ([
    {
      assertions = [
        {
          assertion = cfg.port >= 0 && cfg.port <= 65535;
          message = "aos.services.tailscale.port must be between 0 and 65535";
        }
      ];

      environment.systemPackages = [
        pkgs.tailscale
        pkgs.getent
        pkgs.iproute2
        pkgs.iptables
        pkgs.procps-ng
      ];

      aos.abilities.instances."system:tailscale" = {};

      system.checks.tailscale = {
        description = "Tailscale service checks";
        checks = [
          {
            name = "tailscaled-active";
            description = "tailscaled reaches its ready state";
            script = ''
              vm.wait_until_succeeds(
                  "systemctl is-active --quiet tailscaled.service", timeout=30
              )
            '';
          }
          {
            name = "tailscale-local-api";
            description = "tailscaled creates its protected local API socket";
            script = ''
              vm.succeed("test -S /run/tailscale/tailscaled.sock")
              vm.succeed(
                  "tailscale --socket=/run/tailscale/tailscaled.sock debug prefs "
                  "| grep -F '\"LoggedOut\": true'"
              )
            '';
          }
        ];
      };
    }
  ] ++ builtins.map (fragment: {aos.abilities = fragment;}) abilityFragments));
}
