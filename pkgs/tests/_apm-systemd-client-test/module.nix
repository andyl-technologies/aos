##! Manager-neutral service declarations for service-client integration tests.
{
  config,
  lib,
  ...
}: let
  cfg = config.apm-systemd-client-test;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  inherit (lib.abilities) resultOf;

  command = package: entryPoint: arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {inherit package;};
      entry_point = entryPoint;
      inherit arguments;
    };
    ignore_failure = false;
  };
  coreutilsCommand = entryPoint: arguments:
    command "coreutils" "bin/${entryPoint}" arguments;
  service = name: lifecycle: features:
    serviceManagement.forService {
      inherit serviceTypes;
      consumerInstance = "apm-systemd-client-test";
      declaration =
        {
          service = name;
          # The fixture defines services for explicit manager-client actions.
          # Selecting the package must not start them as a group.
          enabled = false;
          lifecycle =
            {
              environment_files = [];
              condition = [];
              pre_start = [];
              post_start = [];
              stop = [];
              post_stop = [];
              restart_token = null;
              configuration_change_action = "none";
              start_timeout_millis = 90000;
              stop_timeout_millis = 90000;
            }
            // lifecycle;
        }
        // features;
    };

  ok = service "ok" {
    description = "Oneshot service that succeeds";
    execution_model = "oneshot";
    start = [(coreutilsCommand "true" [])];
    restart = "never";
    restart_delay_millis = 0;
    remain_after_exit = true;
  } {};
  fail = service "fail" {
    description = "Oneshot service that fails";
    execution_model = "oneshot";
    start = [(coreutilsCommand "false" [])];
    restart = "never";
    restart_delay_millis = 0;
    remain_after_exit = false;
  } {};
  slow = service "slow" {
    description = "Oneshot service that sleeps for five seconds";
    execution_model = "oneshot";
    start = [(coreutilsCommand "sleep" ["5"])];
    restart = "never";
    restart_delay_millis = 0;
    remain_after_exit = true;
  } {};
  reload =
    service "reload" {
      description = "Long-running service with command-based reload";
      execution_model = "foreground";
      start = [(coreutilsCommand "sleep" ["infinity"])];
      restart = "never";
      restart_delay_millis = 0;
      remain_after_exit = false;
    } {
      reload = {
        strategy = "command";
        commands = [(coreutilsCommand "true" [])];
        signal = null;
        completion = "command-exit";
      };
    };
  notifyReload =
    service "notify-reload" {
      description = "Notification-aware service with signal-based reload";
      execution_model = "foreground";
      start = [
        (command "apm-systemd-client-test" "bin/apm-test-notify-reload" [])
      ];
      restart = "never";
      restart_delay_millis = 0;
      remain_after_exit = false;
    } {
      supervision = {
        startup_protocol = "notification";
        notification_access = "all-processes";
      };
      readiness = {
        mechanism = "process-signal";
        signal_scope = "all-processes";
        timeout_millis = 90000;
      };
      reload = {
        strategy = "signal";
        commands = [];
        signal = "SIGHUP";
        completion = "notification";
      };
    };
  timeout = service "timeout" {
    description = "Oneshot service whose start operation times out";
    execution_model = "oneshot";
    start = [(coreutilsCommand "sleep" ["infinity"])];
    restart = "never";
    restart_delay_millis = 0;
    remain_after_exit = false;
    start_timeout_millis = 2000;
  } {};
  dependency =
    service "dependency" {
      description = "Oneshot service with a failing requirement";
      execution_model = "oneshot";
      start = [(coreutilsCommand "true" [])];
      restart = "never";
      restart_delay_millis = 0;
      remain_after_exit = false;
    } {
      dependencies = {
        after = [(resultOf "fail-lifecycle" "service-resource")];
        before = [];
        requires = [(resultOf "fail-lifecycle" "service-resource")];
        wants = [];
      };
    };
  autorestart = service "autorestart" {
    description = "Failing service with automatic restart";
    execution_model = "foreground";
    start = [(coreutilsCommand "false" [])];
    restart = "always";
    restart_delay_millis = 86400000;
    remain_after_exit = false;
  } {};
  services = [ok fail slow reload notifyReload timeout dependency autorestart];
in {
  options.apm-systemd-client-test.enable = lib.mkOption {
    type = abilityTypes.boolean;
    default = true;
    description = "Expose the manager-neutral service-client test fixtures.";
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (builtins.map
        (fragment: (serviceManagement.splitContribution fragment).declarations)
        services);
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.apm-systemd-client-test = {};}]
        ++ builtins.map
        (fragment: (serviceManagement.splitContribution fragment).configured)
        services
      );
    })
  ];
}
