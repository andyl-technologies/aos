##! Native service declaration for the test HTTP server.
{
  config,
  lib,
  ...
}: let
  cfg = config.test-http-server;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;

  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "test-http-server";
    declaration = {
      service = "main";
      enabled = true;
      lifecycle = {
        description = "AOS test HTTP server";
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {};
              entry_point = "bin/test-http-server";
              arguments = [builtins.toString cfg.port];
            };
            ignore_failure = false;
          }
        ];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "on-failure";
        restart_token = cfg.restartToken;
        restart_delay_millis = 1000;
        configuration_change_action = "restart";
        remain_after_exit = false;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
      isolation = {
        privilege = "unprivileged";
        filesystem = "read-only-software";
        network = "host";
        process_visibility = "private";
        termination_scope = "all-processes";
        temporary_directory = "private";
        devices = [];
        host_paths = [];
        permit_core_dumps = false;
      };
    };
  };
in {
  options.test-http-server = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Enable the test HTTP server.";
    };
    port = lib.mkOption {
      type = abilityTypes.integer {
        minimum = 1;
        maximum = 65535;
      };
      default = 8000;
      description = "TCP port on which the test server listens.";
    };
    restartToken = lib.mkOption {
      type = abilityTypes.optional serviceTypes.restartToken;
      default = null;
      description = "Operator-controlled token whose change requests a restart.";
    };
  };

  config = lib.mkMerge [
    {aos.abilities = (serviceManagement.splitContribution service).declarations;}
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge [
        {instances.test-http-server = {};}
        (serviceManagement.splitContribution service).configured
      ];
    })
  ];
}
