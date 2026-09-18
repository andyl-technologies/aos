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
  inherit (lib.abilities) resultOf;
  ingress = serviceManagement.forProducer {
    consumerInstance = "test-http-server";
    key = "ingress";
    interface = lib.abilities.interfaces.networkPolicy.interfaces.ingress;
    methods = ["observe"];
    parameters = {
      endpoints = [
        {
          transport = "tcp";
          port = cfg.port;
        }
      ];
      prerequisites = [];
    };
  };

  content = serviceManagement.forProducer {
    consumerInstance = "test-http-server";
    key = "content";
    interface = serviceManagement.interfaces.persistentStorageAllocation;
    parameters = {
      name = "content";
      purpose = "state";
      mode = "0755";
    };
  };

  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "test-http-server";
    declaration = {
      service = "main";
      enabled = true;
      lifecycle =
        {
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
                arguments = [
                  "--port=${builtins.toString cfg.port}"
                  (resultOf "content" "planned-path")
                ];
              };
              ignore_failure = false;
            }
          ];
          post_start = [];
          stop = [];
          post_stop = [];
          restart = "on-failure";
          restart_delay_millis = 1000;
          configuration_change_action = "restart";
          remain_after_exit = false;
          start_timeout_millis = 90000;
          stop_timeout_millis = 90000;
        }
        // lib.optionalAttrs (cfg.restartToken != null) {
          restart_token = cfg.restartToken;
        };
      storage.mounts = [
        {
          name = "content";
          source = resultOf "content" "planned-path";
          access = "read-write";
        }
      ];
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
      dependencies = let
        readiness = resultOf "ingress" "resource";
      in {
        prerequisites = [readiness];
        after = [readiness];
        before = [];
        requires = [readiness];
        wants = [];
      };
    };
  };
  fragments = [content ingress service];
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
    {
      aos.abilities = lib.mkMerge (builtins.map
        (fragment: (serviceManagement.splitContribution fragment).declarations)
        fragments);
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.test-http-server = {};}]
        ++ builtins.map
        (fragment: (serviceManagement.splitContribution fragment).configured)
        fragments
      );
    })
  ];
}
