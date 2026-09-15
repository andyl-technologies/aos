##! Native service declaration for the static-cache integration fixture.
{
  config,
  lib,
  ...
}: let
  cfg = config.test-static-cache-server;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  inherit (lib.abilities) resultOf;

  content = serviceManagement.forProducer {
    consumerInstance = "test-static-cache-server";
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
    consumerInstance = "test-static-cache-server";
    declaration = {
      service = "main";
      enabled = true;
      lifecycle = {
        description = "AOS static cache test HTTP server";
        execution_model = "foreground";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {};
              entry_point = "bin/test-static-cache-server";
              arguments = [
                (resultOf "content" "storage-path")
                (builtins.toString cfg.port)
              ];
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
      storage.mounts = [
        {
          name = "content";
          source = resultOf "content" "storage-path";
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
    };
  };
  fragments = [content service];
in {
  options.test-static-cache-server = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Enable the static-cache integration fixture.";
    };
    port = lib.mkOption {
      type = abilityTypes.integer {
        minimum = 1;
        maximum = 65535;
      };
      default = 8000;
      description = "TCP port on which the static cache listens.";
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
        [{instances.test-static-cache-server = {};}]
        ++ builtins.map
        (fragment: (serviceManagement.splitContribution fragment).configured)
        fragments
      );
    })
  ];
}
