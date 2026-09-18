##! Native service declaration for the desired-state pruning fixture.
{
  config,
  lib,
  ...
}: let
  cfg = config.desired-prune-test;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  inherit (lib.abilities) resultOf;

  state = serviceManagement.forProducer {
    consumerInstance = "desired-prune-test";
    key = "state";
    interface = serviceManagement.interfaces.persistentStorageAllocation;
    parameters = {
      name = "state";
      purpose = "state";
      mode = "0750";
    };
  };
  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "desired-prune-test";
    declaration = {
      service = "main";
      enabled = true;
      lifecycle = {
        description = "AOS desired reconciliation prune test";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {};
              entry_point = "bin/desired-prune-test-start";
              arguments = [(resultOf "state" "planned-path")];
            };
            ignore_failure = false;
          }
        ];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "never";
        restart_token = null;
        restart_delay_millis = 0;
        configuration_change_action = "restart";
        remain_after_exit = true;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
      storage.mounts = [
        {
          name = "state";
          source = resultOf "state" "planned-path";
          access = "read-write";
        }
      ];
    };
  };
  fragments = [state service];
in {
  options.desired-prune-test.enable = lib.mkOption {
    type = lib.abilities.types.boolean;
    default = true;
    description = "Enable the desired-state pruning test service.";
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (builtins.map
        (fragment: (serviceManagement.splitContribution fragment).declarations)
        fragments);
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.desired-prune-test = {};}]
        ++ builtins.map
        (fragment: (serviceManagement.splitContribution fragment).configured)
        fragments
      );
    })
  ];
}
