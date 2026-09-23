##! Native service declaration for the desired-state pruning fixture.
{
  config,
  lib,
  ...
}: let
  cfg = config.desired-prune-test;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
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
  serviceDefinition = {
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
  producers = [state];
in {
  options.desired-prune-test.enable = lib.mkOption {
    type = lib.abilities.types.boolean;
    default = true;
    description = "Enable the desired-state pruning test service.";
  };

  config = lib.mkMerge [
    {
      aos.services."desired-prune-test.main" = serviceDefinition // {enable = cfg.enable;};
    }
    (serviceManagement.projectService {
      inherit config lib;
      name = "desired-prune-test.main";
    })
    (serviceManagement.producerModule {
      inherit config lib producers;
      enabled = cfg.enable;
    })
  ];
}
