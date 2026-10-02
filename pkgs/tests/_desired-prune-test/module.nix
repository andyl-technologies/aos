##! Native service declaration for the desired-state pruning fixture.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.desired-prune-test;

  state = config.aos.abilities.filesystem.operations.persistentAllocate.effects."desired-prune-test-state";

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
            path = "${package}/bin/desired-prune-test-start";
            arguments = [state.outputs.path];
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
        source = state.outputs.path;
        access = "read-write";
      }
    ];
  };
in {
  options.desired-prune-test.enable = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = "Enable the desired-state pruning test service.";
  };

  config = lib.mkMerge [
    {
      aos.services."desired-prune-test.main" = serviceDefinition // {enable = cfg.enable;};
    }
    (lib.mkIf cfg.enable {
      aos.abilities.filesystem.operations.persistentAllocate.effects."desired-prune-test-state".lifetime = "persistent";
      aos.abilities.filesystem.operations.persistentAllocate.effects."desired-prune-test-state".input = {
        path = "/var/lib/desired-prune-test";
        mode = "0750";
        owner = "root";
        group = "root";
      };
    })
  ];
}
