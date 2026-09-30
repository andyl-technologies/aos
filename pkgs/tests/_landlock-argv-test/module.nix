##! Native service declaration for the argument-preservation fixture.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.landlock-argv-test;

  state = config.aos.abilities.filesystem.operations.persistentAllocate.effects."landlock-argv-test-state";

  serviceDefinition = {
    lifecycle = {
      description = "AOS argument preservation test";
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package}/bin/landlock-argv-test-recorder";
            arguments = [
              state.outputs.path
              "plain"
              "two words"
              "semi;colon"
              ''quote"inner''
              "colon:value"
            ];
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
  options.landlock-argv-test.enable = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = "Enable the argument-preservation test service.";
  };

  config = lib.mkMerge [
    {
      aos.services."landlock-argv-test.main" = serviceDefinition // {enable = cfg.enable;};
    }
    (lib.mkIf cfg.enable {
      aos.abilities.filesystem.operations.persistentAllocate.effects."landlock-argv-test-state".lifetime = "persistent";
      aos.abilities.filesystem.operations.persistentAllocate.effects."landlock-argv-test-state".input = {
        path = "/var/lib/landlock-argv-test";
        mode = "0750";
        owner = "root";
        group = "root";
      };
    })
  ];
}
