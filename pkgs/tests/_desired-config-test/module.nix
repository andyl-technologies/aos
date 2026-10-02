##! Native configuration and service declarations for desired-state sequencing.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.desired-config-test;

  state = config.aos.abilities.filesystem.operations.persistentAllocate.effects."desired-config-test-state";
  token = lib.types.strWith {
    maxLength = 256;
    pattern = "[A-Za-z0-9_.-]+";
  };
  environment = config.aos.abilities.configuration.operations.file.effects.desired-config-test;

  serviceDefinition = {
    lifecycle = {
      description = "AOS desired reconciliation config sequencing test";
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package}/bin/desired-config-test-start";
            arguments = [
              environment.outputs.path
              state.outputs.path
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
    configuration.views = [
      {
        name = "environment";
        source = environment.outputs.path;
        optional = false;
      }
    ];
    storage.mounts = [
      {
        name = "state";
        source = state.outputs.path;
        access = "read-write";
      }
    ];
  };
in {
  options.desired-config-test = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable the desired-state configuration sequencing fixture.";
    };
    token = lib.mkOption {
      type = token;
      default = "desired-token";
      description = "Token written into the managed test configuration.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services."desired-config-test.main" = serviceDefinition // {enable = cfg.enable;};
    }
    (lib.mkIf cfg.enable {
      aos.abilities.filesystem.operations.persistentAllocate.effects."desired-config-test-state".lifetime = "persistent";
      aos.abilities.filesystem.operations.persistentAllocate.effects."desired-config-test-state".input = {
        path = "/var/lib/desired-config-test";
        mode = "0750";
        owner = "root";
        group = "root";
      };
      aos.abilities.configuration.operations.file.effects.desired-config-test.input = {
        path = "/run/aos/fixtures/desired-config-test.env";
        content = "TOKEN=${cfg.token}\n";
        mode = "0444";
      };
    })
  ];
}
