##! Native credential-consumer declaration used by fleet integration tests.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.aos-credential-delivery-test;

  state = config.aos.abilities.filesystem.operations.persistentAllocate.effects."aos-credential-delivery-test-state";
  credential = config.aos.abilities.credential.operations.deliver.effects.aos-credential-delivery-test;

  serviceDefinition = {
    manager_identity = {
      name = "aos-credential-delivery-test";
      aliases = [];
    };
    lifecycle = {
      description = "System credential consumer";
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package}/bin/aos-credential-delivery-test-consumer";
            arguments = [
              credential.outputs.path
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
      restart_token = cfg.restartToken;
      restart_delay_millis = 0;
      configuration_change_action = "restart";
      remain_after_exit = true;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    credentials.views = [
      {
        name = "join-token";
        reference = credential.outputs.path;
        encrypted = false;
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
  options.aos-credential-delivery-test = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable the credential-delivery integration fixture.";
    };
    credentialName = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z0-9._-]+";
      default = "bootstrap-token";
      description = "Logical system credential name resolved before delivery.";
    };
    encrypted = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether the credential requires encrypted delivery.";
    };
    restartToken = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Operator-controlled token whose change requests a restart.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services."aos-credential-delivery-test.main" = serviceDefinition // {enable = cfg.enable;};
    }
    (lib.mkIf cfg.enable {
      aos.abilities.filesystem.operations.persistentAllocate.effects."aos-credential-delivery-test-state".lifetime = "persistent";
      aos.abilities.filesystem.operations.persistentAllocate.effects."aos-credential-delivery-test-state".input = {
        path = "/var/lib/aos-credential-delivery-test";
        mode = "0700";
        owner = "root";
        group = "root";
      };
      aos.abilities.credential.operations.deliver.effects.aos-credential-delivery-test.input = {
        name = cfg.credentialName;
        scope = "system";
        encrypted = cfg.encrypted;
      };
    })
  ];
}
