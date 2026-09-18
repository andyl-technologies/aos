##! Native configuration and service declarations for desired-state sequencing.
{
  config,
  lib,
  ...
}: let
  cfg = config.desired-config-test;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  inherit (lib.abilities) resultOf;

  token = abilityTypes.refined {
    name = "desired-state test token";
    description = "a non-empty environment value containing letters, digits, dots, underscores, or dashes";
    type = abilityTypes.string {
      maxLength = 256;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[A-Za-z0-9_.-]+";
      }
    ];
  };

  state = serviceManagement.forProducer {
    consumerInstance = "desired-config-test";
    key = "state";
    interface = serviceManagement.interfaces.persistentStorageAllocation;
    parameters = {
      name = "state";
      purpose = "state";
      mode = "0750";
    };
  };
  environment = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "desired-config-test";
    declaration = {
      name = "environment";
      source = {
        kind = "interpolated-text";
        fragments = [
          {
            kind = "literal";
            text = "TOKEN=${cfg.token}\n";
          }
        ];
        maximum_size_bytes = 4096;
      };
      mode = "0444";
    };
  };
  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "desired-config-test";
    declaration = {
      service = "main";
      enabled = true;
      lifecycle = {
        description = "AOS desired reconciliation config sequencing test";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {};
              entry_point = "bin/desired-config-test-start";
              arguments = [
                (resultOf "environment" "planned-path")
                (resultOf "state" "planned-path")
              ];
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
      configuration.views = [
        {
          name = "environment";
          source = resultOf "environment" "planned-path";
          optional = false;
        }
      ];
      storage.mounts = [
        {
          name = "state";
          source = resultOf "state" "planned-path";
          access = "read-write";
        }
      ];
    };
  };
  fragments = [state environment service];
in {
  options.desired-config-test = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
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
      aos.abilities = lib.mkMerge (builtins.map
        (fragment: (serviceManagement.splitContribution fragment).declarations)
        fragments);
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.desired-config-test = {};}]
        ++ builtins.map
        (fragment: (serviceManagement.splitContribution fragment).configured)
        fragments
      );
    })
  ];
}
