##! Native service declaration for the argument-preservation fixture.
{
  config,
  lib,
  ...
}: let
  cfg = config.landlock-argv-test;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  inherit (lib.abilities) resultOf;

  state = serviceManagement.forProducer {
    consumerInstance = "landlock-argv-test";
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
    consumerInstance = "landlock-argv-test";
    declaration = {
      service = "main";
      enabled = true;
      lifecycle = {
        description = "AOS argument preservation test";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {};
              entry_point = "bin/landlock-argv-test-recorder";
              arguments = [
                (resultOf "state" "storage-path")
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
          source = resultOf "state" "storage-path";
          access = "read-write";
        }
      ];
    };
  };
  fragments = [state service];
in {
  options.landlock-argv-test.enable = lib.mkOption {
    type = lib.abilities.types.boolean;
    default = true;
    description = "Enable the argument-preservation test service.";
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (builtins.map
        (fragment: (serviceManagement.splitContribution fragment).declarations)
        fragments);
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.landlock-argv-test = {};}]
        ++ builtins.map
        (fragment: (serviceManagement.splitContribution fragment).configured)
        fragments
      );
    })
  ];
}
