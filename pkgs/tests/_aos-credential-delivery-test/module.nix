##! Native credential-consumer declaration used by fleet integration tests.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos-credential-delivery-test;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  inherit (lib.abilities) resultOf;

  state = serviceManagement.forProducer {
    consumerInstance = "aos-credential-delivery-test";
    key = "state";
    interface = serviceManagement.interfaces.persistentStorageAllocation;
    parameters = {
      name = "state";
      purpose = "state";
      mode = "0700";
    };
  };
  credentialSource = serviceManagement.forProducer {
    consumerInstance = "aos-credential-delivery-test";
    key = "join-token-source";
    interface = serviceManagement.interfaces.namedCredential;
    parameters = {
      name = cfg.credentialName;
      scope = "system";
    };
  };
  credential = serviceManagement.forProducer {
    consumerInstance = "aos-credential-delivery-test";
    key = "join-token";
    interface = serviceManagement.interfaces.credentialDelivery;
    parameters = {
      name = "join-token";
      source = resultOf "join-token-source" "credential-resource";
      encrypted = cfg.encrypted;
    };
  };
  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "aos-credential-delivery-test";
    declaration = {
      service = "main";
      enabled = true;
      lifecycle = {
        description = "System credential consumer";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [
          {
            executable = {
              artifact = lib.abilities.packageOutput {};
              entry_point = "bin/aos-credential-delivery-test-consumer";
              arguments = [
                (resultOf "join-token" "credential-path")
                (resultOf "state" "storage-path")
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
          reference = resultOf "join-token" "credential-path";
          encrypted = cfg.encrypted;
          optional = false;
        }
      ];
      storage.mounts = [
        {
          name = "state";
          source = resultOf "state" "storage-path";
          access = "read-write";
        }
      ];
    };
  };
  fragments = [state credentialSource credential service];
in {
  options.aos-credential-delivery-test = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Enable the credential-delivery integration fixture.";
    };
    credentialName = lib.mkOption {
      type = abilityTypes.localKey;
      default = "bootstrap-token";
      description = "Logical system credential name resolved before delivery.";
    };
    encrypted = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Whether the credential requires encrypted delivery.";
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
        [{instances.aos-credential-delivery-test = {};}]
        ++ builtins.map
        (fragment: (serviceManagement.splitContribution fragment).configured)
        fragments
      );
    })
  ];
}
