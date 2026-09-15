##! Native credential-consumer declaration used by fleet integration tests.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos-secret-reference-test;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  inherit (lib.abilities) resultOf;

  defaultCredentialProvider = lib.abilities.instanceId {
    environment = lib.abilities.environmentId {
      authority = "deployment";
      key = "aos-secret-reference-test";
      stage = "host";
    };
    key = "system-credentials";
  };
  defaultCredential = lib.abilities.resourceReference {
    interface = serviceManagement.interfaces.credentialDelivery.identity;
    resource = {
      provider = defaultCredentialProvider;
      key = "bootstrap-token";
    };
    operations = ["observe"];
    lifetime = "persistent";
  };
  state = serviceManagement.forProducer {
    consumerInstance = "aos-secret-reference-test";
    key = "state";
    interface = serviceManagement.interfaces.persistentStorageAllocation;
    parameters = {
      name = "state";
      purpose = "state";
      mode = "0700";
    };
  };
  credential = serviceManagement.forProducer {
    consumerInstance = "aos-secret-reference-test";
    key = "join-token";
    interface = serviceManagement.interfaces.credentialDelivery;
    parameters = {
      name = "join-token";
      source = cfg.credential;
      encrypted = cfg.encrypted;
    };
  };
  service = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "aos-secret-reference-test";
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
              entry_point = "bin/aos-secret-reference-test-consumer";
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
  fragments = [state credential service];
in {
  options.aos-secret-reference-test = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Enable the credential-delivery integration fixture.";
    };
    credential = lib.mkOption {
      type = abilityTypes.resourceReference;
      default = defaultCredential;
      description = "Credential resource delivered to the test consumer.";
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
        [{instances.aos-secret-reference-test = {};}]
        ++ builtins.map
        (fragment: (serviceManagement.splitContribution fragment).configured)
        fragments
      );
    })
  ];
}
