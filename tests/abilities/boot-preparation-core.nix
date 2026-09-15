##! Verifies the canonical provider-neutral boot-preparation handoff contract.
{lib}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  bootPreparation = lib.abilities.interfaces.bootPreparation;
  request = serviceManagement.forProducer {
    consumerInstance = "host";
    key = "boot-preparation";
    interface = {
      alias = bootPreparation.interfaceAlias;
      declaration = bootPreparation.declaration;
    };
    methods = ["observe" "receive"];
    parameters = {
      source_stage = "initrd";
      receiver_stage = "host";
      preparations = ["configuration-seed" "credential-recovery"];
    };
  };
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        aos.abilities.environment = {
          authority = "test";
          key = "boot-preparation";
          stage = "host";
        };
      }
    ];
    packageModules = [
      {
        name = "consumer";
        module.config.aos.abilities = lib.mkMerge [
          {instances.host = {};}
          request
        ];
      }
    ];
  };
  abilities = evaluated.config.aos.abilities;
  authored = abilities.requests."consumer:boot-preparation";
  interface = abilities.interfaces.boot-preparation-handoff;
in
  assert interface.name == "aos.boot.preparation-handoff";
  assert interface.lifecycle.stableResourceIdentity;
  assert interface.lifecycle.releasesEphemeralOnDisable == false;
  assert interface.outputs.readiness-resource.lifetime == "transaction";
  assert interface.methods.receive.semantics.requiredTargetAccess == "exclusive-write";
  assert interface.methods.observe.semantics.requiredTargetAccess == "read";
  assert authored.parameters.preparations == ["configuration-seed" "credential-recovery"];
  assert abilities.requirementTemplates."consumer:boot-preparation-handoff".methods
  == ["observe" "receive"]; true
