##! Verifies the canonical provider-neutral boot-preparation contracts.
{lib}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  bootPreparation = lib.abilities.interfaces.bootPreparation;
  preparation = bootPreparation.interfaces.preparation;
  handoff = bootPreparation.interfaces.handoff;
  prepare = key: prerequisites:
    serviceManagement.forProducer {
      consumerInstance = "host";
      inherit key;
      interface = preparation;
      methods = ["observe" "prepare"];
      parameters = {
        execution = {
          artifact = lib.abilities.packageOutput {};
          entry_point = "libexec/${key}";
          arguments = [];
        };
        inherit prerequisites;
      };
    };
  handoffRequest = serviceManagement.forProducer {
    consumerInstance = "host";
    key = "boot-preparation-handoff";
    interface = handoff;
    methods = ["observe" "receive"];
    parameters = {
      source_stage = "initrd";
      receiver_stage = "host";
      completion = lib.abilities.resultOf "configuration-seed" "resource";
      preparations = [
        (lib.abilities.resultOf "configuration-seed" "resource")
        (lib.abilities.resultOf "policy-seed" "resource")
      ];
      preserved_mounts = [];
      durable_state_roots = [];
    };
  };
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      ../../modules/abilities/default.nix
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
          (prepare "policy-seed" [])
          (prepare "configuration-seed" [
            (lib.abilities.resultOf "policy-seed" "resource")
          ])
          handoffRequest
        ];
      }
    ];
  };
  abilities = evaluated.config.aos.abilities;
  authoredHandoff = abilities.requests."consumer:boot-preparation-handoff";
  authoredSeed = abilities.requests."consumer:configuration-seed";
  policySeedReference = {
    _type = "aos-request-output-reference";
    request = "consumer:policy-seed";
    output = "resource";
  };
  literalPreparationKeys = builtins.tryEval (builtins.deepSeq
    (
      lib.evalModules {
        modules = [
          {
            options.request = lib.mkOption {type = handoff.requestType;};
            config.request = {
              source_stage = "initrd";
              receiver_stage = "host";
              completion = lib.abilities.resultOf "configuration-seed" "resource";
              preparations = ["configuration-seed" "policy-seed"];
              preserved_mounts = [];
              durable_state_roots = [];
            };
          }
        ];
      }
    )
    .config
    .request
    true);
in
  assert abilities.interfaces.boot-preparation.name == "aos.boot.preparation";
  assert abilities.interfaces.boot-preparation-handoff.name == "aos.boot.preparation-handoff";
  assert preparation.declaration.outputs.resource.lifetime == "transaction";
  assert handoff.declaration.outputs.resource.lifetime == "transaction";
  assert preparation.declaration.methods.prepare.semantics.requiredTargetAccess == "exclusive-write";
  assert preparation.declaration.methods.observe.semantics.requiredTargetAccess == "read";
  assert handoff.declaration.methods.receive.semantics.requiredTargetAccess == "exclusive-write";
  assert authoredSeed.parameters.prerequisites == [policySeedReference];
  assert authoredHandoff.parameters.preparations
  == [
    {
      _type = "aos-request-output-reference";
      request = "consumer:configuration-seed";
      output = "resource";
    }
    policySeedReference
  ];
  assert !literalPreparationKeys.success;
  assert abilities.requirementTemplates."consumer:boot-preparation".methods
  == ["observe" "prepare"];
  assert abilities.requirementTemplates."consumer:boot-preparation-handoff".methods
  == ["observe" "receive"]; true
