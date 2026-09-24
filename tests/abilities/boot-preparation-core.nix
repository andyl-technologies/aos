##! Verifies the canonical provider-neutral boot-preparation contracts.
{lib}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  bootPreparation = lib.abilities.interfaces.bootPreparation;
  preparation = bootPreparation.interfaces.preparation;
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
        ];
      }
    ];
  };
  abilities = evaluated.config.aos.abilities;
  authoredSeed = abilities.requests."consumer:configuration-seed";
  policySeedReference = {
    _type = "aos-request-output-reference";
    request = "consumer:policy-seed";
    output = "resource";
  };
in
  assert abilities.interfaces.boot-preparation.name == "aos.boot.preparation";
  assert builtins.attrNames bootPreparation.interfaces == ["preparation"];
  assert preparation.declaration.outputs.resource.lifetime == "transaction";
  assert preparation.declaration.methods.prepare.semantics.requiredTargetAccess == "exclusive-write";
  assert preparation.declaration.methods.observe.semantics.requiredTargetAccess == "read";
  assert authoredSeed.parameters.prerequisites == [policySeedReference];
  assert abilities.requirementTemplates."consumer:boot-preparation".methods
  == ["observe" "prepare"]; true
