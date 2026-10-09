##! Selects package group producers consumed by image-projected services.
{
  config,
  lib,
}: let
  services = lib.filterAttrs (_: service: service.enable && (service.bootstrap || service.activationOwner != "ability")) config.aos.services;
  effects = config.aos.abilities.serviceManagement.operations.resourceGroup.effects;
  references = builtins.filter builtins.isAttrs (builtins.map (service: (service.resources or {}).resource_group or null) (builtins.attrValues services));
  producerFor = reference: let
    identity = reference.identity or [];
    name = lib.last identity;
    producer = effects.${name} or null;
    validReference =
      lib.types.effectOutput.check reference
      && builtins.length identity >= 4
      && reference.output == "name"
      && builtins.elemAt identity (builtins.length identity - 3) == "serviceManagement"
      && builtins.elemAt identity (builtins.length identity - 2) == "resourceGroup";
    namespace = "aos-pkg-${producer.contract.owner}";
    ownsName = producer.input.name == namespace || lib.hasPrefix "${namespace}-" producer.input.name;
  in
    if !validReference
    then throw "An early service resource group must reference serviceManagement.resourceGroup.outputs.name."
    else if producer == null || !producer.enable || producer.contract.identity != identity || producer.outputs.name.schema != reference.schema
    then throw "An early service resource group refers to an absent or incompatible producer."
    else if !ownsName
    then throw "An early service resource group lies outside its declaring package's namespace."
    else {
      inherit name;
      value = {
        inherit identity;
        input = {
          inherit (producer.input) name description;
          bootstrap = true;
        };
      };
    };
in
  builtins.listToAttrs (builtins.map producerFor references)
