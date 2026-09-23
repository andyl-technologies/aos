##! Composes the typed service option tree from domain modules.
##!
##! Packages extend the same `aos.services` submodule type with ordinary option
##! declarations, so the domain and package fields share one fixed point.
{lib, ...}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  servicePolicy = lib.abilities.interfaces.servicePolicy;
  serviceFields =
    builtins.removeAttrs
    serviceManagement.types.serviceDeclarationFields
    ["service" "enabled"];
  featureModuleFor = name: definition: let
    fieldType =
      if definition ? type
      then definition.type
      else definition;
  in {
    options.${name} = lib.mkOption {
      type =
        if name == "lifecycle"
        then lib.abilities.types.optional fieldType
        else fieldType;
      default = null;
      description = serviceManagement.featureInterfaces.${name}.declaration.description;
    };
  };
  policyFields = {
    hardening = servicePolicy.types.settings.hardeningSettings;
    devicePolicy = servicePolicy.types.settings.devicePolicySettings;
    runtimeConditions = servicePolicy.types.settings.runtimeConditionSettings;
  };
  policyModule = {
    options.policy =
      builtins.mapAttrs
      (name: fieldType:
        lib.mkOption {
          type = lib.abilities.types.optional fieldType;
          default = null;
          description = servicePolicy.interfaces.${name}.declaration.description;
        })
      policyFields;
  };
  featureModules =
    builtins.attrValues (builtins.mapAttrs featureModuleFor serviceFields)
    ++ [policyModule];

  serviceModuleFor = name: let
    nameParts = lib.splitString "." name;
    localName = builtins.elemAt nameParts (builtins.length nameParts - 1);
  in {
    imports =
      [
        {
          config._module.strict = true;
          options.service = lib.mkOption {
            type = serviceManagement.types.serviceDeclarationFields.service;
            default = localName;
            description = "Runtime identity of this service.";
          };
          options.enable = lib.mkOption {
            type = lib.types.bool;
            default = false;
            extensible = true;
            description = "Enable this service instance.";
          };
        }
      ]
      ++ featureModules;
  };
in {
  options.aos.services = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.submodule ({name, ...}: serviceModuleFor name));
    default = {};
    extensible = true;
    description = "Typed service configurations assembled from domain feature modules.";
  };
}
