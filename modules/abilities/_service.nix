##! Composes the typed service option tree from selected domain modules.
##!
##! A package declares its own service settings once as a deferred module.
##! The service submodule evaluates those settings alongside the common fields
##! and other selected features, so all definitions share one fixed point.
{
  config,
  lib,
  ...
}: let
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

  packageSchemaFor = name: let
    schema = config.aos.serviceOptionModules.${name};
  in
    if builtins.isAttrs schema && builtins.attrNames schema == ["options"]
    then schema
    else throw "Service '${name}' option module must contain only an options declaration.";

  serviceModuleFor = name: {
    imports =
      [
        {
          config._module.strict = true;
          options.enable = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = "Enable this service instance.";
          };
        }
      ]
      ++ featureModules
      ++ config.aos.serviceFeatureModules
      ++ lib.optional
      (builtins.hasAttr name config.aos.serviceOptionModules)
      (packageSchemaFor name);
  };
in {
  options.aos.serviceFeatureModules = lib.mkOption {
    type = lib.types.listOf lib.types.deferredModule;
    default = [];
    internal = true;
    description = "Selected modules extending every named service's option tree.";
  };

  options.aos.serviceOptionModules = lib.mkOption {
    type = lib.types.attrsOf lib.types.deferredModule;
    default = {};
    internal = true;
    description = "Package-owned option modules for named services.";
  };

  options.aos.services = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.submodule ({name, ...}: serviceModuleFor name));
    default = {};
    extensible = true;
    description = "Typed service configurations assembled from domain feature modules.";
  };

  # A registered schema creates its named service even when no configuration
  # value is supplied, allowing the service's own defaults to take effect.
  config.aos.services = builtins.mapAttrs (_: _: {}) config.aos.serviceOptionModules;
}
