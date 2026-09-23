##! Composes the typed service option tree from domain modules.
##!
##! Packages extend the same `aos.services` submodule type with ordinary option
##! declarations, so the domain and package fields share one fixed point.
{
  config,
  lib,
  provenance,
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

  serviceModuleFor = name: let
    nameParts = lib.splitString "." name;
    localName = builtins.elemAt nameParts (builtins.length nameParts - 1);
    packageParts = builtins.genList (index: builtins.elemAt nameParts index) (builtins.length nameParts - 1);
    defaultConsumerInstance =
      if packageParts == []
      then name
      else builtins.concatStringsSep "." packageParts;
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
            type = lib.abilities.types.boolean;
            default = false;
            extensible = true;
            description = "Enable this service instance.";
          };
          options.autoStart = lib.mkOption {
            type = lib.abilities.types.boolean;
            default = true;
            description = "Ask the selected manager to start this service automatically.";
          };
          options.consumerInstance = lib.mkOption {
            type = lib.abilities.types.localKey;
            default = defaultConsumerInstance;
            internal = true;
            description = "Local ability instance receiving this service's requests.";
          };
        }
      ]
      ++ featureModules;
  };
  sourceForService = name: let
    definitions =
      provenance.definitionsOfNestedAttr ["aos" "services"] [name "service"]
      ++ provenance.definitionsOfNestedAttr ["aos" "services"] [name "lifecycle"];
    sources = lib.unique (builtins.map (definition: definition.provenance) definitions);
    packages = builtins.filter (source: lib.hasPrefix "package:" source) sources;
  in
    if builtins.length packages > 1
    then throw "Service '${name}' has conflicting package owners."
    else if packages != []
    then builtins.head packages
    else if builtins.elem "@runtime" sources
    then "@runtime"
    else if builtins.elem "@host" sources
    then "@host"
    else "@base";

  project = name: let
    lifecycleDefinitions =
      provenance.definitionsOfNestedAttr ["aos" "services"] [name "lifecycle"];
    service = config.aos.services.${name};
  in
    # A system module may configure a host package's service while the initrd
    # evaluates the same source graph without that package's module. Only a
    # lifecycle authored in this stage can turn it into an ability consumer.
    lib.optional (lifecycleDefinitions != [] && service.lifecycle != null) (serviceManagement.projectService {
      inherit config lib name;
      consumerInstance = service.consumerInstance;
      derivedProvenance = sourceForService name;
    });
  graphs = builtins.concatMap project (builtins.attrNames config.aos.services);
  merged = field: lib.mkMerge (builtins.map (graph: graph.${field}) graphs);
in {
  options.aos.services = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.submodule ({name, ...}: serviceModuleFor name));
    default = {};
    extensible = true;
    description = "Typed service configurations assembled from domain feature modules.";
  };

  config.aos.abilities = {
    requirementTemplates = merged "requirementTemplates";
    instances = merged "instances";
    requests = merged "requests";
  };
}
