##! Projects one evaluated service into package-owned ability definitions.
{serviceManagement}: {
  config,
  lib,
  name,
  consumerInstance ? null,
  featureRequests ? [],
}: let
  service = config.aos.services.${name};
  servicePolicy = lib.abilities.interfaces.servicePolicy;
  nameParts = lib.splitString "." name;
  packageParts = builtins.genList (index: builtins.elemAt nameParts index) (builtins.length nameParts - 1);
  localConsumerInstance =
    if consumerInstance != null
    then consumerInstance
    else if packageParts == []
    then name
    else builtins.concatStringsSep "." packageParts;
  serviceFields =
    builtins.removeAttrs
    serviceManagement.types.serviceDeclarationFields
    ["service" "enabled"];
  declaration =
    {
      inherit (service) service;
      enabled = true;
    }
    // lib.filterAttrs
    (field: value:
      builtins.hasAttr field serviceFields
      && value != null
      && !(builtins.isAttrs value && value == {}))
    service;
  policyRequests = builtins.concatLists (builtins.map
    (name: let
      settings = service.policy.${name};
      interface = servicePolicy.interfaces.${name};
    in
      lib.optional (settings != null) (serviceManagement.featureRequest {
        key = servicePolicy.facets.${name}.facet;
        requirementAlias = interface.alias;
        description = interface.declaration.description;
        inherit (interface.identity) abi descriptor;
        interface = interface.identity.name;
        inherit (interface) methods guarantees;
        parameters = settings;
      }))
    ["hardening" "devicePolicy" "runtimeConditions"]);
  definition =
    if service.lifecycle == null
    then throw "Service '${name}' needs a lifecycle declaration before it can consume service abilities."
    else
      serviceManagement.forService {
        consumerInstance = localConsumerInstance;
        inherit declaration;
        featureRequests = policyRequests ++ featureRequests;
        serviceTypes = serviceManagement.types;
      };
in
  lib.mkMerge [
    {aos.abilities.requirementTemplates = definition.requirementTemplates;}
    (lib.mkIf (service.enable && config.aos.abilities.environment != null) {
      aos.abilities = {
        instances.${localConsumerInstance} = {};
        requests = definition.requests;
      };
    })
  ]
