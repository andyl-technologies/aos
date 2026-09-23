##! Derives one evaluated service's ability graph from its typed configuration.
{serviceManagement}: {
  config,
  lib,
  name,
  consumerInstance,
  derivedProvenance,
}: let
  service = config.aos.services.${name};
  servicePolicy = lib.abilities.interfaces.servicePolicy;
  serviceFields =
    builtins.removeAttrs
    serviceManagement.types.serviceDeclarationFields
    ["service" "enabled"];
  declaration =
    {
      inherit (service) service;
      enabled = service.autoStart;
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
        inherit consumerInstance;
        inherit declaration;
        featureRequests = policyRequests;
        serviceTypes = serviceManagement.types;
      };
  projectEntries = entries:
    builtins.mapAttrs (_: value:
      lib.abilities.derivedDefinition {
        provenance = derivedProvenance;
        inherit value;
      })
    entries;
  configured = service.enable && config.aos.abilities.environment != null;
in {
  requirementTemplates = projectEntries definition.requirementTemplates;
  instances =
    if configured
    then {
      ${consumerInstance} = lib.abilities.derivedDefinition {
        provenance = derivedProvenance;
        value = {};
      };
    }
    else {};
  requests =
    if configured
    then projectEntries definition.requests
    else {};
}
