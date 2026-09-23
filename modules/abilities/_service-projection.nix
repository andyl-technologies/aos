##! Projects one evaluated service into package-owned ability definitions.
{serviceManagement}: {
  config,
  lib,
  name,
  consumerInstance ? name,
  featureContributions ? [],
}: let
  service = config.aos.services.${name};
  serviceFields =
    builtins.removeAttrs
    serviceManagement.types.serviceDeclarationFields
    ["service" "enabled"];
  declaration =
    {
      service = name;
      enabled = true;
    }
    // lib.filterAttrs
    (field: value: builtins.hasAttr field serviceFields && value != null)
    service;
  contribution =
    if service.lifecycle == null
    then throw "Service '${name}' needs a lifecycle declaration before it can consume service abilities."
    else
      serviceManagement.forService {
        inherit consumerInstance declaration featureContributions;
        serviceTypes = serviceManagement.types;
      };
in
  lib.mkMerge [
    {aos.abilities.requirementTemplates = contribution.requirementTemplates;}
    (lib.mkIf (service.enable && config.aos.abilities.environment != null) {
      aos.abilities = {
        instances.${consumerInstance} = {};
        requests = contribution.requests;
      };
    })
  ]
