##! Projects one evaluated service into package-owned ability definitions.
{serviceManagement}: {
  config,
  lib,
  name,
  consumerInstance ? null,
  featureRequests ? [],
}: let
  service = config.aos.services.${name};
  nameParts = lib.splitString "." name;
  localServiceName = builtins.elemAt nameParts (builtins.length nameParts - 1);
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
      service = localServiceName;
      enabled = true;
    }
    // lib.filterAttrs
    (field: value: builtins.hasAttr field serviceFields && value != null)
    service;
  definition =
    if service.lifecycle == null
    then throw "Service '${name}' needs a lifecycle declaration before it can consume service abilities."
    else
      serviceManagement.forService {
        consumerInstance = localConsumerInstance;
        inherit declaration featureRequests;
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
