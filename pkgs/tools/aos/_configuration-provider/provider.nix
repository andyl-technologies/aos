##! Pure realization of configuration resources for the native materializer.
{lib, ...}: let
  interface = lib.abilities.interfaces.serviceManagement.interfaces.managedConfiguration;
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
    conditionalRequirements = [];
  };
  provide = {requests, ...}:
    emptyProvision
    // {
      resourceFragments = builtins.mapAttrs (_: request: {
          kind = interface.identity.name;
          lifetime = "instance";
          value = request.parameters;
        })
        requests;
    };
  pathFor = resource: let
    digest = builtins.hashString "sha256" (builtins.toJSON resource.resource);
  in "/run/aos/configurations/${resource.resource.key}-${digest}";
  compose = {resources, ...}: {
    requests = {};
    outputs = {};
    conditionalRequirements = [];
    realizations = builtins.mapAttrs (_: resource: {
        schema = "aos.configuration.materializer-realization/v1";
        path = pathFor resource;
      })
      resources;
  };
in {
  config.aos.abilities.implementations.configuration-materialization = {
    inherit provide compose;
  };
}
