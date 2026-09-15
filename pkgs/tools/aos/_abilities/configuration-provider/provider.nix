##! Pure realization of configuration resources for the native materializer.
{
  config,
  lib,
  ...
}: let
  interface = lib.abilities.interfaces.serviceManagement.interfaces.managedConfiguration;
  rolloutInterface = config.aos.abilities.interfaces.image-rollout-effects;
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
    conditionalRequirements = [];
  };
  provide = {requests, ...}:
    emptyProvision
    // {
      resourceFragments =
        builtins.mapAttrs (_: request: {
          kind = interface.identity.name;
          lifetime = "instance";
          value = request.parameters;
        })
        requests;
    };
  pathFor = resource: let
    digest = builtins.hashString "sha256" (builtins.toJSON resource.resource);
  in "/run/aos/configurations/${resource.resource.key}-${digest}";
  compose = {resources, ...}: let
    realizations =
      builtins.mapAttrs (_: resource: {
        schema = "aos.configuration.materializer-realization/v1";
        path = pathFor resource;
      })
      resources;
    paths = builtins.map (realization: realization.path) (builtins.attrValues realizations);
    uniquePaths = builtins.attrNames (builtins.listToAttrs (builtins.map (path: {
        name = path;
        value = true;
      })
      paths));
  in
    if builtins.length paths != builtins.length uniquePaths
    then throw "configuration resources select the same materialization path"
    else {
      requests = {};
      outputs = {};
      conditionalRequirements = [];
      inherit realizations;
    };
  provideRollout = {requests, ...}:
    emptyProvision
    // {
      resourceFragments =
        builtins.mapAttrs (_: request: {
          kind = rolloutInterface.name;
          lifetime = "persistent";
          value = request.parameters;
        })
        requests;
    };
  composeRollout = {resources, ...}: {
    requests = {};
    outputs = {};
    conditionalRequirements = [];
    realizations =
      builtins.mapAttrs (_: _: {
        schema = "aos.image-rollout.realization/v1";
      })
      resources;
  };
in {
  config.aos.abilities.implementations = {
    configuration-materialization = {
      inherit provide compose;
    };
    image-rollout-effects = {
      provide = provideRollout;
      compose = composeRollout;
    };
  };
}
