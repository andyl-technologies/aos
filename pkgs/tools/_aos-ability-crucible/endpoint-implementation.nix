##! Ability Crucible implementation of the execution-observation endpoint.
{lib, ...}: let
  endpoint = lib.abilities.interfaces.executionObservationEndpoint.interfaces.endpoint;
in {
  config.aos.abilities.implementations.${endpoint.alias} = {
    description = "Publishes the package-owned Ability Crucible observer endpoint.";
    interface = endpoint.identity;
    artifact = lib.abilities.packageOutput {};
    inherit (endpoint) methods;
    guarantees = [];
    requirements = {};
    providerModule = {
      artifact = lib.abilities.packageOutput {output = "module";};
      path = "endpoint-provider.nix";
    };
    desiredType = null;
    requiredFeatures = [];
  };
}
