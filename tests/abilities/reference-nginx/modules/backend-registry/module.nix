##! Synthetic aggregate registry for reference HTTP backend endpoints.
{lib, ...}: let
  types = lib.abilities.types;
  endpoint = types.record {
    fields = {
      address = types.enum ["127.0.0.1"];
      port = types.integer {
        minimum = 1024;
        maximum = 65535;
      };
      transport = types.enum ["tcp"];
    };
    optional = [];
  };
  endpointMap = types.optional (types.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 1024;
    value = types.optional endpoint;
  });
  lifecycle = {persistentDeleteMethod = null;};
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = "backend";
  };
  declaration = lib.abilities.declareInterface {
    name = "aos.test.http-backend";
    abi = 1;
    description = "Aggregates synthetic loopback HTTP backend endpoints for fixture consumers.";
    requestType = endpoint;
    outputs.endpoints = {
      description = "Published endpoints keyed by fixture backend slot.";
      schema = endpointMap;
      phase = "planning";
      visibility = "protected";
      lifetime = "instance";
    };
    methods = {};
    inherit lifecycle aggregation;
    guarantees = [];
  };
  provider = import ./provider.nix {inherit lib;};
in {
  config.aos.abilities = {
    interfaces.http-backend = declaration;
    implementations.http-backend = {
      description = "Aggregates the synthetic HTTP endpoints contributed by the fixture.";
      interface = "http-backend";
      methods = [];
      guarantees = [];
      requirements = {};
      compose = provider.compose;
      transition = provider.transition;
      artifact = null;
      desiredType = endpoint;
      requiredFeatures = [];
    };
  };
}
