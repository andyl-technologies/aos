##! Provider-neutral authorization-service availability contract.
{lib, ...}: let
  inherit (lib.abilities) declareInterface types;
  alias = "authorization-service-availability";
  resourceKind = "aos.service.instance";
  request = types.record {
    fields.scope = types.enum ["system"];
  };
  observation = types.record {
    fields = {
      schema = types.enum ["aos.ability.authorization-service-availability-observation/v1"];
      expected = request;
      state = types.enum ["absent" "ready" "unknown"];
    };
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  methods.observe = {
    description = "Observes availability of the selected system authorization service.";
    parameters = request;
    outputs.observation =
      output "observation" "attempt"
      "Reports authorization-service availability."
      observation;
    semantics = {
      requiredTargetAccess = "read";
      stopsProvider = false;
    };
    targetResource = resourceKind;
    permittedOperations = ["observe"];
    guarantees = [];
    outcome = {
      completionEvidence = observation;
      observationEvidence = observation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  declaration = declareInterface {
    name = "aos.authorization.service-availability";
    description = "Publishes the running service that answers system authorization requests.";
    abi = 1;
    requestType = request;
    inherit methods;
    lifecycle.persistentDeleteMethod = null;
    outputs.resource =
      output "planning" "instance"
      "References the exact configured authorization service resource."
      types.resourceReference;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = alias;
    };
  };
in {
  config.aos.abilities = {
    interfaces.${alias} = declaration;
    implementations.${alias} = {
      description = "Publishes Polkit's package-owned authorization service resource.";
      interface = alias;
      artifact = lib.abilities.packageOutput {};
      methods = ["observe"];
      guarantees = [];
      providerModule = {
        artifact = lib.abilities.packageOutput {output = "module";};
        path = "availability-provider.nix";
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
}
