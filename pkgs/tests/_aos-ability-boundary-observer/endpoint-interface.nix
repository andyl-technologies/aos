##! Package-owned fleet execution-observer endpoint contract.
{
  config,
  lib,
  packageName,
  ...
}: let
  inherit (lib.abilities) declareInterface types;

  alias = "execution-observer-endpoint";
  interfaceName = "aos.test.execution-observer-endpoint";
  requestType = types.record {
    fields = {
      hosting = types.enum ["managed-service" "external-test-mount"];
      service_resource = {
        type = types.optional (types.deferredResult types.resourceReference);
        optional = true;
      };
      socket_path = types.deferredResult types.executionPath;
    };
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.test.execution-observer-endpoint-observation/v1"];
      expected = requestType;
      state = types.enum ["available" "unavailable" "unknown"];
    };
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  declaration = declareInterface {
    name = interfaceName;
    description = "Publishes the fleet fixture's protected execution-observer endpoint.";
    abi = 1;
    inherit requestType;
    methods.observe = {
      description = "Observes availability of the exact protected fleet endpoint.";
      parameters = requestType;
      targetResource = interfaceName;
      permittedOperations = ["observe"];
      guarantees = [];
      semantics = {
        requiredTargetAccess = "read";
        stopsProvider = false;
      };
      outputs.observation =
        output
        "observation"
        "attempt"
        "Reports availability of the exact fleet observation endpoint."
        observationType;
      outcome = {
        completionEvidence = observationType;
        observationEvidence = observationType;
        supportsRejectedBeforeEffect = true;
        indeterminate = "reconcile";
      };
    };
    outputs = {
      retained-resource =
        output
        "planning"
        "instance"
        "References the selected fleet observation endpoint."
        types.resourceReference;
      socket-path =
        output
        "planning"
        "instance"
        "Returns the selected fleet observation socket."
        types.executionPath;
    };
    lifecycle = {
      persistentDeleteMethod = null;
    };
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = alias;
    };
    guarantees = [];
  };
in {
  config.aos.abilities = {
    interfaces.${alias} = declaration;
    implementations.${alias} = {
      description = "Publishes the package-owned fleet observation endpoint.";
      interface = alias;
      artifact = lib.abilities.packageOutput {};
      methods = ["observe"];
      guarantees = [];
      requirements = {};
      providerModule = {
        artifact = lib.abilities.packageOutput {output = "module";};
        path = "endpoint-provider.nix";
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
}
