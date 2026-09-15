##! D-Bus-owned system-bus availability contract.
{lib, ...}: let
  inherit (lib.abilities) declareInterface types;
  alias = "system-bus-availability";
  resourceKind = "aos.service.instance";
  request = types.record {
    fields.scope = types.enum ["system-bus"];
  };
  observation = types.record {
    fields = {
      schema = types.enum ["aos.ability.dbus-system-bus-availability-observation/v1"];
      expected = request;
      state = types.enum ["absent" "ready" "unknown"];
    };
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  methods.observe = {
    description = "Observes availability of the exact configured system message bus.";
    parameters = request;
    outputs.observation =
      output "observation" "attempt" "Reports system-bus availability." observation;
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
  lifecycle = {
    persistentDeleteMethod = null;
  };
  declaration = declareInterface {
    name = "aos.dbus.system-bus-availability";
    description = "Publishes the exact running system-bus resource for typed service dependencies.";
    abi = 1;
    requestType = request;
    inherit methods lifecycle;
    outputs.readiness-resource =
      output "planning" "instance"
      "References the exact configured system message bus service resource."
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
      description = "Publishes the package-owned system-bus service resource.";
      interface = alias;
      artifact = lib.abilities.packageOutput {};
      methods = ["observe"];
      guarantees = [];
      providerModule = {
        artifact = lib.abilities.packageOutput {};
        path = "share/aos/providers/dbus-availability.nix";
      };
      desiredType = null;
      requiredFeatures = [];
    };
  };
}
