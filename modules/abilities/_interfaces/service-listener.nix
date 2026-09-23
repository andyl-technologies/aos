##! Canonical provider-neutral service listener ownership interface.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
  ...
}: let
  alias = "service-listener-claim";
  request = types.record {
    fields = {
      transport = types.enum ["tcp" "udp"];
      port = types.integer {
        minimum = 1;
        maximum = 65535;
      };
    };
  };
  observation = types.record {
    fields = {
      schema = types.enum ["aos.ability.service-listener-claim-observation/v1"];
      expected = request;
      state = types.enum ["claimed" "absent" "unknown"];
    };
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  methods.observe = {
    description = "Observes ownership of the exclusive host listener slot.";
    parameters = request;
    outputs.observation =
      output "observation" "attempt"
      "Reports ownership of the requested listener slot."
      observation;
    semantics = {
      requiredTargetAccess = "read";
      stopsProvider = false;
    };
    targetResource = "aos.service.listener-claim";
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
    name = "aos.service.listener-claim";
    description = "Claims exclusive ownership of one host-wide transport and port tuple.";
    abi = 1;
    requestType = request;
    inherit methods;
    lifecycle.persistentDeleteMethod = null;
    outputs.resource =
      output "planning" "instance"
      "References the exact listener slot reserved for the consuming service."
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
  document = interfaceDocumentFromDeclaration declaration;
  interface = {
    inherit alias declaration document;
    identity = interfaceIdentity document;
    methods = builtins.attrNames declaration.methods;
    requestType = declaration.requestType;
  };
  slotFor = endpoint: "${endpoint.transport}-${toString endpoint.port}";
  readView = {
    inherit interface slotFor;
  };
in {
  name = "serviceListener";
  inherit readView;
  module.config.aos.abilities.interfaces.${alias} = declaration;
}
