##! Canonical provider-neutral boot-preparation handoff interface.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  interfaceAlias = "boot-preparation-handoff";
  interfaceName = "aos.boot.preparation-handoff";

  canonicalList = element: maxItems:
    types.list {
      inherit element maxItems;
      unique = true;
      canonicalOrder = true;
    };
  preparations = canonicalList types.localKey 16;
  requestType = types.record {
    fields = {
      source_stage = types.enum ["initrd"];
      receiver_stage = types.enum ["host"];
      inherit preparations;
    };
  };
  bootIdentity = types.string {
    maxLength = 128;
    syntax = null;
  };
  receivedEvidence = types.record {
    fields = {
      boot_identity = bootIdentity;
      image_identity = types.digest;
      static_contract = types.digest;
      checkpoint = types.digest;
      completed_preparations = preparations;
    };
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.ability.boot-preparation-handoff-observation/v1"];
      expected = requestType;
      evidence = types.optional receivedEvidence;
      state = types.enum ["absent" "released" "received" "unknown"];
    };
  };
  realizationType = types.record {
    fields.schema = types.enum ["aos.boot.preparation-handoff-realization/v1"];
  };
  lifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = false;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = "boot-preparation-handoff";
  };
  output = phase: description: schema: {
    inherit phase description schema;
    lifetime = "transaction";
    visibility = "protected";
  };
  observationOutput = phase:
    output phase "Reports the exact observed boot-preparation handoff." observationType;
  method = name: description: access: outputs: {
    inherit description outputs;
    semantics = {
      requiredTargetAccess = access;
      stopsProvider = false;
    };
    parameters = requestType;
    targetResource = interfaceName;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  methods = {
    receive = method "receive" "Authenticates and records host receipt of exact initrd preparation evidence." "exclusive-write" {
      observation = observationOutput "runtime";
      retained-resource =
        output "runtime" "References the exact received boot-preparation resource." types.resourceReference;
    };
    observe = method "observe" "Observes an exact boot-preparation handoff without changing ownership." "read" {
      observation = observationOutput "observation";
    };
  };
  declaration = declareInterface {
    name = interfaceName;
    description = "Transfers exact successful boot-preparation evidence from an initrd transaction to its host stage.";
    abi = 1;
    inherit requestType methods lifecycle aggregation;
    outputs.readiness-resource =
      output "planning" "References host receipt of the exact boot-preparation transaction." types.resourceReference;
    guarantees = [];
  };
  document = interfaceDocumentFromDeclaration declaration;
  identity = interfaceIdentity document;
in {
  inherit
    interfaceAlias
    interfaceName
    declaration
    document
    identity
    methods
    requestType
    observationType
    realizationType
    ;

  declarations.${interfaceAlias} = declaration;
}
