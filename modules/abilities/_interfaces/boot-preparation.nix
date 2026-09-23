##! Canonical provider-neutral boot preparation and stage handoff interfaces.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  canonicalList = element: maxItems:
    types.list {
      inherit element maxItems;
      unique = true;
      canonicalOrder = true;
    };
  requestedResources = canonicalList (types.deferredResult types.resourceReference) 64;
  completedResources = canonicalList types.resourceReference 64;
  lifecycle = {
    persistentDeleteMethod = null;
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  canonicalInterface = {
    alias,
    name,
    description,
    requestType,
    observationType,
    realizationType,
    methods,
    outputs,
    controllerGroup,
  }: let
    declaration = declareInterface {
      inherit name description requestType methods outputs lifecycle;
      abi = 1;
      guarantees = [];
      aggregation = {
        scope = "provider-instance";
        key = "slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        inherit controllerGroup;
      };
    };
    document = interfaceDocumentFromDeclaration declaration;
  in {
    inherit alias name declaration document requestType observationType realizationType;
    identity = interfaceIdentity document;
    methods = builtins.attrNames methods;
  };

  preparation = let
    name = "aos.boot.preparation";
    requestType = types.record {
      fields = {
        execution = types.executableReference;
        prerequisites = requestedResources;
      };
    };
    observationType = types.record {
      fields = {
        schema = types.enum ["aos.ability.boot-preparation-observation/v1"];
        expected = requestType;
        state = types.enum ["absent" "completed" "failed" "unknown"];
      };
    };
    realizationType = types.record {
      fields.schema = types.enum ["aos.boot.preparation-realization/v1"];
    };
    observationOutput = phase:
      output phase "attempt"
      "Reports the exact observed preparation state."
      observationType;
    method = methodName: description: access: outputs: {
      inherit description outputs;
      semantics = {
        requiredTargetAccess = access;
        stopsProvider = false;
      };
      parameters = requestType;
      targetResource = name;
      permittedOperations = [methodName];
      guarantees = [];
      outcome = {
        completionEvidence = observationType;
        observationEvidence = observationType;
        supportsRejectedBeforeEffect = true;
        indeterminate = "reconcile";
      };
    };
    methods = {
      prepare = method "prepare" "Executes one exact preparation in its selected boot stage." "exclusive-write" {
        observation = observationOutput "runtime";
        retained-resource =
          output "runtime" "transaction"
          "References the successfully completed boot preparation."
          types.resourceReference;
      };
      observe = method "observe" "Observes completion of one exact boot preparation." "read" {
        observation = observationOutput "observation";
      };
    };
  in
    canonicalInterface {
      alias = "boot-preparation";
      inherit name requestType observationType realizationType methods;
      description = "Executes and retains exact preparation evidence within one boot transaction.";
      outputs.resource =
        output "planning" "transaction"
        "References the exact preparation resource selected before execution."
        types.resourceReference;
      controllerGroup = "boot-preparation";
    };

  handoff = let
    name = "aos.boot.preparation-handoff";
    pathMapping = types.record {
      fields = {
        initrd_path = types.executionPath;
        host_path = types.executionPath;
      };
    };
    pathMappings = canonicalList pathMapping 16;
    requestType = types.record {
      fields = {
        source_stage = types.enum ["initrd"];
        receiver_stage = types.enum ["host"];
        completion = types.deferredResult types.resourceReference;
        preparations = requestedResources;
        preserved_mounts = pathMappings;
        durable_state_roots = pathMappings;
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
        completed_preparations = completedResources;
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
    observationOutput = phase:
      output phase "attempt"
      "Reports the exact observed boot-preparation handoff."
      observationType;
    method = methodName: description: access: outputs: {
      inherit description outputs;
      semantics = {
        requiredTargetAccess = access;
        stopsProvider = false;
      };
      parameters = requestType;
      targetResource = name;
      permittedOperations = [methodName];
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
          output "runtime" "transaction"
          "References the exact received boot-preparation handoff."
          types.resourceReference;
      };
      observe = method "observe" "Observes an exact boot-preparation handoff without changing ownership." "read" {
        observation = observationOutput "observation";
      };
    };
  in
    canonicalInterface {
      alias = "boot-preparation-handoff";
      inherit name requestType observationType realizationType methods;
      description = "Transfers exact successful boot-preparation evidence from an initrd transaction to its host stage.";
      outputs.resource =
        output "planning" "transaction"
        "References host receipt of the exact boot-preparation transaction."
        types.resourceReference;
      controllerGroup = "boot-preparation-handoff";
    };
  readView = {
    interfaces = {
      inherit preparation handoff;
    };

    declarations = {
      ${preparation.alias} = preparation.declaration;
      ${handoff.alias} = handoff.declaration;
    };
  };
in {
  name = "bootPreparation";
  inherit readView;
  module.config.aos.abilities.interfaces = readView.declarations;
}
