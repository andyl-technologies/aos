##! Canonical provider-neutral host network-policy interfaces.
{
  types,
  declareInterface,
  descriptorFor,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  rulesetAlias = "network-ruleset";
  ingressAlias = "network-ingress-policy";
  forwardingAlias = "network-forwarding-policy";
  rulesetName = "aos.network.ruleset";

  canonicalList = element: maxItems:
    types.list {
      inherit element maxItems;
      unique = true;
      canonicalOrder = true;
    };
  prerequisites = canonicalList (types.deferredResult types.resourceReference) 64;
  policy = types.enum ["accept" "drop"];
  endpoint = types.record {
    fields = {
      transport = types.enum ["tcp" "udp"];
      port = types.integer {
        minimum = 1;
        maximum = 65535;
      };
    };
  };
  endpoints = canonicalList endpoint 65536;
  trustedInterfaces =
    canonicalList
    (types.string {
      maxLength = 128;
      syntax = null;
    })
    256;
  ingressRequest = types.record {
    fields = {
      inherit endpoints prerequisites;
    };
  };
  forwardingRequest = types.record {
    fields = {
      inherit policy prerequisites;
    };
  };
  baseRequest = types.record {
    fields = {
      input_policy = policy;
      forward_policy = policy;
      trusted_interfaces = trustedInterfaces;
      inherit prerequisites;
    };
  };
  aggregateRequest = types.record {
    fields = {
      base = baseRequest;
      ingress = types.map {
        keyMaxLength = 64;
        keySyntax = "local-key-v1";
        maxEntries = 4096;
        value = ingressRequest;
      };
      forwarding = types.map {
        keyMaxLength = 64;
        keySyntax = "local-key-v1";
        maxEntries = 4096;
        value = forwardingRequest;
      };
    };
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.ability.network-ruleset-observation/v1"];
      expected = aggregateRequest;
      observed_digest = types.optional types.digest;
      state = types.enum ["applied" "drifted" "unmanaged"];
      discrepancies = canonicalList types.localKey 16;
    };
  };
  realizationType = types.record {
    fields.schema = types.enum ["aos.network.ruleset-realization/v1"];
  };

  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  readinessOutput = description:
    output "planning" "instance" description types.resourceReference;
  observationOutput = phase:
    output phase "attempt" "Reports the exact observed aggregate ruleset state." observationType;
  method = name: description: access: stopsProvider: parameters: outputs: {
    inherit description parameters outputs;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    targetResource = rulesetName;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  controllerMethods = {
    apply = method "apply" "Atomically converges the aggregate network ruleset." "exclusive-write" false aggregateRequest {
      observation = observationOutput "runtime";
      retained-resource =
        output "runtime" "instance" "References the retained aggregate ruleset." types.resourceReference;
    };
    observe = method "observe" "Observes the aggregate network ruleset." "read" false aggregateRequest {
      observation = observationOutput "observation";
    };
    remove = method "remove" "Removes the aggregate ruleset owned by this provider." "exclusive-write" true aggregateRequest {
      observation = observationOutput "runtime";
    };
  };
  facetMethod = parameters: description: {
    observe = method "observe" description "read" false parameters {
      observation = observationOutput "observation";
    };
  };
  controllerLifecycle = {
    persistentDeleteMethod = null;
  };
  mergeContract = descriptorFor "aos.ability.network-policy-aggregate/v1" (
    types.schemaOf "network ruleset aggregate" aggregateRequest
  );
  aggregation = {
    scope = "provider-instance";
    key = "network-ruleset";
    rejectSlotCollisions = false;
    inherit mergeContract;
    controllerGroup = "network-ruleset";
  };

  rulesetDeclaration = declareInterface {
    name = rulesetName;
    description = "Owns one atomic host network ruleset assembled from typed policy facets.";
    abi = 1;
    requestType = aggregateRequest;
    methods = controllerMethods;
    lifecycle = controllerLifecycle;
    inherit aggregation;
    outputs.resource =
      readinessOutput "References readiness for the exact aggregate ruleset revision.";
    guarantees = [];
  };
  ingressMethods =
    facetMethod ingressRequest "Observes the aggregate containing this ingress contribution.";
  ingressDeclaration = declareInterface {
    name = "aos.network.ingress-policy";
    description = "Contributes an exact set of provider-neutral host ingress endpoints.";
    abi = 1;
    requestType = ingressRequest;
    methods = ingressMethods;
    lifecycle = controllerLifecycle;
    inherit aggregation;
    outputs.resource =
      readinessOutput "References the aggregate ruleset containing these ingress endpoints.";
    guarantees = [];
  };
  forwardingMethods =
    facetMethod forwardingRequest "Observes the aggregate containing this forwarding-policy contribution.";
  forwardingDeclaration = declareInterface {
    name = "aos.network.forwarding-policy";
    description = "Contributes a provider-neutral host packet-forwarding policy.";
    abi = 1;
    requestType = forwardingRequest;
    methods = forwardingMethods;
    lifecycle = controllerLifecycle;
    inherit aggregation;
    outputs.resource =
      readinessOutput "References the aggregate ruleset containing this forwarding policy.";
    guarantees = [];
  };

  interface = alias: declaration: let
    document = interfaceDocumentFromDeclaration declaration;
  in {
    inherit alias declaration document;
    identity = interfaceIdentity document;
    methods = builtins.attrNames declaration.methods;
    requestType = declaration.requestType;
  };
  interfaces = {
    ruleset = interface rulesetAlias rulesetDeclaration;
    ingress = interface ingressAlias ingressDeclaration;
    forwarding = interface forwardingAlias forwardingDeclaration;
  };
  readView = {
    inherit
      types
      interfaces
      aggregateRequest
      baseRequest
      ingressRequest
      forwardingRequest
      observationType
      realizationType
      ;
    declarations = builtins.listToAttrs (builtins.map (value: {
      name = value.alias;
      value = value.declaration;
    }) (builtins.attrValues interfaces));
  };
in {
  name = "networkPolicy";
  inherit readView;
  module.config.aos.abilities.interfaces = readView.declarations;
}
