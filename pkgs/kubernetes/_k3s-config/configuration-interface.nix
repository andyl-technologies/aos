##! K3s-owned typed configuration aggregation declarations.
{lib}: let
  inherit (lib.abilities) declareInterface interfaceDocumentFromDeclaration interfaceIdentity types;

  controllerAlias = "k3s-configuration";
  contributionAlias = "k3s-integration";
  controllerName = "aos.k3s.configuration";
  canonicalList = element: maxItems:
    types.list {
      inherit element maxItems;
      unique = true;
      canonicalOrder = true;
    };
  string = maximum:
    types.string {
      maxLength = maximum;
      syntax = null;
    };
  labels = types.map {
    keyMaxLength = 253;
    keySyntax = null;
    maxEntries = 256;
    value = string 253;
  };
  prerequisites = canonicalList (types.deferredResult types.resourceReference) 64;
  baseRequest = types.record {
    fields = {
      flannel_backend = types.enum [
        "vxlan"
        "host-gw"
        "wireguard-native"
        "none"
      ];
      disable_network_policy = types.boolean;
      disable_kube_proxy = types.boolean;
      node_labels = labels;
      inherit prerequisites;
    };
  };
  contributionRequest = types.record {
    fields = {
      disable_flannel = types.boolean;
      disable_network_policy = types.boolean;
      disable_kube_proxy = types.boolean;
      node_labels = labels;
      inherit prerequisites;
    };
  };
  aggregateRequest = types.record {
    fields = {
      base = baseRequest;
      contributions = types.map {
        keyMaxLength = 64;
        keySyntax = "local-key-v1";
        maxEntries = 256;
        value = contributionRequest;
      };
    };
  };
  observation = types.record {
    fields = {
      schema = types.enum ["aos.ability.k3s-configuration-observation/v1"];
      expected = aggregateRequest;
      state = types.enum ["absent" "current" "drifted" "unknown"];
      path = types.optional types.executionPath;
      content_digest = types.optional types.digest;
    };
  };
  realization = types.record {
    fields = {
      schema = types.enum ["aos.k3s.configuration-realization/v1"];
      path = types.executionPath;
    };
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  readiness = description:
    output "planning" "instance" description types.resourceReference;
  method = target: name: access: stopsProvider: parameters: outputs: {
    description = "${name} the exact composed K3s configuration.";
    inherit parameters outputs;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    targetResource = target;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observation;
      observationEvidence = observation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  controllerMethods = {
    apply = method controllerName "apply" "exclusive-write" false aggregateRequest {
      observation = output "runtime" "attempt" "Reports the composed K3s configuration state." observation;
      retained-resource = output "runtime" "instance" "References the retained K3s configuration." types.resourceReference;
    };
    observe = method controllerName "observe" "read" false aggregateRequest {
      observation = output "observation" "attempt" "Reports the composed K3s configuration state." observation;
    };
    release = method controllerName "release" "exclusive-write" true aggregateRequest {
      observation = output "runtime" "attempt" "Reports absence of the released K3s configuration." observation;
    };
  };
  contributionMethods = {
    observe = method controllerName "observe" "read" false contributionRequest {
      observation = output "observation" "attempt" "Reports the aggregate K3s configuration state." observation;
    };
  };
  controllerLifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = false;
    mergeContract = "sha256:${builtins.hashString "sha256" (builtins.toJSON (
      types.schemaOf "K3s configuration aggregate" aggregateRequest
    ))}";
    controllerGroup = controllerAlias;
  };
  controllerDeclaration = declareInterface {
    name = controllerName;
    description = "Owns one K3s configuration assembled from authorized package contributions.";
    abi = 1;
    requestType = aggregateRequest;
    methods = controllerMethods;
    lifecycle = controllerLifecycle;
    inherit aggregation;
    outputs = {
      execution-path = output "planning" "instance" "Returns the package-owned K3s configuration path." types.executionPath;
      readiness-resource = readiness "References readiness for the exact K3s configuration revision.";
    };
    guarantees = [];
  };
  contributionDeclaration = declareInterface {
    name = "aos.k3s.integration";
    description = "Contributes authorized networking and node-label settings to K3s.";
    abi = 1;
    requestType = contributionRequest;
    methods = contributionMethods;
    lifecycle = controllerLifecycle // {releasesEphemeralOnDisable = false;};
    inherit aggregation;
    outputs = {
      execution-path = output "planning" "instance" "Returns the aggregate K3s configuration path." types.executionPath;
      readiness-resource = readiness "References readiness for the aggregate K3s configuration revision.";
    };
    guarantees = [];
  };
  describe = alias: declaration: methods: {
    inherit alias declaration methods;
    document = interfaceDocumentFromDeclaration declaration;
    identity = interfaceIdentity (interfaceDocumentFromDeclaration declaration);
    requestType = declaration.requestType;
    observationType = observation;
  };
in {
  controller =
    describe controllerAlias controllerDeclaration (builtins.attrNames controllerMethods)
    // {
      realizationType = realization;
    };
  contribution = describe contributionAlias contributionDeclaration (builtins.attrNames contributionMethods);
}
