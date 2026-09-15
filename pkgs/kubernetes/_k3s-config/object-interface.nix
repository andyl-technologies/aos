##! K3s-owned Kubernetes object-set declarations.
{
  lib,
  packageName,
  ...
}: let
  inherit (lib.abilities) declareInterface types;
  serverRole = (import ./roles.nix).${packageName}.role != "worker";
  controllerAlias = "kubernetes-object-set";
  contributionAlias = "kubernetes-objects";
  effectsAlias = "kubernetes-object-effects";
  controllerName = "aos.kubernetes.object-set";

  canonicalList = element: maxItems:
    types.list {
      inherit element maxItems;
      unique = true;
      canonicalOrder = true;
    };
  boundedString = maxLength:
    types.string {
      inherit maxLength;
      syntax = null;
    };
  prerequisites = canonicalList (types.deferredResult types.resourceReference) 64;
  nullableName = types.optional (boundedString 253);
  object = types.record {
    fields = {
      key = types.localKey;
      api_version = boundedString 256;
      kind = boundedString 256;
      namespace = nullableName;
      name = boundedString 253;
      content = boundedString types.limits.maxStringLength;
    };
  };
  contributionRequest = types.record {
    fields = {
      objects = canonicalList object 256;
      inherit prerequisites;
    };
  };
  clusterRequest = types.record {
    fields = {
      inherit prerequisites;
    };
  };
  aggregateRequest = types.record {
    fields = {
      cluster = clusterRequest;
      contributions = types.map {
        keyMaxLength = 64;
        keySyntax = "local-key-v1";
        maxEntries = 4096;
        value = contributionRequest;
      };
    };
  };
  objectObservation = types.record {
    fields = {
      revision = types.optional types.digest;
      state = types.enum [
        "absent"
        "current"
        "drifted"
        "foreign"
        "unknown"
      ];
      uid = types.optional (boundedString 4096);
      resource_version = types.optional (boundedString 4096);
    };
  };
  clusterObservation = types.record {
    fields = {
      available = types.boolean;
      incarnation = types.optional (boundedString 4096);
      kubeconfig_digest = types.optional types.digest;
    };
  };
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.ability.kubernetes-object-set-observation/v1"];
      expected = aggregateRequest;
      cluster = clusterObservation;
      objects = types.map {
        keyMaxLength = 128;
        keySyntax = "local-key-v1";
        maxEntries = 65536;
        value = objectObservation;
      };
      state = types.enum [
        "absent"
        "current"
        "drifted"
        "unknown"
      ];
    };
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  readinessOutput = description:
    output "planning" "instance" description types.resourceReference;
  observationOutput = phase:
    output phase "attempt" "Reports the exact observed cluster and object-set state." observationType;
  method = name: description: access: stopsProvider: parameters: outputs: {
    inherit description parameters outputs;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    targetResource = controllerName;
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
    apply = method "apply" "Converges the exact authorized Kubernetes object set." "exclusive-write" false aggregateRequest {
      observation = observationOutput "runtime";
      retained-resource = output "runtime" "instance" "References the retained aggregate object set." types.resourceReference;
    };
    observe = method "observe" "Observes the exact authorized Kubernetes object set." "read" false aggregateRequest {
      observation = observationOutput "observation";
    };
    release = method "release" "Deletes objects still owned by this exact aggregate revision." "exclusive-write" true aggregateRequest {
      observation = observationOutput "runtime";
    };
  };
  contributionMethods = {
    observe = method "observe" "Observes the aggregate containing this exact object contribution." "read" false contributionRequest {
      observation = observationOutput "observation";
    };
  };
  controllerLifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };
  contributionLifecycle =
    controllerLifecycle
    // {
      releasesEphemeralOnDisable = false;
    };
  mergeContract = lib.abilities.descriptorFor "aos.ability.merge-contract/v1" {
    schema = types.schemaOf "Kubernetes object-set aggregate" aggregateRequest;
  };
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = false;
    inherit mergeContract;
    controllerGroup = controllerAlias;
  };
  controllerDeclaration = declareInterface {
    name = controllerName;
    description = "Owns one Kubernetes cluster object set assembled from authorized package contributions.";
    abi = 1;
    requestType = aggregateRequest;
    methods = controllerMethods;
    lifecycle = controllerLifecycle;
    inherit aggregation;
    outputs = {
      readiness-resource = readinessOutput "References readiness for the exact aggregate object-set revision.";
      cluster-readiness-resource = readinessOutput "References the exact observed Kubernetes cluster incarnation.";
      kubeconfig-resource = readinessOutput "References the protected kubeconfig context bound to this cluster.";
    };
    guarantees = [];
  };
  contributionDeclaration = declareInterface {
    name = "aos.kubernetes.objects";
    description = "Contributes an exact authorized set of Kubernetes API objects.";
    abi = 1;
    requestType = contributionRequest;
    methods = contributionMethods;
    lifecycle = contributionLifecycle;
    inherit aggregation;
    outputs = {
      readiness-resource = readinessOutput "References the aggregate containing these exact objects.";
      cluster-readiness-resource = readinessOutput "References the exact observed Kubernetes cluster incarnation.";
      kubeconfig-resource = readinessOutput "References the protected kubeconfig context bound to this cluster.";
    };
    guarantees = [];
  };
  effectsDeclaration = declareInterface {
    name = "aos.k3s.kubernetes-object-effects";
    description = "Executes admitted Kubernetes object operations for one K3s controller-owned resource.";
    abi = 1;
    requestType = aggregateRequest;
    methods = controllerMethods;
    lifecycle = controllerLifecycle;
    outputs = {};
    guarantees = [];
    aggregation = aggregation // {controllerGroup = effectsAlias;};
  };
in {
  config.aos.abilities.interfaces =
    {
      ${controllerAlias} = controllerDeclaration;
      ${contributionAlias} = contributionDeclaration;
    }
    // lib.optionalAttrs serverRole {
      ${effectsAlias} = effectsDeclaration;
    };
}
