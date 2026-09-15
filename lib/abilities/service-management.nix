##! Canonical manager-neutral service lifecycle and feature declarations.
{
  boolean,
  declareInterface,
  guarantee,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  feature = name: semantics:
    guarantee {
      inherit name semantics;
      version = 1;
    };
  features = {
    configuration =
      feature "aos.service.feature.configuration"
      "the selected controller publishes the bound configuration revision before service convergence";
    credentials =
      feature "aos.service.feature.credentials"
      "the selected controller attaches only bound opaque credential views before service execution";
    dependencies =
      feature "aos.service.feature.dependencies"
      "the selected controller maintains declared ordering, readiness, conflict, and propagation relationships";
    identity =
      feature "aos.service.feature.identity"
      "the selected controller runs the service under its declared stable runtime identity";
    isolation =
      feature "aos.service.feature.isolation"
      "the selected controller enforces every isolation property required by the service contract";
    readiness =
      feature "aos.service.feature.readiness"
      "the selected controller observes readiness for the exact desired service revision";
    reload =
      feature "aos.service.feature.reload"
      "the selected controller invokes and observes the service's declared reload protocol";
    storage =
      feature "aos.service.feature.storage"
      "the selected controller attaches only bound storage views with their declared lifetimes";
    supervision =
      feature "aos.service.feature.supervision"
      "the selected controller continuously supervises the exact declared service process";
  };

  interfaceName = "aos.service-management";
  lifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };
  methodSemantics = name: {
    requiredTargetAccess =
      if builtins.elem name ["observe" "observe-boot" "observe-health" "validate" "verify"]
      then "read"
      else "exclusive-write";
    stopsProvider = name == "stop";
  };
  method = name: {
    description = "Performs the ${name} service lifecycle operation.";
    semantics = methodSemantics name;
    parameters = boolean;
    targetResource = interfaceName;
    outputs = {};
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = boolean;
      observationEvidence = boolean;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  declaration = declareInterface {
    name = interfaceName;
    description = "Controls the lifecycle of a provider-neutral service instance.";
    abi = 1;
    requestType = boolean;
    outputs = {};
    methods = {
      observe = method "observe";
      reload = method "reload";
      restart = method "restart";
      start = method "start";
      stop = method "stop";
    };
    inherit lifecycle;
    guarantees = builtins.attrValues features;
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "service-management";
    };
  };
  document = interfaceDocumentFromDeclaration declaration;
in {
  interface = interfaceIdentity document;
  inherit declaration document features;
  featureNames = builtins.attrNames features;
  featureGuarantees = names: builtins.map (name: features.${name}) names;
  requestType = boolean;
  methods = builtins.attrNames declaration.methods;
  inherit lifecycle;
}
