##! Shared ability contracts for Kubernetes role and contribution packages.
{lib}: let
  inherit (lib.abilities) types;

  k3sInterfaceName = "aos.k3s-cluster";
  systemdBootstrapName = "aos.systemd-provider-bootstrap";
  kubernetesEffectsName = "aos.kubernetes-object-effects";

  lifecycle = persistentDeleteMethod: {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = false;
    retainsPersistentByDefault = true;
    inherit persistentDeleteMethod;
  };

  aggregation = group: {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = group;
  };

  requirement = alias: selected: methods: {
    inherit alias;
    accepted_interfaces = [selected];
    inherit methods;
    strength = "required";
    fallback = null;
    guarantees = [];
  };
  requirementTemplate = selected: methods: {
    description = "Requires the ${selected.name} interface.";
    inherit (selected) abi descriptor;
    interface = selected.name;
    inherit methods;
    strength = "required";
    fallback = null;
    guarantees = [];
  };

  output = schema: phase: {
    description = "Publishes a selected Kubernetes provider value.";
    inherit schema phase;
    visibility = "protected";
    lifetime =
      if phase == "observation"
      then "attempt"
      else "instance";
  };

  string = maximum:
    types.string {
      maxLength = maximum;
      syntax = null;
    };
  optionalString = maximum: types.optional (string maximum);
  stringMap = types.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 16;
    value = string 1048576;
  };
  resourceMap = types.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 16;
    value = types.resourceReference;
  };
  addon = types.record {
    fields = {
      chart = string 4096;
      repo = string 4096;
      target_namespace = string 253;
      values_content = string 1048576;
      version = string 256;
    };
    optional = [];
  };
  kubernetesIdentity = types.record {
    fields = {
      "api-version" = string 256;
      kind = string 256;
      name = string 253;
      namespace = optionalString 253;
    };
    optional = [];
  };
  kubernetesObservation = types.record {
    fields = {
      available = types.boolean;
      "content-matches" = types.boolean;
      exists = types.boolean;
      "object-revision" = optionalString 71;
      owned = types.boolean;
      "resource-version" = optionalString 4096;
      schema = types.enum ["aos.ability.kubernetes-object-observation/v1"];
      uid = optionalString 4096;
    };
    optional = [];
  };

  outcome = evidence: indeterminate: {
    completionEvidence = evidence;
    observationEvidence = evidence;
    supportsRejectedBeforeEffect = true;
    inherit indeterminate;
  };
  methodSemantics = name: {
    requiredTargetAccess =
      if builtins.elem name ["observe" "observe-boot" "observe-health" "validate" "verify"]
      then "read"
      else "exclusive-write";
    stopsProvider = builtins.elem name ["delete" "stop"];
  };
  method = target: name: parameters: outputs: evidence: {
    description = "Performs the ${name} operation on ${target}.";
    targetResource = target;
    semantics = methodSemantics name;
    inherit parameters outputs;
    permittedOperations = [name];
    guarantees = [];
    outcome = outcome evidence "reconcile";
  };

  kubernetesMethods = builtins.listToAttrs (builtins.map (name: {
    inherit name;
    value =
      method kubernetesEffectsName name types.boolean {
        observation = output kubernetesObservation "observation";
      }
      kubernetesObservation;
  }) ["apply" "delete" "observe"]);

  bootstrapMethods = {
    observe-manager =
      method systemdBootstrapName "observe-manager" types.boolean {
        cluster-assignment = output types.providerAssignment "observation";
      }
      types.boolean;
    start =
      method systemdBootstrapName "start" types.boolean {}
      types.boolean;
    stop =
      method systemdBootstrapName "stop" types.boolean {}
      types.boolean;
  };

  terminalDeclaration = {
    name,
    group,
    requestSchema,
    methods,
    deleteMethod ? null,
  }:
    lib.abilities.declareInterface {
      inherit name;
      abi = 1;
      description = "Provides the ${name} interface.";
      requestType = requestSchema;
      configurationType = null;
      inherit methods;
      outputs = {};
      lifecycle = lifecycle deleteMethod;
      guarantees = [];
      aggregation = aggregation group;
      requiredFeatures = [];
    };
  systemdDeclaration = terminalDeclaration {
    name = systemdBootstrapName;
    group = "systemd-bootstrap";
    requestSchema = types.boolean;
    methods = bootstrapMethods;
  };
  kubernetesDeclaration = terminalDeclaration {
    name = kubernetesEffectsName;
    group = "kubernetes";
    requestSchema = kubernetesIdentity;
    methods = kubernetesMethods;
    deleteMethod = "delete";
  };
  systemdBootstrap = lib.abilities.interfaceIdentity (lib.abilities.interfaceDocumentFromDeclaration systemdDeclaration);
  kubernetesEffects = lib.abilities.interfaceIdentity (lib.abilities.interfaceDocumentFromDeclaration kubernetesDeclaration);

  k3sProvider = {
    bootstrapMatrix ? false,
    effectQualification ? false,
    providerStateQualification ? false,
    transitionTransform ? transition: transition,
  }: let
    provider = import ./_k3s-ability-provider/default.nix {inherit bootstrapMatrix systemdBootstrap kubernetesEffects;};
  in {
    compose = provider.compose;
    transition = transitionTransform (
      if providerStateQualification
      then provider.providerStateQualificationTransition
      else if effectQualification
      then provider.effectQualificationTransition
      else provider.transition
    );
  };
  k3sDeclaration = lib.abilities.declareInterface {
      name = k3sInterfaceName;
      abi = 1;
      description = "Coordinates the selected k3s cluster and Kubernetes objects.";
      requestType = addon;
      configurationType = addon;
      outputs = {
        object-json = output stringMap "planning";
        objects = output resourceMap "planning";
        service = output types.resourceReference "planning";
        services = output resourceMap "planning";
      };
      methods = {};
      lifecycle = lifecycle null;
      guarantees = [];
      aggregation = aggregation "k3s";
      requiredFeatures = [];
    };
  k3sInterface = lib.abilities.interfaceIdentity (lib.abilities.interfaceDocumentFromDeclaration k3sDeclaration);
in rec {
  inherit k3sInterface kubernetesEffects systemdBootstrap;

  contributorPackage = {
    config.aos.abilities.requirementTemplates.k3s = requirementTemplate k3sInterface [];
  };

  payloadPackage = {};

  k3sPackage = {
    payloadArtifacts ? [],
    effectQualification ? false,
    providerStateQualification ? false,
    transitionTransform ? transition: transition,
    bootstrapMatrix ? false,
  }: let
    provider = k3sProvider {
          inherit bootstrapMatrix effectQualification providerStateQualification transitionTransform;
    };
  in {
    config.aos.abilities = {
      interfaces.k3s = k3sDeclaration;
      implementations.k3s = {
        description = "Composes and transitions the selected k3s cluster.";
        interface = "k3s";
        methods = [];
        guarantees = [];
        requirements = {
          systemd-bootstrap = requirement "systemd-bootstrap" systemdBootstrap ["observe-manager" "start" "stop"];
          kubernetes-terminal = requirement "kubernetes-terminal" kubernetesEffects ["apply" "delete" "observe"];
        };
        inherit (provider) compose transition;
        desiredType = addon;
        artifacts = payloadArtifacts;
      };
    };
  };

  systemdPackage = runtimeSelector: {
    config.aos.abilities = {
      interfaces.systemd-bootstrap = systemdDeclaration;
      implementations.systemd-bootstrap = {
        description = "Executes systemd provider bootstrap operations.";
        interface = "systemd-bootstrap";
        methods = builtins.attrNames bootstrapMethods;
        guarantees = [];
        requirements = {};
        artifact = runtimeSelector;
        handlerDescriptor = {
          artifact = runtimeSelector;
          entryPoint = "bin/.aos-package-runtime-unwrapped";
          arguments = types.boolean;
          result = types.boolean;
        };
      };
    };
  };

  kubernetesPackage = runtimeSelector: {
    config.aos.abilities = {
      interfaces.kubernetes = kubernetesDeclaration;
      implementations.kubernetes = {
        description = "Executes Kubernetes object operations.";
        interface = "kubernetes";
        methods = builtins.attrNames kubernetesMethods;
        guarantees = [];
        requirements = {};
        artifact = runtimeSelector;
        handlerDescriptor = {
          artifact = runtimeSelector;
          entryPoint = "libexec/aos-kubernetes-object-handler-v1";
          arguments = types.boolean;
          result = kubernetesObservation;
        };
      };
    };
  };
}
