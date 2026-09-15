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

  requirement = selected: methods: {
    inherit (selected) abi descriptor;
    interface = selected.name;
    inherit methods;
    strength = "required";
    fallback = null;
    guarantees = [];
  };

  output = schema: phase: {
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

  terminalExport = {
    name,
    group,
    handler,
    requestSchema,
    methods,
    deleteMethod ? null,
  }:
    lib.abilities.define {
      interface = name;
      abi = 1;
      inherit requestSchema methods handler;
      outputs = {};
      lifecycle = lifecycle deleteMethod;
      guarantees = [];
      aggregation = aggregation group;
      requires = {};
      ownsResourceKinds = [name];
    };
  systemdDefinition = terminalExport {
    name = systemdBootstrapName;
    group = "systemd-bootstrap";
    handler = "systemd-bootstrap-terminal";
    requestSchema = types.boolean;
    methods = bootstrapMethods;
  };
  kubernetesDefinition = terminalExport {
    name = kubernetesEffectsName;
    group = "kubernetes";
    handler = "native-kubernetes-object";
    requestSchema = kubernetesIdentity;
    methods = kubernetesMethods;
    deleteMethod = "delete";
  };
  systemdBootstrap = lib.abilities.interfaceIdentity (lib.abilities.interfaceDocument [] systemdDefinition);
  kubernetesEffects = lib.abilities.interfaceIdentity (lib.abilities.interfaceDocument [] kubernetesDefinition);

  k3sDefinition = {
    bootstrapMatrix ? false,
    effectQualification ? false,
    providerStateQualification ? false,
    transitionTransform ? transition: transition,
  }:
    lib.abilities.define {
      interface = k3sInterfaceName;
      abi = 1;
      requestSchema = addon;
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
      requires = {
        systemd-bootstrap = requirement systemdBootstrap ["observe-manager" "start" "stop"];
        kubernetes-terminal = requirement kubernetesEffects ["apply" "delete" "observe"];
      };
      composeEntry = "compose";
      transitionEntry = "transition";
      ownsResourceKinds = [k3sInterfaceName];
      inherit (import ./_k3s-ability-provider/default.nix {inherit bootstrapMatrix systemdBootstrap kubernetesEffects;}) compose;
      transition = transitionTransform (
        if providerStateQualification
        then (import ./_k3s-ability-provider/default.nix {inherit bootstrapMatrix systemdBootstrap kubernetesEffects;}).providerStateQualificationTransition
        else if effectQualification
        then (import ./_k3s-ability-provider/default.nix {inherit bootstrapMatrix systemdBootstrap kubernetesEffects;}).effectQualificationTransition
        else (import ./_k3s-ability-provider/default.nix {inherit bootstrapMatrix systemdBootstrap kubernetesEffects;}).transition
      );
    };
  k3sInterface = lib.abilities.interfaceIdentity (lib.abilities.interfaceDocument [] (k3sDefinition {}));
in rec {
  inherit k3sInterface kubernetesEffects systemdBootstrap;

  contributorPackage = {
    config.aos.abilities.requirementTemplates.k3s = requirement k3sInterface [];
  };

  payloadPackage = {};

  k3sPackage = {
    payloadArtifacts ? [],
    effectQualification ? false,
    providerStateQualification ? false,
    transitionTransform ? transition: transition,
    bootstrapMatrix ? false,
  }: {
    config.aos.abilities = lib.abilities.projectDefinitions {
      k3s = {
        artifacts = payloadArtifacts;
        definition = k3sDefinition {
          inherit bootstrapMatrix effectQualification providerStateQualification transitionTransform;
        };
      };
    };
  };

  systemdPackage = runtimeSelector: {
    config.aos.abilities = lib.abilities.projectDefinitions {
      systemd-bootstrap = {
        artifact = runtimeSelector;
        definition = systemdDefinition;
        handler = {
          artifact = runtimeSelector;
          entryPoint = "bin/.aos-package-runtime-unwrapped";
          arguments = types.boolean;
          result = types.boolean;
        };
      };
    };
  };

  kubernetesPackage = runtimeSelector: {
    config.aos.abilities = lib.abilities.projectDefinitions {
      kubernetes = {
        artifact = runtimeSelector;
        definition = kubernetesDefinition;
        handler = {
          artifact = runtimeSelector;
          entryPoint = "libexec/aos-kubernetes-object-handler-v1";
          arguments = types.boolean;
          result = kubernetesObservation;
        };
      };
    };
  };
}
