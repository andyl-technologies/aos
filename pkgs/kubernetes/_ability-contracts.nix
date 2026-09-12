##! Shared ability contracts for Kubernetes role and contribution packages.
{lib}: let
  inherit (lib.abilities) schemas;

  interface = name: descriptor: {
    inherit name descriptor;
    abi = 1;
  };

  k3sInterface =
    interface
    "aos.k3s-cluster"
    "sha256:20917b76cabc6d68475c0bf1d0cb7e95bd0a6cb92fd3afeca5bcaf292d4943e1";
  systemdBootstrap =
    interface
    "aos.systemd-provider-bootstrap"
    "sha256:833e92258892d87a1f1cb16f66bfd1629c47a97386a9853cd93ffa30037b82f1";
  kubernetesEffects =
    interface
    "aos.kubernetes-object-effects"
    "sha256:bbced9c501c3c41ab4b5f2a70a2945bde2128ef0a37ad900f6d9f1e2f110963e";

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
    schemas.string {
      maxLength = maximum;
      syntax = null;
    };
  optionalString = maximum: schemas.optional (string maximum);
  stringMap = schemas.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 16;
    value = string 1048576;
  };
  resourceMap = schemas.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 16;
    value = schemas.resourceReference;
  };
  addon = schemas.record {
    fields = {
      chart = string 4096;
      repo = string 4096;
      target_namespace = string 253;
      values_content = string 1048576;
      version = string 256;
    };
    optional = [];
  };
  kubernetesIdentity = schemas.record {
    fields = {
      "api-version" = string 256;
      kind = string 256;
      name = string 253;
      namespace = optionalString 253;
    };
    optional = [];
  };
  kubernetesObservation = schemas.record {
    fields = {
      available = schemas.boolean;
      "content-matches" = schemas.boolean;
      exists = schemas.boolean;
      "object-revision" = optionalString 71;
      owned = schemas.boolean;
      "resource-version" = optionalString 4096;
      schema = schemas.enum ["aos.ability.kubernetes-object-observation/v1"];
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
  method = target: name: family: parameters: outputs: evidence: {
    targetResource = target;
    operationFamily = family;
    inherit parameters outputs;
    permittedOperations = [name];
    guarantees = [];
    outcome = outcome evidence "reconcile";
  };

  kubernetesMethods = builtins.listToAttrs (builtins.map (name: {
    inherit name;
    value =
      method kubernetesEffects.name name {
        kind = "kubernetes-object";
        action = name;
      }
      schemas.boolean {
        observation = output kubernetesObservation "observation";
      }
      kubernetesObservation;
  }) ["apply" "delete" "observe"]);

  bootstrapMethods = {
    observe-manager =
      method systemdBootstrap.name "observe-manager" {
        kind = "observe-readiness";
      }
      schemas.boolean {
        cluster-assignment = output schemas.providerAssignment "observation";
      }
      schemas.boolean;
    start =
      method systemdBootstrap.name "start" {
        kind = "service-lifecycle";
        action = "start";
      }
      schemas.boolean {}
      schemas.boolean;
    stop =
      method systemdBootstrap.name "stop" {
        kind = "service-lifecycle";
        action = "stop";
      }
      schemas.boolean {}
      schemas.boolean;
  };

  terminalExport = {
    selected,
    group,
    handler,
    requestSchema,
    methods,
    deleteMethod ? null,
  }:
    lib.abilities.define {
      interface = selected.name;
      abi = selected.abi;
      inherit requestSchema methods handler;
      outputs = {};
      lifecycle = lifecycle deleteMethod;
      guarantees = [];
      aggregation = aggregation group;
      requires = {};
      ownsResourceKinds = [selected.name];
    };

  common = {
    activationMode = "structured-effects";
    ownership = [[]];
  };
in rec {
  inherit k3sInterface kubernetesEffects systemdBootstrap;

  contributorPackage = {
    activationMode = "contracts-only";
    requirements.k3s = requirement k3sInterface [];
  };

  payloadPackage = {
    activationMode = "contracts-only";
  };

  k3sPackage = {
    providerArtifact,
    payloadArtifacts ? [],
  }:
    common
    // {
      artifacts = payloadArtifacts;
      exports.k3s = {
        artifact = providerArtifact;
        export = lib.abilities.define {
          interface = k3sInterface.name;
          abi = k3sInterface.abi;
          requestSchema = addon;
          outputs = {
            object-json = output stringMap "planning";
            objects = output resourceMap "planning";
            service = output schemas.resourceReference "planning";
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
          ownsResourceKinds = [k3sInterface.name];
          inherit (import ./_k3s-ability-provider/default.nix) compose transition;
        };
      };
    };

  systemdPackage = runtimeArtifact:
    common
    // {
      exports.systemd-bootstrap = {
        artifact = runtimeArtifact;
        export = terminalExport {
          selected = systemdBootstrap;
          group = "systemd-bootstrap";
          handler = "systemd-bootstrap-terminal";
          requestSchema = schemas.boolean;
          methods = bootstrapMethods;
        };
      };
      handlers.systemd-bootstrap-terminal = {
        artifact = runtimeArtifact;
        entryPoint = "bin/.aos-package-runtime-unwrapped";
        arguments = schemas.boolean;
        result = schemas.boolean;
      };
    };

  kubernetesPackage = runtimeArtifact:
    common
    // {
      exports.kubernetes = {
        artifact = runtimeArtifact;
        export = terminalExport {
          selected = kubernetesEffects;
          group = "kubernetes";
          handler = "native-kubernetes-object-v1";
          requestSchema = kubernetesIdentity;
          methods = kubernetesMethods;
          deleteMethod = "delete";
        };
      };
      handlers.native-kubernetes-object-v1 = {
        artifact = runtimeArtifact;
        entryPoint = "libexec/aos-kubernetes-object-handler-v1";
        arguments = schemas.boolean;
        result = kubernetesObservation;
      };
    };
}
