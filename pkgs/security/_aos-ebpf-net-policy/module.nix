##! Package-owned BPF network policy selection, application, and readiness.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.security.ebpfNetworkPolicy;
  types = lib.abilities.types;
  consumerInstance = "ebpf-cgroup-network-policy";
  alias = "ebpf-cgroup-network-policy";
  effectsAlias = "ebpf-cgroup-network-policy-effects";
  packageArtifact = lib.abilities.packageOutput {};

  policyType = types.record {
    fields = {
      name = types.localKey;
      cgroup = types.executionPath;
      policy = types.artifactPathReference;
      object = types.artifactPathReference;
    };
  };
  requestType = types.record {
    fields = {
      policies = types.list {
        element = policyType;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      prerequisites = types.list {
        element = types.deferredResult types.resourceReference;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
    };
  };
  stateType = types.enum ["absent" "applied" "drifted" "unknown"];
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.security.ebpf-net-policy-observation/v1"];
      expected = requestType;
      state = stateType;
      loaded = types.list {
        element = types.localKey;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
    };
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  method = name: description: access: stopsProvider: outputs: {
    inherit description outputs;
    parameters = requestType;
    targetResource = "aos.network.ebpf-cgroup-policy";
    permittedOperations = [name];
    guarantees = [];
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  observationOutput = output "runtime" "attempt" "Reports the exact pinned BPF network policy state." observationType;
  methods = {
    apply = method "apply" "Loads and pins the selected BPF network policy set." "exclusive-write" false {
      observation = observationOutput;
      retained-resource = output "runtime" "instance" "References the exact applied policy set." types.resourceReference;
    };
    observe = method "observe" "Observes the selected BPF network policy pins." "read" false {observation = observationOutput;};
    remove = method "remove" "Releases the selected BPF network policy pins." "exclusive-write" true {observation = observationOutput;};
  };
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = alias;
  };
  declaration = lib.abilities.declareInterface {
    name = "aos.network.ebpf-cgroup-policy";
    description = "Selects exact immutable BPF policy artifacts for named cgroups.";
    abi = 1;
    inherit requestType methods aggregation;
    outputs.readiness-resource = output "planning" "instance" "References readiness for the exact policy set." types.resourceReference;
    lifecycle.persistentDeleteMethod = null;
    guarantees = [];
  };
  identity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration declaration
  );
  effectsDeclaration = lib.abilities.declareInterface {
    name = "aos.linux.ebpf-cgroup-policy-effects";
    description = "Executes admitted Linux cgroup BPF policy operations.";
    abi = 1;
    inherit requestType methods;
    outputs = {};
    inherit (declaration) lifecycle;
    guarantees = [];
    aggregation = aggregation // {controllerGroup = effectsAlias;};
  };
  effectsIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration effectsDeclaration
  );
  realizationType = types.record {
    fields = {
      schema = types.enum ["aos.linux.ebpf-net-policy-realization/v1"];
      loader = types.executableReference;
      pin_directory = types.executionPath;
    };
  };
  policyRequest = {
    policies = cfg.policies;
    prerequisites = [];
  };
in {
  options.aos.security.ebpfNetworkPolicy = {
    enable = lib.mkOption {
      type = types.boolean;
      default = false;
      description = "Apply the selected package-owned BPF network policy set.";
    };
    policies = lib.mkOption {
      type = types.list {
        element = policyType;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      default = [];
      description = "Exact cgroup targets, immutable policy documents, and BPF objects.";
    };
  };

  config.aos.abilities = lib.mkMerge [
    {
      interfaces = {
        ${alias} = declaration;
        ${effectsAlias} = effectsDeclaration;
      };
      implementations.${alias} = {
        description = "Owns selected BPF network policy resources through a pure controller.";
        interface = identity;
        artifact = packageArtifact;
        methods = builtins.attrNames methods;
        guarantees = [];
        requirements.effects = {
          alias = "effects";
          description = "Invokes the package-owned Linux BPF network terminal.";
          accepted_interfaces = [effectsIdentity];
          methods = builtins.attrNames methods;
          guarantees = [];
          strength = "required";
          fallback = null;
        };
        providerModule = {
          artifact = packageArtifact;
          path = "share/aos/providers/ebpf-cgroup-network-policy.nix";
        };
        desiredType = realizationType;
        requiredFeatures = [];
      };
      implementations.${effectsAlias} = {
        description = "Loads and pins BPF network policies through the package-owned Linux backend.";
        interface = effectsAlias;
        artifact = packageArtifact;
        methods = builtins.attrNames methods;
        guarantees = [];
        handlerDescriptor = {
          artifact = packageArtifact;
          entryPoint = "bin/aos-ebpf-net-policy-provider";
          arguments = requestType;
          result = observationType;
        };
        desiredType = null;
        requiredFeatures = [];
      };
      requirementTemplates.${alias} =
        lib.abilities.interfaceSelector {
          name = identity.name;
          abi = identity.abi;
        }
        // {
          description = "Requires the selected BPF network policy set.";
          methods = ["apply" "observe" "remove"];
          guarantees = [];
          strength = "required";
          fallback = null;
        };
    }
    (lib.mkIf (cfg.enable && cfg.policies != []) {
      instances.${consumerInstance} = {};
      requests.cgroup-policy-set = {
        requirement = alias;
        consumer = consumerInstance;
        scope = ["host-policy"];
        parameters = policyRequest;
      };
    })
  ];
}
