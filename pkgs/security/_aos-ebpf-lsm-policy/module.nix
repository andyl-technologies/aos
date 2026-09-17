##! Package-owned BPF-LSM policy selection, application, and readiness.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.security.ebpfLsm;
  types = lib.abilities.types;
  consumerInstance = "ebpf-lsm-policy";
  alias = "ebpf-lsm-policy-set";
  effectsAlias = "ebpf-lsm-policy-effects";
  packageArtifact = lib.abilities.packageOutput {};

  policyType = types.record {
    fields = {
      name = types.localKey;
      policy = types.artifactPathReference;
      object = types.artifactPathReference;
      programs = types.list {
        element = types.string {
          maxLength = 128;
          syntax = null;
        };
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
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
      schema = types.enum ["aos.security.ebpf-lsm-policy-observation/v1"];
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
    targetResource = "aos.security.ebpf-lsm-policy-set";
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
  observationOutput = output "runtime" "attempt" "Reports the exact pinned BPF-LSM policy state." observationType;
  methods = {
    apply = method "apply" "Loads and pins the selected BPF-LSM policy set." "exclusive-write" false {
      observation = observationOutput;
      retained-resource = output "runtime" "instance" "References the exact applied policy set." types.resourceReference;
    };
    observe = method "observe" "Observes the selected BPF-LSM policy pins." "read" false {observation = observationOutput;};
    remove = method "remove" "Releases the selected BPF-LSM policy pins." "exclusive-write" true {observation = observationOutput;};
  };
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = alias;
  };
  declaration = lib.abilities.declareInterface {
    name = "aos.security.ebpf-lsm-policy-set";
    description = "Selects and applies exact immutable BPF-LSM policy artifacts.";
    abi = 1;
    inherit requestType methods aggregation;
    outputs.resource = output "planning" "instance" "References readiness for the exact policy set." types.resourceReference;
    lifecycle.persistentDeleteMethod = null;
    guarantees = [];
  };
  identity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration declaration
  );
  effectsDeclaration = lib.abilities.declareInterface {
    name = "aos.linux.ebpf-lsm-policy-effects";
    description = "Executes admitted Linux BPF-LSM policy operations.";
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
      schema = types.enum ["aos.linux.ebpf-lsm-policy-realization/v1"];
      loader = types.executableReference;
      pin_directory = types.executionPath;
    };
  };
  policyRequest = {
    policies = cfg.policies;
    prerequisites = [];
  };
in {
  options.aos.security.ebpfLsm = {
    enable = lib.mkOption {
      type = types.boolean;
      default = false;
      description = "Apply the selected package-owned BPF-LSM policy set.";
    };
    policies = lib.mkOption {
      type = types.list {
        element = policyType;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      default = [
        {
          name = "aos-lsm-task-audit";
          policy = {
            artifact = packageArtifact;
            path = "share/aos/ebpf-lsm/aos-task-audit.json";
          };
          object = {
            artifact = packageArtifact;
            path = "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o";
          };
          programs = ["aos_lsm_file_mprotect"];
        }
      ];
      description = "Exact immutable policy documents, BPF objects, and expected programs.";
    };
  };

  config.aos.abilities = lib.mkMerge [
    {
      interfaces = {
        ${alias} = declaration;
        ${effectsAlias} = effectsDeclaration;
      };
      implementations.${alias} = {
        description = "Owns selected BPF-LSM policy resources through a pure controller.";
        interface = identity;
        artifact = packageArtifact;
        methods = builtins.attrNames methods;
        guarantees = [];
        requirements.effects = {
          alias = "effects";
          description = "Invokes the package-owned Linux BPF-LSM terminal.";
          accepted_interfaces = [effectsIdentity];
          methods = builtins.attrNames methods;
          guarantees = [];
          strength = "required";
          fallback = null;
        };
        providerModule = {
          artifact = lib.abilities.packageOutput {output = "module";};
          path = "provider.nix";
        };
        desiredType = realizationType;
        requiredFeatures = [];
      };
      implementations.${effectsAlias} = {
        description = "Loads and pins BPF-LSM policies through the package-owned Linux backend.";
        interface = effectsAlias;
        artifact = packageArtifact;
        methods = builtins.attrNames methods;
        guarantees = [];
        handlerDescriptor = {
          artifact = packageArtifact;
          entryPoint = "bin/aos-ebpf-lsm-provider";
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
          description = "Requires the selected BPF-LSM policy set.";
          methods = ["apply" "observe" "remove"];
          guarantees = [];
          strength = "required";
          fallback = null;
        };
    }
    (lib.mkIf cfg.enable {
      instances.${consumerInstance} = {};
      requests.policy-set = {
        requirement = alias;
        consumer = consumerInstance;
        scope = ["host-policy"];
        parameters = policyRequest;
      };
    })
  ];
}
