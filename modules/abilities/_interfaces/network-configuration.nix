##! Canonical provider-neutral host network configuration resource.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  alias = "network-configuration";
  interfaceName = "aos.network.configuration";

  optional = type: {
    type = types.optional type;
    optional = true;
  };
  text = maxLength:
    types.string {
      inherit maxLength;
      syntax = null;
    };
  exactSelectorVariants = {
    name = types.record {
      fields = {
        kind = types.enum ["name"];
        value = text 64;
      };
    };
    mac = types.record {
      fields = {
        kind = types.enum ["mac"];
        value = text 32;
      };
    };
  };
  exactSelector = types.taggedUnion {
    tag = "kind";
    variants = exactSelectorVariants;
  };
  selector = types.taggedUnion {
    tag = "kind";
    variants =
      exactSelectorVariants
      // {
        ethernet = types.record {
          fields.kind = types.enum ["ethernet"];
        };
      };
  };
  addresses = types.list {
    element = text 128;
    maxItems = 64;
    unique = true;
    canonicalOrder = true;
  };
  dnsServers = types.list {
    element = text 128;
    maxItems = 32;
    unique = true;
    canonicalOrder = true;
  };
  addressing = types.record {
    fields = {
      dhcp = types.boolean;
      inherit addresses;
      gateway = optional (text 128);
      dns = dnsServers;
      link_local = optional (types.enum ["ipv4" "ipv6" "both"]);
      ipv4_link_local_route = optional types.boolean;
    };
  };
  link = types.taggedUnion {
    tag = "kind";
    variants = {
      ethernet = types.record {
        fields = {
          kind = types.enum ["ethernet"];
          name = types.localKey;
          inherit selector addressing;
        };
      };
      vlan = types.record {
        fields = {
          kind = types.enum ["vlan"];
          name = types.localKey;
          parent = selector;
          id = types.integer {
            minimum = 1;
            maximum = 4094;
          };
          inherit addressing;
        };
      };
      bond = types.record {
        fields = {
          kind = types.enum ["bond"];
          name = types.localKey;
          members = types.list {
            element = selector;
            maxItems = 64;
            unique = true;
            canonicalOrder = true;
          };
          mode = text 64;
          inherit addressing;
        };
      };
    };
  };
  bootstrap = types.record {
    fields = {
      selector = exactSelector;
      inherit addresses;
      gateway = optional (text 128);
      dns = dnsServers;
    };
  };
  resolver = types.record {
    fields = {
      enabled = types.boolean;
      nameservers = types.list {
        element = text 128;
        maxItems = 32;
        unique = true;
        canonicalOrder = true;
      };
      search = types.list {
        element = text 253;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      dnssec = types.enum ["allow-downgrade" "no" "yes"];
    };
  };
  prerequisites = types.list {
    element = types.deferredResult types.resourceReference;
    maxItems = 64;
    unique = true;
    canonicalOrder = true;
  };
  policyType = types.record {
    fields = {
      authority = types.enum ["image" "operator"];
      links = types.list {
        element = link;
        maxItems = 256;
        unique = true;
        canonicalOrder = false;
      };
      inherit resolver prerequisites;
    };
  };
  applyInputType = types.record {
    fields.bootstrap = optional bootstrap;
  };
  emptyInputType = types.record {fields = {};};
  observationType = types.record {
    fields = {
      schema = types.enum ["aos.ability.network-configuration-observation/v1"];
      expected = policyType;
      applied_bootstrap = optional bootstrap;
      state = types.enum ["absent" "ready" "drifted" "unknown"];
      discrepancies = types.list {
        element = types.localKey;
        maxItems = 512;
        unique = true;
        canonicalOrder = true;
      };
    };
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  method = name: description: parameters: access: stopsProvider: outputs: {
    inherit description outputs;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    inherit parameters;
    targetResource = interfaceName;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  observation = phase:
    output phase "attempt" "Reports the exact observed host network configuration." observationType;
  methods = {
    apply = method "apply" "Converges the exact provider-neutral host network configuration." applyInputType "exclusive-write" false {
      observation = observation "runtime";
      retained-resource = output "runtime" "persistent" "References the retained network configuration." types.resourceReference;
    };
    observe = method "observe" "Observes the exact host network configuration." emptyInputType "read" false {
      observation = observation "observation";
    };
    remove = method "remove" "Releases the exact host network configuration owned by this controller." emptyInputType "exclusive-write" true {
      observation = observation "runtime";
    };
  };
  lifecycle.persistentDeleteMethod = null;
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = alias;
  };
  declaration = declareInterface {
    name = interfaceName;
    description = "Converges semantic host networking without exposing a service manager or configuration-file backend.";
    abi = 1;
    requestType = policyType;
    inherit methods lifecycle aggregation;
    outputs.resource =
      output "planning" "persistent" "References readiness for this exact network configuration." types.resourceReference;
    guarantees = [];
  };
  document = interfaceDocumentFromDeclaration declaration;
  identity = interfaceIdentity document;
  effectsAlias = "network-configuration-effects";
  effectsMethod = name: description: parameters: access: stopsProvider: {
    inherit description;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    inherit parameters;
    targetResource = interfaceName;
    outputs.observation =
      output
      (
        if name == "observe"
        then "observation"
        else "runtime"
      )
      "attempt"
      "Reports the exact terminal network-configuration state."
      observationType;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  effectsDeclaration = declareInterface {
    name = "aos.network.configuration-effects";
    description = "Executes one selected backend's checked effects for a provider-neutral host network configuration.";
    abi = 1;
    requestType = applyInputType;
    outputs = {};
    methods = {
      apply = effectsMethod "apply" "Applies a persistent policy with optional authorized early-network input." applyInputType "exclusive-write" false;
      observe = effectsMethod "observe" "Observes the exact applied host network state." applyInputType "read" false;
      remove = effectsMethod "remove" "Removes the exact owned host network state." applyInputType "exclusive-write" true;
    };
    inherit lifecycle;
    aggregation =
      aggregation
      // {
        controllerGroup = effectsAlias;
        # The owning controller and an authorized spanning transaction may both
        # receive grants to the same persistent network resource.
        rejectSlotCollisions = false;
      };
    configurationType = null;
    guarantees = [];
  };
  effectsDocument = interfaceDocumentFromDeclaration effectsDeclaration;
  effectsIdentity = interfaceIdentity effectsDocument;
  readView = {
    interface = {
      inherit alias declaration document identity observationType;
      requestType = policyType;
      types = {
        policy = policyType;
        inherit bootstrap;
        applyInput = applyInputType;
      };
      methods = builtins.attrNames methods;
      effects = {
        alias = effectsAlias;
        declaration = effectsDeclaration;
        document = effectsDocument;
        identity = effectsIdentity;
        methods = builtins.attrNames effectsDeclaration.methods;
        requestType = applyInputType;
        inherit observationType;
      };
    };
    declarations = {
      ${alias} = declaration;
      ${effectsAlias} = effectsDeclaration;
    };
  };
in {
  name = "networkConfiguration";
  inherit readView;
  module.config.aos.abilities.interfaces = readView.declarations;
}
