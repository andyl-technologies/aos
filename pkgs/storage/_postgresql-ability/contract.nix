##! Shared PostgreSQL ability contracts and pure provider.
{lib}: let
  inherit (lib.abilities) types;

  providerSource = ./provider;

  interfaceDeclaration = name: {
    inherit name;
    abi = 1;
  };
  postgresqlDeclaration = interfaceDeclaration "aos.postgresql";
  endpointDeclaration = interfaceDeclaration "aos.network-endpoint-effects";
  storageDeclaration = interfaceDeclaration "aos.host-storage-effects";
  networkPolicyDeclaration = interfaceDeclaration "aos.host-network-policy-effects";
  credentialDeclaration = interfaceDeclaration "aos.credential-delivery-effects";
  postgresqlEffectsDeclaration = interfaceDeclaration "aos.postgresql-effects";
  compatibleStateFormat = "sha256:3f1ee821c852480fa2cc3160555bbb187668c1509f84345d4339306910487596";
  incompatibleStateFormat = "sha256:8825d1eed586b8e50a61fc1ee0cd51330da8ae06b605c865b3201d64d426786d";

  loopbackIngressGuarantee = lib.abilities.guarantee {
    name = "aos.guarantee.loopback-tcp-ingress-enforcement";
    version = 1;
    semantics = "A successful apply installs a host policy that admits TCP ingress only to the requested 127.0.0.1 address and concrete port. A successful observe proves that exact rule remains active. Neither operation admits ingress to that port through a non-loopback address.";
  };

  string = maximum:
    types.string {
      maxLength = maximum;
      syntax = null;
    };
  localKey = types.string {
    maxLength = 128;
    syntax = "local-key-v1";
  };
  postgresqlName = types.string {
    maxLength = 63;
    syntax = "local-key-v1";
  };
  revision = string 71;
  optionalRevision = types.optional revision;
  path = string 4096;

  endpoint = types.record {
    fields = {
      address = string 15;
      port = types.integer {
        minimum = 1024;
        maximum = 65535;
      };
      transport = types.enum ["tcp"];
    };
    optional = [];
  };
  endpointRequest = types.record {
    fields = {
      address = types.enum ["127.0.0.1"];
      port = types.integer {
        minimum = 0;
        maximum = 65535;
      };
      transport = types.enum ["tcp"];
    };
    optional = [];
  };
  credentialView = types.record {
    fields = {
      path = path;
      version = revision;
    };
    optional = [];
  };
  credentialRequest = types.record {
    fields = {
      version = revision;
      view = localKey;
    };
    optional = [];
  };
  credentialObservation = types.record {
    fields = {
      delivered = types.boolean;
      observed_version = optionalRevision;
      requested_version = revision;
      schema = types.enum ["aos.ability.credential-delivery-observation/v1"];
      view = localKey;
    };
    optional = [];
  };
  storageRequest = types.record {
    fields = {
      cluster = localKey;
      lifetime = types.enum ["instance" "persistent"];
      owner = types.enum ["postgresql-slot" "root"];
      purpose = localKey;
    };
    optional = [];
  };
  networkPolicyRequest = requiredEndpoint:
    types.record {
      fields = {
        direction = types.enum ["ingress"];
        endpoint =
          if requiredEndpoint
          then endpoint
          else types.optional endpoint;
        protocol = types.enum ["tcp"];
      };
      optional = [];
    };
  postgresqlRequest = types.record {
    fields = {
      cluster = localKey;
      configuration_revision = revision;
      database = postgresqlName;
      credential_view = types.optional credentialView;
      endpoint = types.optional endpoint;
      role = postgresqlName;
      storage_path = types.optional path;
    };
    optional = [];
  };
  postgresqlContribution = types.record {
    fields = {
      cluster = localKey;
      database = postgresqlName;
      role = postgresqlName;
      credential_version = revision;
    };
    optional = [];
  };

  revisionedObservation = schema: fields:
    types.record {
      fields =
        fields
        // {
          observed_revision = optionalRevision;
          requested_revision = revision;
          inherit schema;
        };
      optional = [];
    };
  endpointObservation =
    revisionedObservation
    (types.enum ["aos.ability.network-endpoint-observation/v1"])
    {
      endpoint = types.optional endpoint;
      owned = types.boolean;
    };
  storageObservation =
    revisionedObservation
    (types.enum ["aos.ability.host-storage-observation/v1"])
    {
      attached = types.boolean;
      exists = types.boolean;
      path = path;
    };
  networkPolicyObservation =
    revisionedObservation
    (types.enum ["aos.ability.host-network-policy-observation/v1"])
    {
      active = types.boolean;
      endpoint = types.optional endpoint;
    };
  postgresqlObservation = types.record {
    fields = {
      cluster = localKey;
      database = postgresqlName;
      endpoint = types.optional endpoint;
      observed_revision = optionalRevision;
      production_control_path = types.enum ["/bin/postgresql-control"];
      ready = types.boolean;
      role = postgresqlName;
      schema = types.enum ["aos.ability.postgresql-observation/v1"];
      submitted_revision = revision;
    };
    optional = [];
  };

  output = schema: phase: lifetime: {
    inherit schema phase lifetime;
    visibility = "protected";
  };
  runtimeOutput = schema: lifetime: output schema "runtime" lifetime;
  observationOutput = schema: output schema "observation" "attempt";

  lifecycle = persistent: {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = !persistent;
    retainsPersistentByDefault = persistent;
    persistentDeleteMethod = null;
  };
  aggregation = group: {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = group;
  };
  requirementWithGuarantees = selected: methods: guarantees: {
    inherit (selected) abi descriptor;
    interface = selected.name;
    inherit methods guarantees;
    strength = "required";
    fallback = null;
  };
  requirement = selected: methods: requirementWithGuarantees selected methods [];
  outcome = evidence: {
    completionEvidence = evidence;
    observationEvidence = evidence;
    supportsRejectedBeforeEffect = true;
    indeterminate = "reconcile";
  };
  methodSemantics = name: {
    requiredTargetAccess =
      if builtins.elem name ["observe" "observe-boot" "observe-health" "validate" "verify"]
      then "read"
      else "exclusive-write";
    stopsProvider = name == "stop";
  };
  method = target: name: operationFamily: parameters: outputs: evidence: {
    targetResource = target;
    inherit parameters outputs;
    semantics = methodSemantics name;
    permittedOperations = [name];
    guarantees = [];
    outcome = outcome evidence;
  };

  endpointMethods = {
    materialize =
      method endpointDeclaration.name "materialize" {
        kind = "network-endpoint";
        action = "materialize";
      }
      endpointRequest {
        endpoint = runtimeOutput endpoint "instance";
      }
      endpointObservation;
    observe =
      method endpointDeclaration.name "observe" {
        kind = "network-endpoint";
        action = "observe";
      }
      endpointRequest {
        endpoint = runtimeOutput endpoint "instance";
      }
      endpointObservation;
    release =
      method endpointDeclaration.name "release" {
        kind = "network-endpoint";
        action = "release";
      }
      endpointRequest {}
      endpointObservation;
  };
  storageMethods = {
    ensure =
      method storageDeclaration.name "ensure" {
        kind = "host-storage";
        action = "ensure";
      }
      storageRequest {
        path = runtimeOutput path "instance";
      }
      storageObservation;
    observe =
      method storageDeclaration.name "observe" {
        kind = "host-storage";
        action = "observe";
      }
      storageRequest {
        path = runtimeOutput path "instance";
      }
      storageObservation;
    release =
      method storageDeclaration.name "release" {
        kind = "host-storage";
        action = "release";
      }
      storageRequest {}
      storageObservation;
  };
  networkPolicyMethods = let
    withEnforcement = methodContract:
      methodContract
      // {
        guarantees = [loopbackIngressGuarantee];
      };
  in {
    apply = withEnforcement (
      method networkPolicyDeclaration.name "apply" {
        kind = "host-network-policy";
        action = "apply";
      } (networkPolicyRequest true) {
        active = runtimeOutput types.boolean "instance";
      }
      networkPolicyObservation
    );
    observe = withEnforcement (
      method networkPolicyDeclaration.name "observe" {
        kind = "host-network-policy";
        action = "observe";
      } (networkPolicyRequest true) {
        active = runtimeOutput types.boolean "instance";
      }
      networkPolicyObservation
    );
    remove =
      method networkPolicyDeclaration.name "remove" {
        kind = "host-network-policy";
        action = "remove";
      } (networkPolicyRequest false) {}
      networkPolicyObservation;
  };
  credentialMethods = {
    acquire =
      method credentialDeclaration.name "acquire" {
        kind = "credential";
        action = "acquire";
      }
      credentialRequest {
        credential-view = runtimeOutput credentialView "instance";
      }
      credentialObservation;
    deliver =
      method credentialDeclaration.name "deliver" {
        kind = "credential";
        action = "deliver";
      }
      credentialRequest {
        credential-view = runtimeOutput credentialView "instance";
      }
      credentialObservation;
    release =
      method credentialDeclaration.name "release" {
        kind = "release-resource";
      }
      credentialRequest {}
      credentialObservation;
  };
  postgresqlMethods = {
    materialize =
      method postgresqlEffectsDeclaration.name "materialize" {
        kind = "prepare-managed-configuration";
      }
      postgresqlRequest {
        configuration-revision = runtimeOutput revision "persistent";
      }
      postgresqlObservation;
    observe =
      method postgresqlEffectsDeclaration.name "observe" {
        kind = "observe-readiness";
      }
      postgresqlRequest {
        observed-revision = observationOutput optionalRevision;
        ready = observationOutput types.boolean;
        submitted-revision = observationOutput revision;
      }
      postgresqlObservation;
    start =
      method postgresqlEffectsDeclaration.name "start" {
        kind = "service-lifecycle";
        action = "start";
      }
      postgresqlRequest {}
      postgresqlObservation;
    restart =
      method postgresqlEffectsDeclaration.name "restart" {
        kind = "service-lifecycle";
        action = "restart";
      }
      postgresqlRequest {}
      postgresqlObservation;
    stop =
      method postgresqlEffectsDeclaration.name "stop" {
        kind = "service-lifecycle";
        action = "stop";
      }
      postgresqlRequest {}
      postgresqlObservation;
  };

  terminalExport = {
    selected,
    group,
    handler,
    requestSchema,
    methods,
    persistent,
    guarantees ? [],
    selectedLifecycle ? lifecycle persistent,
  }:
    lib.abilities.define {
      interface = selected.name;
      abi = selected.abi;
      inherit requestSchema methods handler;
      outputs = {};
      lifecycle = selectedLifecycle;
      inherit guarantees;
      aggregation = aggregation group;
      requires = {};
      ownsResourceKinds = [selected.name];
    };

  interfaceFor = export:
    lib.abilities.interfaceIdentity (lib.abilities.interfaceDocument [] export);
  credentialEffects = interfaceFor (terminalExport {
    selected = credentialDeclaration;
    group = "credential";
    handler = "native-credential-delivery";
    requestSchema = credentialRequest;
    methods = credentialMethods;
    persistent = false;
  });
  endpointEffects = interfaceFor (terminalExport {
    selected = endpointDeclaration;
    group = "endpoint";
    handler = "native-network-endpoint";
    requestSchema = endpointRequest;
    methods = endpointMethods;
    persistent = false;
  });
  networkPolicyEffects = interfaceFor (terminalExport {
    selected = networkPolicyDeclaration;
    group = "network-policy";
    handler = "native-host-network-policy";
    requestSchema = networkPolicyRequest false;
    methods = networkPolicyMethods;
    persistent = false;
    guarantees = [loopbackIngressGuarantee];
  });
  postgresqlEffects = interfaceFor (terminalExport {
    selected = postgresqlEffectsDeclaration;
    group = "postgresql-terminal";
    handler = "native-postgresql";
    requestSchema = postgresqlRequest;
    methods = postgresqlMethods;
    persistent = true;
  });
  storageEffects = interfaceFor (terminalExport {
    selected = storageDeclaration;
    group = "storage";
    handler = "native-host-storage";
    requestSchema = storageRequest;
    methods = storageMethods;
    persistent = true;
    selectedLifecycle = {
      stableResourceIdentity = true;
      releasesEphemeralOnDisable = true;
      retainsPersistentByDefault = true;
      persistentDeleteMethod = null;
    };
  });

  postgresqlProvider = import ./provider {
    interfaces = {
      inherit
        credentialEffects
        endpointEffects
        networkPolicyEffects
        postgresqlEffects
        storageEffects
        ;
    };
    inherit loopbackIngressGuarantee;
  };

  postgresqlInterface = interfaceFor (postgresqlExport null);

  postgresqlExport = stateFormat:
    lib.abilities.define {
      interface = postgresqlDeclaration.name;
      abi = postgresqlDeclaration.abi;
      requestSchema = postgresqlContribution;
      outputs.clusters = output (types.map {
        keyMaxLength = 128;
        keySyntax = "local-key-v1";
        maxEntries = 64;
        value = types.resourceReference;
      }) "planning" "persistent";
      methods = {};
      lifecycle = lifecycle true;
      guarantees = [];
      aggregation = aggregation "postgresql";
      requires = {
        credential = requirement credentialEffects ["acquire" "deliver" "release"];
        endpoint = requirement endpointEffects ["materialize" "observe" "release"];
        network-policy =
          requirementWithGuarantees
          networkPolicyEffects
          ["apply" "observe" "remove"]
          [loopbackIngressGuarantee];
        postgresql-terminal = requirement postgresqlEffects ["materialize" "observe" "restart" "start" "stop"];
        storage = requirement storageEffects ["ensure" "observe" "release"];
      };
      composeEntry = "compose";
      transitionEntry = "transition";
      ownsResourceKinds =
        [postgresqlDeclaration.name]
        ++ lib.optional (stateFormat != null) postgresqlEffectsDeclaration.name;
      inherit stateFormat;
      compose = postgresqlProvider.compose;
      transition = postgresqlProvider.transition;
    };
in {
  inherit
    aggregation
    compatibleStateFormat
    credentialEffects
    credentialMethods
    credentialObservation
    credentialRequest
    endpointEffects
    endpointMethods
    endpointObservation
    endpointRequest
    incompatibleStateFormat
    lifecycle
    loopbackIngressGuarantee
    networkPolicyEffects
    networkPolicyMethods
    networkPolicyObservation
    networkPolicyRequest
    output
    postgresqlContribution
    postgresqlEffects
    postgresqlExport
    postgresqlInterface
    postgresqlMethods
    postgresqlObservation
    postgresqlProvider
    postgresqlRequest
    providerSource
    requirement
    requirementWithGuarantees
    storageEffects
    storageMethods
    storageObservation
    storageRequest
    terminalExport
    ;
}
