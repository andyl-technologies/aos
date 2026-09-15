##! Authenticated ability contract shared by production nginx and its reference fixture.
{
  lib,
  providerArtifact,
  runtimeArtifact,
  hostResourceRuntime ? null,
  effectQualification ? false,
  providerStateQualification ? false,
  qualificationClaims ? {},
}: let
  inherit (lib.abilities) types;
  serviceManagementContract = lib.abilities.interfaces.serviceManagement;
  runtimeInterfaces = import ./_nginx-runtime-interfaces.nix {
    inherit (lib.abilities) declareInterface guarantee interfaceDocumentFromDeclaration interfaceIdentity;
    inherit (lib.abilities) types;
  };

  managedConfiguration = runtimeInterfaces.managedConfiguration.interface;
  credentialDelivery = runtimeInterfaces.credentialDelivery.interface;
  serviceDefinition = runtimeInterfaces.serviceDefinition.interface;
  nginxValidationDeclaration = {
    name = "aos.nginx-validation";
    abi = 1;
  };
  httpBackend = runtimeInterfaces.httpBackend.interface;
  serviceManagement = serviceManagementContract.interface;
  endpointEffectsDeclaration = {
    name = "aos.network-endpoint-effects";
    abi = 1;
  };
  storageEffectsDeclaration = {
    name = "aos.host-storage-effects";
    abi = 1;
  };
  networkPolicyEffectsDeclaration = {
    name = "aos.host-network-policy-effects";
    abi = 1;
  };
  foregroundProcess = runtimeInterfaces.foregroundProcess.interface;

  foregroundProcessSupervisionGuarantee = lib.abilities.guarantee {
    name = "aos.foreground-process-supervision";
    version = 1;
    semantics = "the application-container executor retains and observes the exact declared foreground process";
  };

  loopbackIngressGuarantee = lib.abilities.guarantee {
    name = "aos.guarantee.loopback-tcp-ingress-enforcement";
    version = 1;
    semantics = "A successful apply installs a host policy that admits TCP ingress only to the requested 127.0.0.1 address and concrete port. A successful observe proves that exact rule remains active. Neither operation admits ingress to that port through a non-loopback address.";
  };
  loopbackEgressGuarantee = lib.abilities.guarantee {
    name = "aos.guarantee.loopback-tcp-egress-enforcement";
    version = 1;
    semantics = "A successful apply installs a host policy that admits TCP egress to the requested endpoint only through its 127.0.0.1 address and concrete port. A successful observe proves that exact rule remains active. Neither operation admits egress to that port through a non-loopback address.";
  };

  lifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = true;
    persistentDeleteMethod = null;
  };

  ephemeralLifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };

  aggregation = group: {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = group;
  };

  requirement = selected: methods: strength: fallback: {
    inherit (selected) abi descriptor;
    interface = selected.name;
    inherit methods strength fallback;
    guarantees = [];
  };

  required = selected:
    requirement selected [] "required" null;

  methodRequirement = selected: methods:
    requirement selected methods "required" null;

  methodRequirementWithGuarantees = selected: methods: guarantees:
    (methodRequirement selected methods) // {inherit guarantees;};

  output = schema: {
    inherit schema;
    phase = "planning";
    visibility = "protected";
    lifetime = "instance";
  };

  string = types.string {
    maxLength = 65536;
    syntax = null;
  };

  revision = types.string {
    maxLength = 71;
    syntax = null;
  };

  optionalRevision = types.optional revision;

  localKeyString = types.string {
    maxLength = 128;
    syntax = "local-key-v1";
  };

  resourcePath = types.string {
    maxLength = 4096;
    syntax = null;
  };

  endpoint = types.record {
    fields = {
      address = types.string {
        maxLength = 15;
        syntax = null;
      };
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

  storageRequest = types.record {
    fields = {
      cluster = localKeyString;
      lifetime = types.enum ["instance" "persistent"];
      owner = types.enum ["postgresql-slot" "root"];
      purpose = localKeyString;
    };
    optional = [];
  };

  networkPolicyRequest = requiredEndpoint:
    types.record {
      fields = {
        direction = types.enum ["egress" "ingress"];
        endpoint =
          if requiredEndpoint
          then endpoint
          else types.optional endpoint;
        protocol = types.enum ["tcp"];
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
      path = resourcePath;
    };

  networkPolicyObservation =
    revisionedObservation
    (types.enum ["aos.ability.host-network-policy-observation/v1"])
    {
      active = types.boolean;
      endpoint = types.optional endpoint;
    };

  credentialView = types.record {
    fields = {
      path = types.string {
        maxLength = 4096;
        syntax = null;
      };
      version = types.string {
        maxLength = 71;
        syntax = null;
      };
    };
    optional = [];
  };

  storagePaths = types.record {
    fields = {
      logs = string;
      runtime = string;
      state = string;
    };
    optional = [];
  };

  runtimeStoragePath = types.string {
    maxLength = 4096;
    syntax = null;
  };

  runtimeStoragePaths = types.record {
    fields = {
      logs = runtimeStoragePath;
      runtime = runtimeStoragePath;
      state = runtimeStoragePath;
    };
    optional = [];
  };

  nginxValidationRequest = types.record {
    fields = {
      candidate = types.boolean;
      credential_views = types.list {
        element = credentialView;
        maxItems = 1024;
      };
      storage_paths = types.optional runtimeStoragePaths;
    };
    optional = [];
  };

  consumerProbe = types.record {
    fields = {
      address = types.string {
        maxLength = 15;
        syntax = null;
      };
      execution_strategy = types.enum ["foreground-process" "managed-service"];
      port = types.integer {
        minimum = 1024;
        maximum = 65535;
      };
      tls_credential_path = types.string {
        maxLength = 4096;
        syntax = null;
      };
      tls_port = types.integer {
        minimum = 1024;
        maximum = 65535;
      };
    };
    optional = ["tls_credential_path" "tls_port"];
  };

  virtualHost = types.record {
    fields = {
      host = string;
      response_content = types.string {
        maxLength = 256;
        syntax = null;
      };
      response_identity = localKeyString;
      proxy_backend = types.boolean;
      tls = types.boolean;
      credential_version = types.string {
        maxLength = 71;
        syntax = null;
      };
    };
    optional = ["credential_version" "proxy_backend"];
  };

  methodSemantics = name: {
    requiredTargetAccess =
      if builtins.elem name ["observe" "observe-boot" "observe-health" "validate" "verify"]
      then "read"
      else "exclusive-write";
    stopsProvider = name == "stop";
  };
  method = targetResource: name: {
    inherit targetResource;
    semantics = methodSemantics name;
    parameters = types.boolean;
    outputs = {};
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = types.boolean;
      observationEvidence = types.boolean;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };

  validationMethod = name:
    (method nginxValidationDeclaration.name name)
    // {parameters = nginxValidationRequest;};

  endpointEffectMethod = name: outputs: {
    targetResource = endpointEffectsDeclaration.name;
    inherit outputs;
    semantics = methodSemantics name;
    parameters = endpointRequest;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = endpointObservation;
      observationEvidence = endpointObservation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };

  storageEffectMethod = name: outputs: {
    targetResource = storageEffectsDeclaration.name;
    inherit outputs;
    semantics = methodSemantics name;
    parameters = storageRequest;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = storageObservation;
      observationEvidence = storageObservation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };

  networkPolicyEffectMethod = name: parameters: outputs: guarantees: {
    targetResource = networkPolicyEffectsDeclaration.name;
    inherit parameters outputs guarantees;
    semantics = methodSemantics name;
    permittedOperations = [name];
    outcome = {
      completionEvidence = networkPolicyObservation;
      observationEvidence = networkPolicyObservation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };

  runtimeMethodOutput = schema: {
    inherit schema;
    phase = "runtime";
    visibility = "protected";
    lifetime = "instance";
  };

  terminalExport = {
    name,
    group,
    handler,
    methods,
    requestSchema ? types.boolean,
    selectedLifecycle ? lifecycle,
    guarantees ? [],
  }:
    lib.abilities.define {
      interface = name;
      abi = 1;
      inherit requestSchema;
      outputs = {};
      inherit methods;
      lifecycle = selectedLifecycle;
      inherit guarantees;
      aggregation = aggregation group;
      requires = {};
      ownsResourceKinds = [name];
      inherit handler;
    };

  nginxValidationDefinition = terminalExport {
    name = nginxValidationDeclaration.name;
    group = "nginx-validation";
    handler = "nginx-terminal";
    methods = {
      record = validationMethod "record";
      release = validationMethod "release";
      validate = validationMethod "validate";
    };
  };
  endpointEffectsDefinition = terminalExport {
    name = endpointEffectsDeclaration.name;
    group = "network-endpoint";
    handler = "native-network-endpoint";
    requestSchema = endpointRequest;
    selectedLifecycle = ephemeralLifecycle;
    methods = {
      materialize = endpointEffectMethod "materialize" {
        endpoint = runtimeMethodOutput endpoint;
      };
      observe = endpointEffectMethod "observe" {
        endpoint = runtimeMethodOutput endpoint;
      };
      release = endpointEffectMethod "release" {};
    };
  };
  networkPolicyEffectsDefinition = terminalExport {
    name = networkPolicyEffectsDeclaration.name;
    group = "network-policy";
    handler = "native-host-network-policy";
    requestSchema = networkPolicyRequest false;
    selectedLifecycle = ephemeralLifecycle;
    guarantees = [loopbackEgressGuarantee loopbackIngressGuarantee];
    methods = {
      apply = networkPolicyEffectMethod "apply" (networkPolicyRequest true) {
        active = runtimeMethodOutput types.boolean;
      } [loopbackEgressGuarantee loopbackIngressGuarantee];
      observe = networkPolicyEffectMethod "observe" (networkPolicyRequest true) {
        active = runtimeMethodOutput types.boolean;
      } [loopbackEgressGuarantee loopbackIngressGuarantee];
      remove = networkPolicyEffectMethod "remove" (networkPolicyRequest false) {} [];
    };
  };
  storageEffectsDefinition = terminalExport {
    name = storageEffectsDeclaration.name;
    group = "storage";
    handler = "native-host-storage";
    requestSchema = storageRequest;
    methods = {
      ensure = storageEffectMethod "ensure" {
        path = runtimeMethodOutput resourcePath;
      };
      observe = storageEffectMethod "observe" {
        path = runtimeMethodOutput resourcePath;
      };
      release = storageEffectMethod "release" {};
    };
  };
  interfaceFor = export:
    lib.abilities.interfaceIdentity (lib.abilities.interfaceDocument [] export);
  nginxValidation = interfaceFor nginxValidationDefinition;
  endpointEffects = interfaceFor endpointEffectsDefinition;
  networkPolicyEffects = interfaceFor networkPolicyEffectsDefinition;
  storageEffects = interfaceFor storageEffectsDefinition;

  provider = import providerArtifact {
    interfaces = {
      inherit
        credentialDelivery
        endpointEffects
        foregroundProcess
        httpBackend
        managedConfiguration
        networkPolicyEffects
        nginxValidation
        serviceDefinition
        serviceManagement
        storageEffects
        ;
    };
    serviceFeatures = builtins.attrValues serviceManagementContract.features;
    inherit
      foregroundProcessSupervisionGuarantee
      loopbackIngressGuarantee
      loopbackEgressGuarantee
      ;
  };
  runtimeAttrs = lib.optionalAttrs (runtimeArtifact != null) {
    artifact = runtimeArtifact;
  };
  hostResourceRuntimeAttrs = lib.optionalAttrs (hostResourceRuntime != null) {
    artifact = hostResourceRuntime;
  };
in let
  implementations =
    {
      nginx = {
        export = lib.abilities.define {
          interface = "aos.nginx";
          abi = 1;
          requestSchema = virtualHost;
          configurationSchema = consumerProbe;
          outputs = {
            configuration = output types.resourceReference;
            credential-view = output (types.optional types.resourceReference);
            manager = output types.resourceReference;
            rendered-configuration = output string;
            virtual-host-count = output (types.integer {
              minimum = 0;
              maximum = 1024;
            });
          };
          methods = {};
          inherit lifecycle;
          guarantees = [];
          aggregation = aggregation "nginx";
          requires =
            {
              configuration = required managedConfiguration;
              backend = requirement httpBackend [] "advisory" {
                outputs.endpoints = null;
              };
              credential = requirement credentialDelivery [] "advisory" {
                outputs.credential-views = {};
              };
              endpoint = methodRequirement endpointEffects ["materialize" "observe" "release"];
              network-policy =
                methodRequirementWithGuarantees
                networkPolicyEffects
                ["apply" "observe" "remove"]
                [loopbackEgressGuarantee loopbackIngressGuarantee];
              storage = methodRequirement storageEffects ["ensure" "observe" "release"];
              service = required serviceDefinition;
              validation-terminal = methodRequirement nginxValidation ["record" "release" "validate"];
            }
            // (
              if hostResourceRuntime != null
              then {
                service-terminal =
                  requirement serviceManagement ["observe" "reload" "restart" "start" "stop"] "required" null
                  // {guarantees = builtins.attrValues serviceManagementContract.features;};
              }
              else {
                service-terminal =
                  requirement serviceManagement ["observe" "reload" "restart" "start" "stop"] "required" null
                  // {guarantees = builtins.attrValues serviceManagementContract.features;};
                service-terminal-foreground =
                  requirement foregroundProcess ["observe" "start" "stop"] "required" null
                  // {guarantees = [foregroundProcessSupervisionGuarantee];};
                service-terminal-system-container =
                  requirement serviceManagement ["observe" "reload" "restart" "start" "stop"] "required" null
                  // {guarantees = builtins.attrValues serviceManagementContract.features;};
              }
            );
          composeEntry = "compose";
          transitionEntry = "transition";
          ownsResourceKinds = ["aos.nginx"];
          compose = provider.compose;
          transition =
            if providerStateQualification
            then provider.providerStateQualificationTransition
            else if effectQualification
            then provider.effectQualificationTransition
            else provider.transition;
        };
      };

      nginx-validation =
        {
          export = nginxValidationDefinition;
        }
        // runtimeAttrs;
    }
    // lib.optionalAttrs (hostResourceRuntime != null) {
      network-endpoint =
        {
          export = endpointEffectsDefinition;
        }
        // hostResourceRuntimeAttrs;

      network-policy =
        {
          export = networkPolicyEffectsDefinition;
        }
        // hostResourceRuntimeAttrs;

      storage =
        {
          export = storageEffectsDefinition;
        }
        // hostResourceRuntimeAttrs;
    };

  handlers =
    {
      nginx-terminal =
        {
          entryPoint = "bin/nginx";
          arguments = nginxValidationRequest;
          result = types.boolean;
        }
        // runtimeAttrs;
    }
    // lib.optionalAttrs (hostResourceRuntime != null) {
      native-network-endpoint =
        {
          entryPoint = "libexec/aos-network-endpoint-handler-v1";
          arguments = endpointRequest;
          result = endpointObservation;
        }
        // hostResourceRuntimeAttrs;
      native-host-network-policy =
        {
          entryPoint = "libexec/aos-host-network-policy-handler-v1";
          arguments = networkPolicyRequest false;
          result = networkPolicyObservation;
        }
        // hostResourceRuntimeAttrs;
      native-host-storage =
        {
          entryPoint = "libexec/aos-host-storage-handler-v1";
          arguments = storageRequest;
          result = storageObservation;
        }
        // hostResourceRuntimeAttrs;
    };
in {
  config.aos.abilities = lib.abilities.projectDefinitions (
    builtins.mapAttrs (
      name: implementation:
        {
          definition = implementation.export;
          artifact = implementation.artifact or null;
          handler =
            if implementation.export.handler == null
            then null
            else handlers.${implementation.export.handler};
        }
        // lib.optionalAttrs (builtins.hasAttr name qualificationClaims) {
          qualification = qualificationClaims.${name};
        }
    )
    implementations
  );
}
