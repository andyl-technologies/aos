##! Authenticated ability contract shared by production nginx and its reference fixture.
{
  lib,
  providerArtifact,
  runtimeArtifact,
  hostResourceRuntime ? null,
  effectQualification ? false,
  providerStateQualification ? false,
}: let
  inherit (lib.abilities) schemas;
  serviceManagementContract = lib.abilities.interfaces.serviceManagement;

  interface = name: descriptor: {
    inherit name descriptor;
    abi = 1;
  };

  managedConfiguration =
    interface
    "aos.managed-configuration"
    "sha256:fce7ea027ff0640e13116a3501b96fd356ac96d47d82d26aff193d6d2bc8780e";
  credentialDelivery =
    interface
    "aos.credential-delivery"
    "sha256:e8c5924bd71f8c018958430a91907c662e09af55221d2c94a758dc4a1377d44f";
  serviceDefinition =
    interface
    "aos.service-definition"
    "sha256:71b6dad75359531ccfc92bfbb5824fb3555afb097e697d994ee6f9f862ae46af";
  nginxValidation =
    interface
    "aos.nginx-validation"
    "sha256:3aaa289923966ca40279d7030374aa6d72d0cbf07e655b9c61741ca5b59507e1";
  httpBackend =
    interface
    "aos.http-backend"
    "sha256:289893585ef1b59314c8adfb77c26e698d6db1333178e3b3d1e1e0c0b54754c0";
  serviceManagement = serviceManagementContract.interface;
  endpointEffects =
    interface
    "aos.network-endpoint-effects"
    "sha256:6b4d345ab4350917a04b770f0ac4b82888ffe6ef7e647caa9fe94ccb9f9dac6a";
  storageEffects =
    interface
    "aos.host-storage-effects"
    "sha256:5e0c90d7b65c40e72245dd1350bdae2c9f5c176ceb6caa9cb8789dc5448755c8";
  networkPolicyEffects =
    interface
    "aos.host-network-policy-effects"
    "sha256:e912beeec7f8d007704910c27cc8c7d3e75267e49679f6ff933577752556df0e";
  foregroundProcess =
    interface
    "aos.foreground-process"
    "sha256:6f692b67b0670968fb335b4ebe93951cd40bdedf925f98f025b93024b30b17cb";

  foregroundProcessSupervisionGuarantee = {
    name = "aos.foreground-process-supervision";
    version = 1;
    descriptor = "sha256:b213e3c6ef28e4930a1091296e28fbfddde9f539d2daeb0287edfe955047311a";
  };

  loopbackIngressGuarantee = lib.abilities.guarantee {
    name = "aos.guarantee.loopback-tcp-ingress-enforcement";
    version = 1;
    descriptor = "sha256:6b12b1c4db768f272434c6e43ca8c484887fc0fa3a51be2ae2784982325c2092";
  };
  loopbackEgressGuarantee = lib.abilities.guarantee {
    name = "aos.guarantee.loopback-tcp-egress-enforcement";
    version = 1;
    descriptor = "sha256:91fc94f9ff09a955256a2a86d1df6df00e1635c8fc035e2f68e262cbc29dcd53";
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

  string = schemas.string {
    maxLength = 65536;
    syntax = null;
  };

  revision = schemas.string {
    maxLength = 71;
    syntax = null;
  };

  optionalRevision = schemas.optional revision;

  localKeyString = schemas.string {
    maxLength = 128;
    syntax = "local-key-v1";
  };

  resourcePath = schemas.string {
    maxLength = 4096;
    syntax = null;
  };

  endpoint = schemas.record {
    fields = {
      address = schemas.string {
        maxLength = 15;
        syntax = null;
      };
      port = schemas.integer {
        minimum = 1024;
        maximum = 65535;
      };
      transport = schemas.enum ["tcp"];
    };
    optional = [];
  };

  endpointRequest = schemas.record {
    fields = {
      address = schemas.enum ["127.0.0.1"];
      port = schemas.integer {
        minimum = 0;
        maximum = 65535;
      };
      transport = schemas.enum ["tcp"];
    };
    optional = [];
  };

  storageRequest = schemas.record {
    fields = {
      cluster = localKeyString;
      lifetime = schemas.enum ["instance" "persistent"];
      owner = schemas.enum ["postgresql-slot" "root"];
      purpose = localKeyString;
    };
    optional = [];
  };

  networkPolicyRequest = requiredEndpoint:
    schemas.record {
      fields = {
        direction = schemas.enum ["egress" "ingress"];
        endpoint =
          if requiredEndpoint
          then endpoint
          else schemas.optional endpoint;
        protocol = schemas.enum ["tcp"];
      };
      optional = [];
    };

  revisionedObservation = schema: fields:
    schemas.record {
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
    (schemas.enum ["aos.ability.network-endpoint-observation/v1"])
    {
      endpoint = schemas.optional endpoint;
      owned = schemas.boolean;
    };

  storageObservation =
    revisionedObservation
    (schemas.enum ["aos.ability.host-storage-observation/v1"])
    {
      attached = schemas.boolean;
      exists = schemas.boolean;
      path = resourcePath;
    };

  networkPolicyObservation =
    revisionedObservation
    (schemas.enum ["aos.ability.host-network-policy-observation/v1"])
    {
      active = schemas.boolean;
      endpoint = schemas.optional endpoint;
    };

  credentialView = schemas.record {
    fields = {
      path = schemas.string {
        maxLength = 4096;
        syntax = null;
      };
      version = schemas.string {
        maxLength = 71;
        syntax = null;
      };
    };
    optional = [];
  };

  storagePaths = schemas.record {
    fields = {
      logs = string;
      runtime = string;
      state = string;
    };
    optional = [];
  };

  runtimeStoragePath = schemas.string {
    maxLength = 4096;
    syntax = null;
  };

  runtimeStoragePaths = schemas.record {
    fields = {
      logs = runtimeStoragePath;
      runtime = runtimeStoragePath;
      state = runtimeStoragePath;
    };
    optional = [];
  };

  nginxValidationRequest = schemas.record {
    fields = {
      candidate = schemas.boolean;
      credential_views = schemas.list {
        element = credentialView;
        maxItems = 1024;
      };
      storage_paths = schemas.optional runtimeStoragePaths;
    };
    optional = [];
  };

  consumerProbe = schemas.record {
    fields = {
      address = schemas.string {
        maxLength = 15;
        syntax = null;
      };
      execution_strategy = schemas.enum ["foreground-process" "managed-service"];
      port = schemas.integer {
        minimum = 1024;
        maximum = 65535;
      };
      tls_credential_path = schemas.string {
        maxLength = 4096;
        syntax = null;
      };
      tls_port = schemas.integer {
        minimum = 1024;
        maximum = 65535;
      };
    };
    optional = ["tls_credential_path" "tls_port"];
  };

  virtualHost = schemas.record {
    fields = {
      host = string;
      response_content = schemas.string {
        maxLength = 256;
        syntax = null;
      };
      response_identity = localKeyString;
      proxy_backend = schemas.boolean;
      tls = schemas.boolean;
      credential_version = schemas.string {
        maxLength = 71;
        syntax = null;
      };
    };
    optional = ["credential_version" "proxy_backend"];
  };

  method = targetResource: operationFamily: name: {
    inherit operationFamily targetResource;
    parameters = schemas.boolean;
    outputs = {};
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = schemas.boolean;
      observationEvidence = schemas.boolean;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };

  validationMethod = operationFamily: name:
    (method nginxValidation.name operationFamily name)
    // {parameters = nginxValidationRequest;};

  endpointEffectMethod = operationFamily: name: outputs: {
    targetResource = endpointEffects.name;
    inherit operationFamily outputs;
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

  storageEffectMethod = operationFamily: name: outputs: {
    targetResource = storageEffects.name;
    inherit operationFamily outputs;
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

  networkPolicyEffectMethod = operationFamily: name: parameters: outputs: guarantees: {
    targetResource = networkPolicyEffects.name;
    inherit operationFamily parameters outputs guarantees;
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
    requestSchema ? schemas.boolean,
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

  provider = import providerArtifact;
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
            configuration = output schemas.resourceReference;
            credential-view = output (schemas.optional schemas.resourceReference);
            manager = output schemas.resourceReference;
            rendered-configuration = output string;
            virtual-host-count = output (schemas.integer {
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
          export = terminalExport {
            name = nginxValidation.name;
            group = "nginx-validation";
            handler = "nginx-terminal";
            methods = {
              record = validationMethod {kind = "record-generation-association";} "record";
              release = validationMethod {kind = "release-resource";} "release";
              validate = validationMethod {kind = "validate-candidate";} "validate";
            };
          };
        }
        // runtimeAttrs;
    }
    // lib.optionalAttrs (hostResourceRuntime != null) {
      network-endpoint =
        {
          export = terminalExport {
            name = endpointEffects.name;
            group = "network-endpoint";
            handler = "native-network-endpoint";
            requestSchema = endpointRequest;
            selectedLifecycle = ephemeralLifecycle;
            methods = {
              materialize =
                endpointEffectMethod {
                  kind = "network-endpoint";
                  action = "materialize";
                } "materialize" {
                  endpoint = runtimeMethodOutput endpoint;
                };
              observe =
                endpointEffectMethod {
                  kind = "network-endpoint";
                  action = "observe";
                } "observe" {
                  endpoint = runtimeMethodOutput endpoint;
                };
              release = endpointEffectMethod {
                kind = "network-endpoint";
                action = "release";
              } "release" {};
            };
          };
        }
        // hostResourceRuntimeAttrs;

      network-policy =
        {
          export = terminalExport {
            name = networkPolicyEffects.name;
            group = "network-policy";
            handler = "native-host-network-policy";
            requestSchema = networkPolicyRequest false;
            selectedLifecycle = ephemeralLifecycle;
            guarantees = [loopbackEgressGuarantee loopbackIngressGuarantee];
            methods = {
              apply =
                networkPolicyEffectMethod {
                  kind = "host-network-policy";
                  action = "apply";
                } "apply" (networkPolicyRequest true) {
                  active = runtimeMethodOutput schemas.boolean;
                } [loopbackEgressGuarantee loopbackIngressGuarantee];
              observe =
                networkPolicyEffectMethod {
                  kind = "host-network-policy";
                  action = "observe";
                } "observe" (networkPolicyRequest true) {
                  active = runtimeMethodOutput schemas.boolean;
                } [loopbackEgressGuarantee loopbackIngressGuarantee];
              remove = networkPolicyEffectMethod {
                kind = "host-network-policy";
                action = "remove";
              } "remove" (networkPolicyRequest false) {} [];
            };
          };
        }
        // hostResourceRuntimeAttrs;

      storage =
        {
          export = terminalExport {
            name = storageEffects.name;
            group = "storage";
            handler = "native-host-storage";
            requestSchema = storageRequest;
            methods = {
              ensure =
                storageEffectMethod {
                  kind = "host-storage";
                  action = "ensure";
                } "ensure" {
                  path = runtimeMethodOutput resourcePath;
                };
              observe =
                storageEffectMethod {
                  kind = "host-storage";
                  action = "observe";
                } "observe" {
                  path = runtimeMethodOutput resourcePath;
                };
              release = storageEffectMethod {
                kind = "host-storage";
                action = "release";
              } "release" {};
            };
          };
        }
        // hostResourceRuntimeAttrs;
    };

  handlers =
    {
      nginx-terminal =
        {
          entryPoint = "bin/nginx";
          arguments = nginxValidationRequest;
          result = schemas.boolean;
        }
        // runtimeAttrs;
    }
    // lib.optionalAttrs (hostResourceRuntime != null) {
      native-network-endpoint =
        {
          entryPoint = "libexec/aos-network-endpoint-handler";
          arguments = endpointRequest;
          result = endpointObservation;
        }
        // hostResourceRuntimeAttrs;
      native-host-network-policy =
        {
          entryPoint = "libexec/aos-host-network-policy-handler";
          arguments = networkPolicyRequest false;
          result = networkPolicyObservation;
        }
        // hostResourceRuntimeAttrs;
      native-host-storage =
        {
          entryPoint = "libexec/aos-host-storage-handler";
          arguments = storageRequest;
          result = storageObservation;
        }
        // hostResourceRuntimeAttrs;
    };
in {
  config.aos.abilities.implementations =
    builtins.mapAttrs (
      _: implementation: {
        definition = implementation.export;
        artifact = implementation.artifact or null;
        handler =
          if implementation.export.handler == null
          then null
          else handlers.${implementation.export.handler};
      }
    )
    implementations;
}
