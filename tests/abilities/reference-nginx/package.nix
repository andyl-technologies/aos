##! Production ability-package companion for the nginx lifecycle fixture.
{
  lib,
  mkDerivation,
  credentialRuntime ? ./providers/credential,
  hostResourceRuntime ? systemdRuntime,
  managedConfigurationRuntime ? ./providers/managed-configuration,
  nginxRuntime ? ../../../pkgs/networking/_nginx-ability-provider,
  systemdRuntime ? ./providers/systemd,
  transitionTransform ? transition: transition,
}: let
  inherit (lib.abilities) schemas;

  nginxArtifact = ../../../pkgs/networking/_nginx-ability-provider;
  nginxProvider = import nginxArtifact;
  managedConfigurationArtifact = ./providers/managed-configuration;
  httpBackendRegistryArtifact = ./providers/http-backend-registry;
  credentialArtifact = ./providers/credential;
  systemdArtifact = ./providers/systemd;

  interface = name: descriptor: {
    inherit name descriptor;
    abi = 1;
  };

  managedConfiguration =
    interface
    "aos.managed-configuration"
    "sha256:f2f4174c1b63997d056df99fe7eeb1d07c37a52f88588e03163bc8bf536ea802";
  credentialDelivery =
    interface
    "aos.credential-delivery"
    "sha256:e8c5924bd71f8c018958430a91907c662e09af55221d2c94a758dc4a1377d44f";
  credentialDeliveryEffects =
    interface
    "aos.credential-delivery-effects"
    "sha256:bc251c0837c1d453a6c5840d9146d9e27a95ad82032d9b4c60baf40d293cf1eb";
  systemdService =
    interface
    "aos.systemd-service"
    "sha256:c74a42b33fc3b7455be4d0cc7e57f7cb1f5f71886b61e6dd359456bf65b2368d";
  nginxValidation =
    interface
    "aos.nginx-validation"
    "sha256:3aaa289923966ca40279d7030374aa6d72d0cbf07e655b9c61741ca5b59507e1";
  httpBackend =
    interface
    "aos.http-backend"
    "sha256:289893585ef1b59314c8adfb77c26e698d6db1333178e3b3d1e1e0c0b54754c0";
  endpointEffects =
    interface
    "aos.network-endpoint-effects"
    "sha256:6b4d345ab4350917a04b770f0ac4b82888ffe6ef7e647caa9fe94ccb9f9dac6a";
  networkPolicyEffects =
    interface
    "aos.host-network-policy-effects"
    "sha256:e912beeec7f8d007704910c27cc8c7d3e75267e49679f6ff933577752556df0e";
  managedConfigurationEffects =
    interface
    "aos.managed-configuration-effects"
    "sha256:682ee08aadd9d0198b409146a373bf38d901ba530b74180400c9087616a41dab";
  systemdServiceEffects =
    interface
    "aos.systemd-service-effects"
    "sha256:383803bfd7eb105968a80a796fc4726b5663890e88220d26b20dbd2b33349b50";
  foregroundProcess =
    interface
    "aos.foreground-process"
    "sha256:6f692b67b0670968fb335b4ebe93951cd40bdedf925f98f025b93024b30b17cb";
  nginxInterface =
    interface
    "aos.nginx"
    "sha256:dd3a483912cab00425d3a9af94af01503986f486412166e64b76ab5d79cdde57";

  localSystemdManagerGuarantee = {
    name = "aos.local-systemd-manager";
    version = 1;
    descriptor = "sha256:50995c1c62000543639c8d9f85995c35cc44a9022933ed79e5447654593291d4";
  };
  systemContainerManagerDelegationGuarantee = {
    name = "aos.system-container-manager-delegation";
    version = 1;
    descriptor = "sha256:a811c4d2cc0fd8e09a019ae518bbe95f393ed5bc3265a1b72902adfa7325ceda";
  };
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

  credentialEffectsLifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };

  foregroundProcessLifecycle = {
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

  foregroundProcessRequest = schemas.record {
    fields = {
      arguments = schemas.list {
        element = schemas.string {
          maxLength = 4096;
          syntax = null;
        };
        maxItems = 128;
      };
      artifact = schemas.artifactReference;
      entry_point = schemas.string {
        maxLength = 4096;
        syntax = null;
      };
    };
    optional = [];
  };

  foregroundProcessObservation = schemas.record {
    fields = {
      process_identity = schemas.optional (schemas.string {
        maxLength = 1024;
        syntax = null;
      });
      running = schemas.boolean;
      schema = schemas.enum ["aos.ability.foreground-process-observation/v1"];
    };
    optional = [];
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

  backendEndpoints = schemas.optional (schemas.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 1024;
    value = schemas.optional endpoint;
  });

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

  credentialRequest = schemas.record {
    fields = {
      version = schemas.string {
        maxLength = 71;
        syntax = null;
      };
      view = localKeyString;
    };
    optional = [];
  };

  credentialObservation = schemas.record {
    fields = {
      delivered = schemas.boolean;
      observed_version = schemas.optional (schemas.string {
        maxLength = 71;
        syntax = null;
      });
      requested_version = schemas.string {
        maxLength = 71;
        syntax = null;
      };
      schema = schemas.enum ["aos.ability.credential-delivery-observation/v1"];
      view = localKeyString;
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

  localKeyString = schemas.string {
    maxLength = 128;
    syntax = "local-key-v1";
  };

  consumerProbe = schemas.record {
    fields = {
      address = schemas.string {
        maxLength = 15;
        syntax = null;
      };
      execution_strategy = schemas.enum ["foreground-process" "systemd-manager"];
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

  resourceMap = schemas.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 1024;
    value = schemas.resourceReference;
  };

  stringMap = schemas.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 1024;
    value = string;
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

  managedVirtualHost = schemas.record {
    fields = {
      backend_endpoint = endpoint;
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
    optional = ["backend_endpoint" "credential_version" "proxy_backend"];
  };

  recoverableMethods = ["acquire" "deliver" "observe" "prepare" "publish" "record" "release" "stop" "validate"];

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
      indeterminate =
        if builtins.elem name recoverableMethods
        then "reconcile"
        else "intervention-required";
    };
  };

  methodWithOutputs = targetResource: operationFamily: name: outputs:
    (method targetResource operationFamily name) // {inherit outputs;};

  foregroundProcessMethod = operationFamily: name:
    (method foregroundProcess.name operationFamily name)
    // {
      outcome = {
        completionEvidence = foregroundProcessObservation;
        observationEvidence = foregroundProcessObservation;
        supportsRejectedBeforeEffect = true;
        indeterminate = "reconcile";
      };
    };

  validationMethod = operationFamily: name:
    (method nginxValidation.name operationFamily name)
    // {parameters = nginxValidationRequest;};

  credentialEffectMethod = operationFamily: name: outputs:
    (methodWithOutputs credentialDeliveryEffects.name operationFamily name outputs)
    // {
      parameters = credentialRequest;
      outcome = {
        completionEvidence = credentialObservation;
        observationEvidence = credentialObservation;
        supportsRejectedBeforeEffect = true;
        indeterminate = "reconcile";
      };
    };

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

  managedConfigurationProvider = import ./providers/managed-configuration/default.nix;
  credentialProvider = import ./providers/credential/default.nix;
  systemdProvider = import ./providers/systemd/default.nix;
  httpBackendRegistryProvider = import ./providers/http-backend-registry/default.nix;
  baseNginxAbilityPackage = import ../../../pkgs/networking/_nginx-ability-contract.nix {
    inherit lib hostResourceRuntime;
    providerArtifact = nginxArtifact;
    runtimeArtifact = nginxRuntime;
  };
  nginxAbilityPackage =
    baseNginxAbilityPackage
    // {
      exports =
        baseNginxAbilityPackage.exports
        // {
          nginx =
            baseNginxAbilityPackage.exports.nginx
            // {
              export =
                baseNginxAbilityPackage.exports.nginx.export
                // {
                  transition = transitionTransform baseNginxAbilityPackage.exports.nginx.export.transition;
                };
            };
        };
    };
in let
  mkPackage = pname: src: abilityPackage:
    mkDerivation {
      inherit pname src abilityPackage;
      version = "1.0.0";

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/share/${pname}"
            printf '%s\n' 'production companion payload' > "$out/share/${pname}/README"
          '';
        }
      ];

      meta = {
        description = "Production nginx ability companion fixture";
        license = "Apache-2.0";
      };
    };

  common = {
    activationMode = "structured-effects";
    ownership = [[]];
  };
in {
  consumer = mkPackage "ability-reference-nginx-consumer" nginxArtifact {
    activationMode = "contracts-only";
    requirements.nginx = required nginxInterface;
    ownership = [];
  };

  backend-consumer = mkPackage "ability-reference-nginx-backend-consumer" nginxArtifact {
    activationMode = "contracts-only";
    requirements = {
      nginx = required nginxInterface;
      backend = required httpBackend;
    };
    ownership = [];
  };

  backend-registry = mkPackage "ability-reference-http-backend-registry" httpBackendRegistryArtifact {
    activationMode = "contracts-only";
    ownership = [];
    exports.http-backend = {
      artifact = httpBackendRegistryArtifact;
      export = lib.abilities.define {
        interface = httpBackend.name;
        abi = httpBackend.abi;
        requestSchema = endpoint;
        configurationSchema = null;
        outputs.endpoints = output backendEndpoints;
        methods = {};
        inherit lifecycle;
        guarantees = [];
        aggregation = aggregation "backend";
        requires = {};
        composeEntry = "compose";
        transitionEntry = "transition";
        ownsResourceKinds = [];
        compose = httpBackendRegistryProvider.compose;
        transition = httpBackendRegistryProvider.transition;
      };
    };
  };

  nginx = mkPackage "ability-reference-nginx" nginxArtifact nginxAbilityPackage;

  managed-configuration = mkPackage "ability-reference-managed-configuration" managedConfigurationArtifact (common
    // {
      exports = {
        managed-configuration = {
          artifact = managedConfigurationArtifact;
          export = lib.abilities.define {
            interface = managedConfiguration.name;
            abi = managedConfiguration.abi;
            requestSchema = schemas.record {
              fields = {
                virtualHosts = schemas.list {
                  element = managedVirtualHost;
                  maxItems = 1024;
                };
                consumer_content_revision = string;
                consumer_controller_revision = string;
                consumer_instance = string;
                consumer_probe = consumerProbe;
                consumer_storage_paths = storagePaths;
              };
              optional = [];
            };
            outputs = {
              published-configurations = output resourceMap;
              rendered-configurations = output stringMap;
            };
            methods = {};
            inherit lifecycle;
            guarantees = [];
            aggregation = aggregation "configuration";
            requires.effects = methodRequirement managedConfigurationEffects ["prepare" "publish" "release"];
            composeEntry = "compose";
            transitionEntry = "transition";
            ownsResourceKinds = [managedConfiguration.name];
            compose = managedConfigurationProvider.compose;
            transition = transitionTransform managedConfigurationProvider.transition;
          };
        };
        managed-configuration-effects = {
          artifact = managedConfigurationRuntime;
          export = terminalExport {
            name = managedConfigurationEffects.name;
            group = "managed-configuration-effects";
            handler = "managed-configuration-terminal";
            methods = {
              prepare = method managedConfigurationEffects.name {kind = "prepare-managed-configuration";} "prepare";
              publish = method managedConfigurationEffects.name {kind = "publish-configuration";} "publish";
              release = method managedConfigurationEffects.name {kind = "release-resource";} "release";
            };
          };
        };
      };
      handlers.managed-configuration-terminal = {
        artifact = managedConfigurationRuntime;
        entryPoint = "bin/.aos-package-runtime-unwrapped";
        arguments = schemas.boolean;
        result = schemas.boolean;
      };
    });

  credential = mkPackage "ability-reference-credential" credentialArtifact (common
    // {
      exports = {
        credential-delivery = {
          artifact = credentialArtifact;
          export = lib.abilities.define {
            interface = credentialDelivery.name;
            abi = credentialDelivery.abi;
            requestSchema = schemas.record {
              fields = {
                hosts = schemas.list {
                  element = string;
                  maxItems = 1024;
                };
                version = schemas.string {
                  maxLength = 71;
                  syntax = null;
                };
              };
              optional = [];
            };
            outputs.credential-views = output resourceMap;
            methods = {};
            inherit lifecycle;
            guarantees = [];
            aggregation = aggregation "credentials";
            requires.effects = methodRequirement credentialDeliveryEffects ["acquire" "deliver" "release"];
            composeEntry = "compose";
            transitionEntry = "transition";
            ownsResourceKinds = [credentialDelivery.name];
            compose = credentialProvider.compose;
            transition = transitionTransform credentialProvider.transition;
          };
        };
        credential-delivery-effects = {
          artifact = credentialRuntime;
          export = terminalExport {
            name = credentialDeliveryEffects.name;
            group = "credential-delivery-effects";
            handler = "native-credential-delivery-v1";
            requestSchema = credentialRequest;
            selectedLifecycle = credentialEffectsLifecycle;
            methods = {
              acquire =
                credentialEffectMethod {
                  kind = "credential";
                  action = "acquire";
                } "acquire" {
                  credential-view = runtimeMethodOutput credentialView;
                };
              deliver =
                credentialEffectMethod {
                  kind = "credential";
                  action = "deliver";
                } "deliver" {
                  credential-view = runtimeMethodOutput credentialView;
                };
              release = credentialEffectMethod {kind = "release-resource";} "release" {};
            };
          };
        };
      };
      handlers.native-credential-delivery-v1 = {
        artifact = credentialRuntime;
        entryPoint = "libexec/aos-credential-delivery-handler-v1";
        arguments = credentialRequest;
        result = credentialObservation;
      };
    });

  systemd = mkPackage "ability-reference-systemd" systemdArtifact (common
    // {
      exports = {
        foreground-process = {
          artifact = systemdRuntime;
          export = terminalExport {
            name = foregroundProcess.name;
            group = "foreground-process";
            handler = "native-foreground-process-v1";
            requestSchema = foregroundProcessRequest;
            selectedLifecycle = foregroundProcessLifecycle;
            guarantees = [foregroundProcessSupervisionGuarantee];
            methods = {
              observe = foregroundProcessMethod {kind = "observe-readiness";} "observe";
              start = foregroundProcessMethod {
                kind = "service-lifecycle";
                action = "start";
              } "start";
              stop = foregroundProcessMethod {
                kind = "service-lifecycle";
                action = "stop";
              } "stop";
            };
          };
        };
        systemd-service = {
          artifact = systemdArtifact;
          export = lib.abilities.define {
            interface = systemdService.name;
            abi = systemdService.abi;
            requestSchema = schemas.record {
              fields = {
                configuration_revision = string;
                consumer_endpoint = string;
                unit = string;
                virtual_host_count = schemas.integer {
                  minimum = 0;
                  maximum = 1024;
                };
                storage_paths = storagePaths;
              };
              optional = [];
            };
            outputs.managers = output resourceMap;
            methods = {};
            inherit lifecycle;
            guarantees = [];
            aggregation = aggregation "services";
            requires = {};
            composeEntry = "compose";
            transitionEntry = "transition";
            ownsResourceKinds = [systemdService.name];
            compose = systemdProvider.compose;
            transition = transitionTransform systemdProvider.transition;
          };
        };
        systemd-service-effects = {
          artifact = systemdRuntime;
          export = terminalExport {
            name = systemdServiceEffects.name;
            group = "systemd-service-effects";
            handler = "systemd-terminal";
            guarantees = [localSystemdManagerGuarantee systemContainerManagerDelegationGuarantee];
            methods = {
              observe = method systemdServiceEffects.name {kind = "observe-readiness";} "observe";
              reload = method systemdServiceEffects.name {
                kind = "service-lifecycle";
                action = "reload";
              } "reload";
              start = method systemdServiceEffects.name {
                kind = "service-lifecycle";
                action = "start";
              } "start";
              stop = method systemdServiceEffects.name {
                kind = "service-lifecycle";
                action = "stop";
              } "stop";
            };
          };
        };
      };
      handlers.native-foreground-process-v1 = {
        artifact = systemdRuntime;
        entryPoint = "libexec/aos-foreground-process-handler-v1";
        arguments = foregroundProcessRequest;
        result = foregroundProcessObservation;
      };
      handlers.systemd-terminal = {
        artifact = systemdRuntime;
        entryPoint = "bin/.aos-package-runtime-unwrapped";
        arguments = schemas.boolean;
        result = schemas.boolean;
      };
    });
}
