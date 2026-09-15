##! Production ability-package companion for the nginx lifecycle fixture.
{
  lib,
  mkDerivation,
  credentialRuntime ? ./providers/credential,
  hostResourceRuntime ? serviceRuntime,
  managedConfigurationRuntime ? ./providers/managed-configuration,
  nginxRuntime ? ../../../pkgs/networking/_nginx-ability-provider,
  serviceRuntime ? ./providers/service,
  effectQualification ? false,
  providerStateQualification ? false,
  transitionTransform ? transition: transition,
}: let
  inherit (lib.abilities) types;
  schemas = lib.abilities.schemas;

  nginxArtifact = ../../../pkgs/networking/_nginx-ability-provider;
  nginxProvider = import nginxArtifact {
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
        ;
    };
    serviceFeatures = builtins.attrValues serviceManagementContract.features;
    inherit
      foregroundProcessSupervisionGuarantee
      loopbackIngressGuarantee
      loopbackEgressGuarantee
      ;
  };
  managedConfigurationArtifact = ./providers/managed-configuration;
  httpBackendRegistryArtifact = ./providers/http-backend-registry;
  credentialArtifact = ./providers/credential;
  serviceArtifact = ./providers/service;
  serviceProvider = import serviceArtifact;
  fixtureRuntime = name: entryPoints: source:
    if builtins.isAttrs source
    then source
    else
      mkDerivation {
        pname = "ability-reference-${name}-runtime";
        version = "1.0.0";
        src = source;
        phases = [
          {
            name = "install";
            script = ''
              mkdir -p "$out/share/source"
              cp -R "$src"/. "$out/share/source/"
              ${lib.concatMapStringsSep "\n" (entryPoint: ''
                  mkdir -p "$out/$(dirname ${lib.escapeShellArg entryPoint})"
                  printf '#!%s\nexit 64\n' "$CONFIG_SHELL" > "$out/${entryPoint}"
                  chmod +x "$out/${entryPoint}"
                '')
                entryPoints}
            '';
          }
        ];
      };
  selectorFor = runtime:
    lib.abilities.packageOutput {
      package = runtime.pname;
      output = runtime.outputName or "out";
    };
  credentialRuntimeDependency = fixtureRuntime "credential" ["libexec/aos-credential-delivery-handler-v1"] credentialRuntime;
  hostResourceRuntimeDependency =
    fixtureRuntime "host-resources" [
      "libexec/aos-host-network-policy-handler-v1"
      "libexec/aos-host-storage-handler-v1"
      "libexec/aos-network-endpoint-handler-v1"
    ]
    hostResourceRuntime;
  managedConfigurationRuntimeDependency = fixtureRuntime "managed-configuration" ["bin/.aos-package-runtime-unwrapped"] managedConfigurationRuntime;
  nginxRuntimeDependency = fixtureRuntime "nginx" ["bin/nginx"] nginxRuntime;
  serviceRuntimeDependency =
    fixtureRuntime "service" [
      "bin/.aos-package-runtime-unwrapped"
      "libexec/aos-foreground-process-handler-v1"
    ]
    serviceRuntime;
  packageRuntimeSelector = selectorFor serviceRuntimeDependency;
  nginxRuntimeSelector = selectorFor nginxRuntimeDependency;
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
  credentialDeliveryEffects =
    interface
    "aos.credential-delivery-effects"
    "sha256:bc251c0837c1d453a6c5840d9146d9e27a95ad82032d9b4c60baf40d293cf1eb";
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
  serviceManagement = serviceManagementContract.interface;
  foregroundProcess =
    interface
    "aos.foreground-process"
    "sha256:6f692b67b0670968fb335b4ebe93951cd40bdedf925f98f025b93024b30b17cb";
  nginxInterface =
    interface
    "aos.nginx"
    "sha256:5eb5252567f450038b4bc34cf004852d81427b745662fbdd3cf8175f5d2da7a6";

  foregroundProcessSupervisionGuarantee = {
    name = "aos.foreground-process-supervision";
    version = 1;
    descriptor = "sha256:b213e3c6ef28e4930a1091296e28fbfddde9f539d2daeb0287edfe955047311a";
  };

  loopbackIngressGuarantee = lib.abilities.guarantee {
    name = "aos.guarantee.loopback-tcp-ingress-enforcement";
    version = 1;
    semantics = "successful application and observation prove loopback-only TCP ingress for the requested endpoint";
  };
  loopbackEgressGuarantee = lib.abilities.guarantee {
    name = "aos.guarantee.loopback-tcp-egress-enforcement";
    version = 1;
    semantics = "successful application and observation prove loopback-only TCP egress for the requested endpoint";
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
    description = "Requires the ${selected.name} interface for the nginx reference composition.";
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

  foregroundProcessRequest = types.record {
    fields = {
      arguments = types.list {
        element = types.string {
          maxLength = 4096;
          syntax = null;
        };
        maxItems = 128;
      };
      artifact = types.artifactReference;
      entry_point = types.string {
        maxLength = 4096;
        syntax = null;
      };
    };
    optional = [];
  };

  foregroundProcessObservation = types.record {
    fields = {
      process_identity = types.optional (types.string {
        maxLength = 1024;
        syntax = null;
      });
      running = types.boolean;
      schema = types.enum ["aos.ability.foreground-process-observation/v1"];
    };
    optional = [];
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

  backendEndpoints = types.optional (types.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 1024;
    value = types.optional endpoint;
  });

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

  credentialRequest = types.record {
    fields = {
      version = types.string {
        maxLength = 71;
        syntax = null;
      };
      view = localKeyString;
    };
    optional = [];
  };

  credentialObservation = types.record {
    fields = {
      delivered = types.boolean;
      observed_version = types.optional (types.string {
        maxLength = 71;
        syntax = null;
      });
      requested_version = types.string {
        maxLength = 71;
        syntax = null;
      };
      schema = types.enum ["aos.ability.credential-delivery-observation/v1"];
      view = localKeyString;
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

  localKeyString = types.string {
    maxLength = 128;
    syntax = "local-key-v1";
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

  resourceMap = types.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 1024;
    value = types.resourceReference;
  };

  stringMap = types.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 1024;
    value = string;
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

  managedVirtualHost = types.record {
    fields = {
      backend_endpoint = endpoint;
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
    optional = ["backend_endpoint" "credential_version" "proxy_backend"];
  };

  recoverableMethods = ["acquire" "deliver" "observe" "prepare" "publish" "record" "release" "reload" "restart" "start" "stop" "validate"];

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
      indeterminate =
        if builtins.elem name recoverableMethods
        then "reconcile"
        else "intervention-required";
    };
  };

  methodWithOutputs = targetResource: name: outputs:
    (method targetResource name) // {inherit outputs;};

  foregroundProcessMethod = name:
    (method foregroundProcess.name name)
    // {
      outcome = {
        completionEvidence = foregroundProcessObservation;
        observationEvidence = foregroundProcessObservation;
        supportsRejectedBeforeEffect = true;
        indeterminate = "reconcile";
      };
    };

  validationMethod = name:
    (method nginxValidation.name name)
    // {parameters = nginxValidationRequest;};

  credentialEffectMethod = name: outputs:
    (methodWithOutputs credentialDeliveryEffects.name name outputs)
    // {
      parameters = credentialRequest;
      outcome = {
        completionEvidence = credentialObservation;
        observationEvidence = credentialObservation;
        supportsRejectedBeforeEffect = true;
        indeterminate = "reconcile";
      };
    };

  endpointEffectMethod = name: outputs: {
    targetResource = endpointEffects.name;
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

  networkPolicyEffectMethod = name: parameters: outputs: guarantees: {
    targetResource = networkPolicyEffects.name;
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

  managedConfigurationProvider = import ./providers/managed-configuration/default.nix;
  credentialProvider = import ./providers/credential/default.nix;
  httpBackendRegistryProvider = import ./providers/http-backend-registry/default.nix;
  baseNginxAbilityModule = import ../../../pkgs/networking/_nginx-ability-contract.nix {
    inherit effectQualification providerStateQualification lib;
    providerArtifact = nginxArtifact;
    runtimeArtifact = nginxRuntimeSelector;
    hostResourceRuntime = selectorFor hostResourceRuntimeDependency;
  };
  baseNginxAbilities = baseNginxAbilityModule.config.aos.abilities;
  baseNginxImplementations = baseNginxAbilities.implementations;
  nginxAbilityModule = {
    config.aos.abilities = {
      inherit (baseNginxAbilities) interfaces;
      implementations =
        baseNginxImplementations
        // {
          nginx =
            baseNginxImplementations.nginx
            // {
              transition = transitionTransform baseNginxImplementations.nginx.transition;
            };
        };
    };
  };
in let
  mkPackage = pname: src: runtimeDeps: abilities:
    mkDerivation {
      inherit pname src runtimeDeps abilities;
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
in {
  consumer = mkPackage "ability-reference-nginx-consumer" nginxArtifact [] {
    config.aos.abilities.requirementTemplates.nginx = required nginxInterface;
  };

  backend-consumer = mkPackage "ability-reference-nginx-backend-consumer" nginxArtifact [] {
    config.aos.abilities.requirementTemplates = {
      nginx = required nginxInterface;
      backend = required httpBackend;
    };
  };

  backend-registry = mkPackage "ability-reference-http-backend-registry" httpBackendRegistryArtifact [] {
    config.aos.abilities = lib.abilities.projectDefinitions {
      http-backend = {
        definition = lib.abilities.define {
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
  };

  nginx = mkPackage "ability-reference-nginx" nginxArtifact [nginxRuntimeDependency hostResourceRuntimeDependency] nginxAbilityModule;

  managed-configuration = mkPackage "ability-reference-managed-configuration" managedConfigurationArtifact [managedConfigurationRuntimeDependency] {
    config.aos.abilities = lib.abilities.projectDefinitions {
      managed-configuration = {
        definition = lib.abilities.define {
          interface = managedConfiguration.name;
          abi = managedConfiguration.abi;
          requestSchema = types.record {
            fields = {
              virtualHosts = types.list {
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
          transition = transitionTransform (
            if providerStateQualification
            then managedConfigurationProvider.effectQualificationTransition
            else if effectQualification
            then managedConfigurationProvider.effectQualificationTransition
            else managedConfigurationProvider.transition
          );
        };
      };
      managed-configuration-effects = {
        artifact = selectorFor managedConfigurationRuntimeDependency;
        definition = terminalExport {
          name = managedConfigurationEffects.name;
          group = "managed-configuration-effects";
          handler = "managed-configuration-terminal";
          methods = {
            prepare = method managedConfigurationEffects.name "prepare";
            publish = method managedConfigurationEffects.name "publish";
            release = method managedConfigurationEffects.name "release";
          };
        };
        handler = {
          artifact = selectorFor managedConfigurationRuntimeDependency;
          entryPoint = "bin/.aos-package-runtime-unwrapped";
          arguments = types.boolean;
          result = types.boolean;
        };
      };
    };
  };

  credential = mkPackage "ability-reference-credential" credentialArtifact [credentialRuntimeDependency] {
    config.aos.abilities = lib.abilities.projectDefinitions {
      credential-delivery = {
        definition = lib.abilities.define {
          interface = credentialDelivery.name;
          abi = credentialDelivery.abi;
          requestSchema = types.record {
            fields = {
              hosts = types.list {
                element = string;
                maxItems = 1024;
              };
              version = types.string {
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
          transition = transitionTransform (
            if providerStateQualification
            then credentialProvider.providerStateQualificationTransition
            else if effectQualification
            then credentialProvider.effectQualificationTransition
            else credentialProvider.transition
          );
        };
      };
      credential-delivery-effects = {
        artifact = selectorFor credentialRuntimeDependency;
        definition = terminalExport {
          name = credentialDeliveryEffects.name;
          group = "credential-delivery-effects";
          handler = "native-credential-delivery";
          requestSchema = credentialRequest;
          selectedLifecycle = credentialEffectsLifecycle;
          methods = {
            acquire = credentialEffectMethod "acquire" {
              credential-view = runtimeMethodOutput credentialView;
            };
            deliver = credentialEffectMethod "deliver" {
              credential-view = runtimeMethodOutput credentialView;
            };
            release = credentialEffectMethod "release" {};
          };
        };
        handler = {
          artifact = selectorFor credentialRuntimeDependency;
          entryPoint = "libexec/aos-credential-delivery-handler";
          arguments = credentialRequest;
          result = credentialObservation;
        };
      };
    };
  };

  service = mkPackage "ability-reference-service" serviceArtifact [serviceRuntimeDependency] {
    config.aos.abilities = lib.abilities.projectDefinitions {
      foreground-process = {
        artifact = packageRuntimeSelector;
        definition = terminalExport {
          name = foregroundProcess.name;
          group = "foreground-process";
          handler = "native-foreground-process";
          requestSchema = foregroundProcessRequest;
          selectedLifecycle = foregroundProcessLifecycle;
          guarantees = [foregroundProcessSupervisionGuarantee];
          methods = {
            observe = foregroundProcessMethod "observe";
            start = foregroundProcessMethod "start";
            stop = foregroundProcessMethod "stop";
          };
        };
        handler = {
          artifact = packageRuntimeSelector;
          entryPoint = "libexec/aos-foreground-process-handler";
          arguments = foregroundProcessRequest;
          result = foregroundProcessObservation;
        };
      };
      service-definition = {
        definition = lib.abilities.define {
          interface = serviceDefinition.name;
          abi = serviceDefinition.abi;
          requestSchema = types.record {
            fields = {
              configuration_revision = string;
              consumer_endpoint = string;
              service = string;
              virtual_host_count = types.integer {
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
          ownsResourceKinds = [serviceDefinition.name];
          compose = serviceProvider.compose;
          transition = transitionTransform serviceProvider.transition;
        };
      };
      service-management = {
        artifact = packageRuntimeSelector;
        definition = terminalExport {
          name = serviceManagement.name;
          group = "service-management";
          handler = "service-management-terminal";
          guarantees = builtins.attrValues serviceManagementContract.features;
          selectedLifecycle = serviceManagementContract.lifecycle;
          methods = {
            observe = method serviceManagement.name "observe";
            reload = method serviceManagement.name "reload";
            restart = method serviceManagement.name "restart";
            start = method serviceManagement.name "start";
            stop = method serviceManagement.name "stop";
          };
        };
        handler = {
          artifact = packageRuntimeSelector;
          entryPoint = "bin/.aos-package-runtime-unwrapped";
          arguments = types.boolean;
          result = types.boolean;
        };
      };
    };
  };
}
