##! Production ability-package companion for the nginx lifecycle fixture.
{
  lib,
  mkDerivation,
  credentialRuntime ? ./providers/credential,
  managedConfigurationRuntime ? ./providers/managed-configuration,
  nginxRuntime ? ./providers/nginx,
  systemdRuntime ? ./providers/systemd,
}: let
  inherit (lib.abilities) schemas;

  nginxArtifact = ./providers/nginx;
  managedConfigurationArtifact = ./providers/managed-configuration;
  credentialArtifact = ./providers/credential;
  systemdArtifact = ./providers/systemd;

  interface = name: descriptor: {
    inherit name descriptor;
    abi = 1;
  };

  managedConfiguration =
    interface
    "aos.managed-configuration"
    "sha256:771c63c0fe1730c0592b49c14600a115b2c842d5b363d66158b918ccd051ee3d";
  credentialDelivery =
    interface
    "aos.credential-delivery"
    "sha256:d282faba1d3a1afd3ed7b2cde885331d8c2cf94f9b7968eb88987cffae852a3b";
  credentialDeliveryEffects =
    interface
    "aos.credential-delivery-effects"
    "sha256:bc251c0837c1d453a6c5840d9146d9e27a95ad82032d9b4c60baf40d293cf1eb";
  systemdService =
    interface
    "aos.systemd-service"
    "sha256:b712c9e3697e87d62bb62549d8692b4d8f825bae9733ae523f76a40bd3882666";
  nginxValidation =
    interface
    "aos.nginx-validation"
    "sha256:c781b7f06eabaa9386ab0438f150b028e98b6d07ad78a907a567d27ee14602a6";
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
    "sha256:5d368e34482c6e2bea67626aa86cbc8b0ab882644009835d77de312c77333c88";

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

  nginxValidationRequest = schemas.record {
    fields = {
      candidate = schemas.boolean;
      credential_views = schemas.list {
        element = credentialView;
        maxItems = 1024;
      };
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
    };
    optional = [];
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
      tls = schemas.boolean;
    };
    optional = [];
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

  nginxProvider = import ./providers/nginx/default.nix;
  managedConfigurationProvider = import ./providers/managed-configuration/default.nix;
  credentialProvider = import ./providers/credential/default.nix;
  systemdProvider = import ./providers/systemd/default.nix;
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
  };

  nginx = mkPackage "ability-reference-nginx" nginxArtifact (common
    // {
      exports = {
        nginx = {
          artifact = nginxArtifact;
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
            requires = {
              configuration = required managedConfiguration;
              credential = requirement credentialDelivery [] "advisory" {
                outputs.credential-views = {};
              };
              service = required systemdService;
              service-terminal =
                requirement systemdServiceEffects ["observe" "reload" "start" "stop"] "required" null
                // {guarantees = [localSystemdManagerGuarantee];};
              service-terminal-foreground =
                requirement foregroundProcess ["observe" "start" "stop"] "required" null
                // {guarantees = [foregroundProcessSupervisionGuarantee];};
              service-terminal-system-container =
                requirement systemdServiceEffects ["observe" "reload" "start" "stop"] "required" null
                // {guarantees = [localSystemdManagerGuarantee systemContainerManagerDelegationGuarantee];};
              validation-terminal = methodRequirement nginxValidation ["record" "release" "validate"];
            };
            composeEntry = "compose";
            transitionEntry = "transition";
            ownsResourceKinds = ["aos.nginx"];
            compose = nginxProvider.compose;
            transition = nginxProvider.transition;
          };
        };
        nginx-validation = {
          artifact = nginxRuntime;
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
        };
      };
      handlers.nginx-terminal = {
        artifact = nginxRuntime;
        entryPoint = "bin/nginx";
        arguments = nginxValidationRequest;
        result = schemas.boolean;
      };
    });

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
                  element = virtualHost;
                  maxItems = 1024;
                };
                consumer_content_revision = string;
                consumer_controller_revision = string;
                consumer_instance = string;
                consumer_probe = consumerProbe;
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
            transition = managedConfigurationProvider.transition;
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
              fields.hosts = schemas.list {
                element = string;
                maxItems = 1024;
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
            transition = credentialProvider.transition;
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
            transition = systemdProvider.transition;
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
      handlers.systemd-terminal = {
        artifact = systemdRuntime;
        entryPoint = "bin/.aos-package-runtime-unwrapped";
        arguments = schemas.boolean;
        result = schemas.boolean;
      };
    });
}
