##! Production ability-package companion for the nginx lifecycle fixture.
{
  lib,
  mkDerivation,
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
    "sha256:6c813d376a0141954cdf320c4fa422330b42c4d88bec0d67dcfff4b78cdd234a";
  credentialDelivery =
    interface
    "aos.credential-delivery"
    "sha256:d282faba1d3a1afd3ed7b2cde885331d8c2cf94f9b7968eb88987cffae852a3b";
  systemdService =
    interface
    "aos.systemd-service"
    "sha256:1be97040a30ac274816ff7d1ee53f384989165f2ed09c80956a1d90458b72f5f";
  nginxValidation =
    interface
    "aos.nginx-validation"
    "sha256:cfe3335b1ff3082ffd17e38f098e804461daaa32db19a2aba9faa2e2acaddd1d";
  managedConfigurationEffects =
    interface
    "aos.managed-configuration-effects"
    "sha256:2b5e3051194f29f19bdf178c7e51f3bc4dbee7b67eafb04cba7953580dd990bf";
  systemdServiceEffects =
    interface
    "aos.systemd-service-effects"
    "sha256:08e463bed96f053e557f557c95342666e81358396a44f89bf4c07a2aa780d6c5";
  nginxInterface =
    interface
    "aos.nginx"
    "sha256:0eb9b90f9f0fd0f744b13281c98bd37c0782ae74e2b85cc89c3cfef1b4cc1312";

  lifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = true;
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

  localKeyString = schemas.string {
    maxLength = 128;
    syntax = "local-key-v1";
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
      indeterminate = "intervention-required";
    };
  };

  terminalExport = {
    name,
    group,
    handler,
    methods,
  }:
    lib.abilities.define {
      interface = name;
      abi = 1;
      requestSchema = schemas.boolean;
      outputs = {};
      inherit methods lifecycle;
      guarantees = [];
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
              service-terminal = methodRequirement systemdServiceEffects ["observe" "reload" "start" "stop"];
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
          artifact = nginxArtifact;
          export = terminalExport {
            name = nginxValidation.name;
            group = "nginx-validation";
            handler = "nginx-terminal";
            methods = {
              record = method nginxValidation.name {kind = "record-generation-association";} "record";
              release = method nginxValidation.name {kind = "release-resource";} "release";
              validate = method nginxValidation.name {kind = "validate-candidate";} "validate";
            };
          };
        };
      };
      handlers.nginx-terminal = {
        artifact = nginxArtifact;
        entryPoint = "libexec/reference-terminal";
        arguments = schemas.boolean;
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
              fields.virtualHosts = schemas.list {
                element = virtualHost;
                maxItems = 1024;
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
          artifact = managedConfigurationArtifact;
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
        artifact = managedConfigurationArtifact;
        entryPoint = "libexec/reference-terminal";
        arguments = schemas.boolean;
        result = schemas.boolean;
      };
    });

  credential = mkPackage "ability-reference-credential" credentialArtifact (common
    // {
      exports.credential-delivery = {
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
          requires = {};
          composeEntry = "compose";
          transitionEntry = "transition";
          ownsResourceKinds = [credentialDelivery.name];
          compose = credentialProvider.compose;
          transition = credentialProvider.transition;
        };
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
          artifact = systemdArtifact;
          export = terminalExport {
            name = systemdServiceEffects.name;
            group = "systemd-service-effects";
            handler = "systemd-terminal";
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
        artifact = systemdArtifact;
        entryPoint = "libexec/reference-terminal";
        arguments = schemas.boolean;
        result = schemas.boolean;
      };
    });
}
