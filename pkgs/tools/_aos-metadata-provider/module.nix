##! Owns typed platform metadata operations and their retained native handlers.
{
  config,
  lib,
  package,
  ...
}: let
  types = import ./types.nix {inherit lib;};
  nativeTools = {
    blkid = lib.mkOption {
      type = lib.types.str;
      description = "Immutable blkid executable used for media probing.";
    };
    mount = lib.mkOption {
      type = lib.types.str;
      description = "Immutable mount executable used for read-only metadata media.";
    };
    umount = lib.mkOption {
      type = lib.types.str;
      description = "Immutable umount executable used to release metadata media.";
    };
  };
  acquisitionProgram = package // {meta = (package.meta or {}) // {mainProgram = "aos-metadata-acquisition-provider";};};
  policyProgram = package // {meta = (package.meta or {}) // {mainProgram = "aos-metadata-policy-provider";};};
  evaluation = config.aos.config.evalAtBoot or {};
  configured = (evaluation.trust or null) != null;
  configKeys = config.aos.apm.configKeys or {};
  keyFileContent = keys: "${lib.concatStringsSep "\n" keys}\n";
  configuredAuthorization = {
    schema = "aos.metadata.provisioning-authorization-configuration/v1";
    trust_mode = evaluation.trust;
    trusted_config_keys =
      lib.mapAttrsToList (operator: keys: {
        kind = "immutable-file";
        path = builtins.toString (builtins.toFile "aos-metadata-trust-${builtins.hashString "sha256" operator}.pub" (keyFileContent keys));
        content_sha256 = "sha256:${builtins.hashString "sha256" (keyFileContent keys)}";
      })
      configKeys;
  };
in {
  imports = [./policy.nix ./facts/module.nix];
  options.aos.metadata.storageProvisioning.authorizationConfiguration = lib.mkOption {
    type = lib.types.nullOr types.authorizationConfiguration;
    default = null;
    internal = true;
    readOnly = true;
    description = "Metadata trust policy derived from final settings; runtime authority supplies the native library identity.";
  };

  config = lib.mkMerge [
    {
      aos.abilities.metadata.operations = {
        detect = {
          input.options = nativeTools;
          result.options = {
            platform = lib.mkOption {
              type = types.platform;
              description = "Detected metadata platform and acquisition requirements.";
            };
            need_network = lib.mkOption {
              type = lib.types.bool;
              description = "Whether acquisition requires early network connectivity.";
            };
          };
          handler.program = acquisitionProgram;
        };
        acquire = {
          input.options =
            nativeTools
            // {
              platform = lib.mkOption {
                type = lib.types.deferred types.platform;
                description = "Exact platform result from metadata detection.";
              };
            };
          result.options = {
            acquired_metadata = lib.mkOption {
              type = types.acquired;
              description = "Untrusted exact metadata and observed instance facts.";
            };
            network_bootstrap = lib.mkOption {
              type = lib.types.nullOr types.networkBootstrap;
              description = "Exact static network seed when supplied by metadata.";
            };
          };
          handler.program = acquisitionProgram;
        };
        authorize = {
          input.options = {
            evaluation_context = lib.mkOption {
              type = lib.types.deferred lib.types.str;
              description = "Admitted immutable native evaluation descriptor supplying source library authority.";
            };
            configuration = lib.mkOption {
              type = types.authorizationConfiguration;
              description = "Exact trust policy and immutable configuration anchors.";
            };
            acquired_metadata = lib.mkOption {
              type = lib.types.deferred types.acquired;
              description = "Untrusted metadata result to authenticate as one input.";
            };
          };
          result.options.canonical_input = lib.mkOption {
            type = lib.types.str;
            description = "Canonical authorized input bytes for immutable content commitment.";
          };
          result.options.authorized_input = lib.mkOption {
            type = types.authorized;
            description = "Authenticated operator module and explicitly observational facts.";
          };
          handler.program = policyProgram;
        };
      };
    }
    (lib.mkIf configured {
      aos.metadata.storageProvisioning.authorizationConfiguration = configuredAuthorization;
    })
  ];
}
