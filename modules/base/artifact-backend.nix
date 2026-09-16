##! Provider-neutral artifact backend requirement and authenticated projection.
{
  config,
  lib,
  ...
}: let
  artifactBackend = lib.abilities.interfaces.artifactBackend.interfaces.backend;
  consumer = "system:artifact-backend";
  hostStage =
    config.aos.abilities.environment != null
    && config.aos.abilities.environment.stage == "host";
  storeRoot = lib.types.addCheck lib.types.pathInStore (value:
    builtins.match "/nix/store/[0-9a-z]+-[^/]+" (builtins.toString value) != null);
  backendType = lib.types.addCheck (lib.types.submodule {
      config._module.strict = true;
      options = {
        _type = lib.mkOption {
          type = lib.types.enum ["aos-package-artifact-backend"];
        };
        name = lib.mkOption {
          type = lib.types.nonEmptyStr;
        };
        artifact = lib.mkOption {
          type = lib.abilities.types.artifactReference;
        };
        package = lib.mkOption {
          type = storeRoot;
        };
        buildStaticContract = lib.mkOption {
          type = lib.types.functionTo lib.types.anything;
        };
        defaultDefinition = lib.mkOption {
          type = lib.types.functionTo lib.types.anything;
        };
        buildContainer = lib.mkOption {
          type = lib.types.functionTo lib.types.anything;
        };
      };
    })
    (backend: backend.artifact.store_path == builtins.toString backend.package);
in {
  options.aos.artifacts.backend = lib.mkOption {
    type = lib.types.nullOr (lib.types.uniq backendType);
    default = null;
    readOnly = true;
    internal = true;
    contributable = true;
    description = "Exact package-owned artifact backend selected by an ability binding.";
  };

  config = {
    aos.abilities = {
      instances = lib.mkIf hostStage {${consumer} = {};};
      requirementTemplates.${consumer} = {
        description = "Requires one authenticated package-owned artifact construction backend.";
        interface = artifactBackend.identity.name;
        inherit (artifactBackend.identity) abi descriptor;
      };
      requests = lib.mkIf hostStage {
        ${consumer} = {
          requirement = consumer;
          inherit consumer;
          parameters = true;
        };
      };
    };
  };
}
