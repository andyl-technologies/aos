##! Declares the ordinary artifact composer owned by the native OCI package.
{lib, ...}: let
  backendType =
    lib.types.addCheck (lib.types.submodule {
      config._module.strict = true;
      options = {
        _type = lib.mkOption {
          type = lib.types.enum ["aos-package-artifact-backend"];
        };
        name = lib.mkOption {
          type = lib.types.nonEmptyStr;
        };
        artifact = lib.mkOption {
          type = lib.types.package;
        };
        package = lib.mkOption {
          type = lib.types.package;
        };
        buildDeploymentArtifact = lib.mkOption {
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
    (backend: builtins.toString backend.artifact == builtins.toString backend.package);
in {
  options.aos.artifacts.backend = lib.mkOption {
    type = lib.types.nullOr (lib.types.uniq backendType);
    default = null;
    readOnly = true;
    internal = true;
    extensible = true;
    description = "Exact package-owned artifact composer selected by its module.";
  };
}
