##! Provider-neutral artifact backend requirement and authenticated projection.
{lib, ...}: let
  storeRoot =
    lib.types.addCheck lib.types.pathInStore (value:
      builtins.match "/nix/store/[0-9a-z]+-[^/]+" (builtins.toString value) != null);
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
          type = lib.abilities.types.packageOutputSelector;
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
    (backend: backend.artifact == lib.abilities.packageOutput {});
in {
  options.aos.artifacts.backend = lib.mkOption {
    type = lib.types.nullOr (lib.types.uniq backendType);
    default = null;
    readOnly = true;
    internal = true;
    extensible = true;
    description = "Exact package-owned artifact backend selected by an ability binding.";
  };
}
