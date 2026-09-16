##! Opaque package-selected artifact construction boundary.
{lib, ...}: let
  backendType = {
    name = "package artifact backend";
    description = "package-owned artifact construction backend";
    check = value:
      builtins.isAttrs value
      && (value._type or null) == "aos-package-artifact-backend"
      && builtins.isFunction (value.buildStaticContract or null);
    merge = location: definitions:
      if builtins.length definitions == 1
      then (builtins.head definitions).value
      else throw "The option '${builtins.concatStringsSep "." location}' requires exactly one selected artifact backend.";
  };
in {
  options.aos.artifacts.backend = lib.mkOption {
    type = lib.types.nullOr backendType;
    default = null;
    readOnly = true;
    internal = true;
    contributable = true;
    description = "Exact package-owned artifact backend selected by an ability binding.";
  };
}
