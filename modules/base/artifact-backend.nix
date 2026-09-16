##! Opaque package-selected artifact construction boundary.
{lib, ...}: let
  backendRecordValid = value:
    builtins.isAttrs value
    && builtins.attrNames value
    == [
      "_type"
      "buildContainer"
      "buildStaticContract"
      "defaultDefinition"
      "name"
      "package"
    ]
    && (value._type or null) == "aos-package-artifact-backend"
    && builtins.isString value.name
    && value.name != ""
    && builtins.isString value.package
    && builtins.match "/nix/store/[0-9a-z]+-[^/]+" value.package != null
    && builtins.isFunction value.buildStaticContract
    && builtins.isFunction value.defaultDefinition
    && builtins.isFunction value.buildContainer;
  backendType = {
    name = "package artifact backend";
    description = "package-owned artifact construction backend";
    check = backendRecordValid;
    merge = location: definitions:
      if builtins.length definitions != 1
      then throw "The option '${builtins.concatStringsSep "." location}' requires exactly one selected artifact backend."
      else let
        value = (builtins.head definitions).value;
      in
        if !backendRecordValid value
        then throw "The option '${builtins.concatStringsSep "." location}' is not a complete package artifact backend."
        else value;
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
