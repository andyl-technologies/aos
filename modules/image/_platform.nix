##! Exact package-selected immutable image builder projection.
{lib, ...}: let
  consumer = "image:builder";
  builderInterface = lib.abilities.interfaces.imageBuilder.interfaces.builder;
  platformRecordValid = value:
    builtins.isAttrs value
    && builtins.attrNames value
    == [
      "_type"
      "name"
      "normalArtifactPath"
      "package"
      "plan"
    ]
    && (value._type or null) == "aos-image-builder"
    && builtins.isString value.name
    && value.name != ""
    && builtins.isString value.normalArtifactPath
    && value.normalArtifactPath != ""
    && builtins.isString value.package
    && builtins.match "/nix/store/[0-9a-z]+-[^/]+" value.package != null
    && builtins.isFunction value.plan;
  platformType = {
    name = "selected immutable image builder";
    description = "package-owned immutable image planning backend";
    check = platformRecordValid;
    merge = location: definitions:
      if builtins.length definitions != 1
      then throw "The option '${builtins.concatStringsSep "." location}' requires exactly one selected image builder."
      else let
        value = (builtins.head definitions).value;
      in
        if !platformRecordValid value
        then throw "The option '${builtins.concatStringsSep "." location}' is not a complete image builder."
        else value;
  };
in {
  options.aos.image.platform = lib.mkOption {
    type = lib.types.nullOr platformType;
    default = null;
    readOnly = true;
    internal = true;
    contributable = true;
    description = "Exact package-owned image builder selected by an ability binding.";
  };

  config.aos.abilities = {
    instances.${consumer} = {};
    requirementTemplates.${consumer} = {
      description = "Requires one package-owned immutable image builder.";
      interface = builderInterface.identity.name;
      inherit (builderInterface.identity) abi descriptor;
    };
    requests.${consumer} = {
      requirement = consumer;
      inherit consumer;
      parameters = true;
    };
  };
}
