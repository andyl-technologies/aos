##! Binds exact native service and endpoint publication outputs.
{
  config,
  lib,
  package,
  ...
}: let
  publishedType = config.aos.abilities.referenceHttpBackend.operations.publish.result.options.endpoints.type;
  binding = lib.types.submodule {
    options = {
      enable = lib.mkEnableOption "reference backend consumer binding";
      service = lib.mkOption {type = lib.types.deferred lib.types.str;};
      endpoints = lib.mkOption {type = lib.types.deferred publishedType;};
    };
  };
  selected = lib.filterAttrs (_: value: value.enable) config.aos.referenceBackendConsumers;
  program = package // {meta.mainProgram = "aos-reference-binding";};
in {
  options.aos.referenceBackendConsumers = lib.mkOption {
    type = lib.types.attrsOf binding;
    default = {};
    description = "Named consumers bound to exact service and endpoint publication results.";
  };
  config.aos.abilities.referenceHttpBackend.operations.bind = {
    input.options = {
      service = lib.mkOption {type = lib.types.deferred lib.types.str;};
      endpoints = lib.mkOption {type = lib.types.deferred publishedType;};
    };
    result.options = {
      resource = lib.mkOption {type = lib.types.str;};
      service = lib.mkOption {type = lib.types.str;};
      endpoints = lib.mkOption {type = publishedType;};
    };
    handler = {inherit program;};
    effects = lib.mapAttrs (_: value: {input = {inherit (value) service endpoints;};}) selected;
  };
}
