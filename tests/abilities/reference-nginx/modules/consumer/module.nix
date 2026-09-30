##! Checks native service output bindings without introducing service aliases.
{
  config,
  lib,
  package,
  ...
}: let
  binding = lib.types.submodule {
    options = {
      enable = lib.mkEnableOption "reference nginx consumer binding";
      service = lib.mkOption {type = lib.types.deferred lib.types.str;};
    };
  };
  selected = lib.filterAttrs (_: value: value.enable) config.aos.referenceNginxConsumers;
  program = package // {meta.mainProgram = "aos-reference-binding";};
in {
  options.aos.referenceNginxConsumers = lib.mkOption {
    type = lib.types.attrsOf binding;
    default = {};
    description = "Named consumers bound to exact native service results.";
  };
  config.aos.abilities.referenceNginx.operations.bind = {
    input.options.service = lib.mkOption {type = lib.types.deferred lib.types.str;};
    result.options = {
      resource = lib.mkOption {type = lib.types.str;};
      service = lib.mkOption {type = lib.types.str;};
    };
    handler = {inherit program;};
    effects = lib.mapAttrs (_: value: {input.service = value.service;}) selected;
  };
}
