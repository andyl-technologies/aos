##! Owns source-authored marker effects and their actual deferred dependency.
{
  config,
  lib,
  package,
  ...
}: let
  operation = config.aos.abilities.nativeDependencyBarrier.operations.ensure;
in {
  options.aos.nativeDependencyBarrier.requests = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule operation.input);
    default = {};
    description = "Qualification-only independent markers with exact native dependencies.";
  };
  config.aos.abilities.nativeDependencyBarrier.operations.ensure = {
    input.options = {
      name = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9._-]*";
        description = "Bounded fixture marker name.";
      };
      parent = lib.mkOption {
        type = lib.types.nullOr (lib.types.deferred lib.types.str);
        default = null;
        description = "Actual prerequisite result whose graph edge orders the marker.";
      };
    };
    result.options.resource = lib.mkOption {
      type = lib.types.str;
      description = "Actual independently observable fixture marker path.";
    };
    handler.program = package;
    effects = lib.mapAttrs (_: input: {inherit input;}) config.aos.nativeDependencyBarrier.requests;
  };
}
