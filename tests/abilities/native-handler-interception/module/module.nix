##! Selects the retained qualification wrapper through ordinary authored options.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.nativeHandlerInterception.${package.name};
  operationType = lib.types.submodule {
    options = {
      ability = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z][A-Za-z0-9]*";
        description = "Declared native ability to intercept.";
      };
      name = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z][A-Za-z0-9]*";
        description = "Declared native operation to intercept.";
      };
    };
  };
  selection = operation:
    lib.setAttrByPath
    [operation.ability "operations" operation.name "handler" "program"]
    (lib.mkForce package);
in {
  options.aos.nativeHandlerInterception.${package.name}.operations = lib.mkOption {
    type = lib.types.listOf operationType;
    default = [];
    description = "Qualification-only exact native operations delegated by this retained wrapper.";
  };
  config.aos.abilities = lib.mkMerge (map selection cfg.operations);
}
