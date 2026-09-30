##! Separates host and early-boot module evaluation scopes.
{lib, ...}: let
  inherit (lib) mkOption types;
in {
  options.aos.activation.stages = mkOption {
    type = types.attrsOf (types.submodule {
      options.modules = mkOption {
        type = types.listOf types.deferredModule;
        default = [];
        description = "Modules included when evaluating this deployment stage.";
      };
    });
    default = {
      host = {};
      initrd = {};
    };
    description = "Independent deployment stages composed from module values.";
  };
}
