##! Handler interpretation: an executable artifact or a composition of effects.
{lib, ...}: {
  _module.strict = true;

  options = {
    program = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "Derivation whose main program implements the terminal operation protocol.";
    };
    children = lib.mkOption {
      type = lib.types.attrsOf lib.types.deferredModule;
      default = {};
      description = "Typed child effect modules implementing a composed operation.";
    };
    exports = lib.mkOption {
      type = lib.types.attrs;
      default = {};
      description = "Child outputs returned by a composed handler.";
    };
  };
}
