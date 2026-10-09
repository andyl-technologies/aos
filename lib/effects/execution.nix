##! Handler interpretation: an executable artifact or a composition of effects.
{lib, ...}: {
  _module.strict = true;

  options = {
    phase = lib.mkOption {
      type = lib.types.enum ["installation" "startup"];
      default = "installation";
      description = "Earliest deployment phase in which the handler may execute.";
    };

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
