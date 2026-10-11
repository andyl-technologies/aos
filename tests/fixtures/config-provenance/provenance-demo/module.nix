##! Declares and derives a package-owned native effect from ordinary operator settings.
{lib, config, package, ...}: {
  options.aos.provenance.message = lib.mkOption {
    type = lib.types.str;
    default = "package-owned";
    extensible = true;
    description = "Operator-configurable message owned by the fixture package.";
  };
  config.aos.provenance.message = lib.mkDefault "package-owned";
  config.aos.abilities.provenance.operations.write = {
    input.options = {
      path = lib.mkOption {type = lib.types.str;};
      text = lib.mkOption {type = lib.types.deferred lib.types.str;};
    };
    result.options.path = lib.mkOption {type = lib.types.str;};
    handler.program = package;
    effects.demo.input = {
      path = "/etc/provenance-demo.conf";
      text = config.aos.provenance.message;
    };
  };
}
