##! Shared typed static render plans for host and initrd systemd projections.
{lib}: let
  selectorType = lib.types.submodule {
    config._module.strict = true;
    options = {
      package = lib.mkOption {type = lib.types.nonEmptyStr;};
      output = lib.mkOption {type = lib.types.nonEmptyStr;};
      path = lib.mkOption {type = lib.types.nonEmptyStr;};
    };
  };
  planOptions = {
    input = lib.mkOption {
      type = lib.types.str;
      description = "Canonical JSON input for the authenticated systemd renderer.";
    };
    name = lib.mkOption {
      type = lib.types.nonEmptyStr;
      description = "Stable diagnostic name for the rendered artifact.";
    };
    selectors = lib.mkOption {
      type = lib.types.listOf selectorType;
      default = [];
      description = "Authenticated package output paths used by symbolic render input.";
    };
  };
in {
  render = lib.types.submodule {
    config._module.strict = true;
    options = planOptions;
  };
  network = lib.types.submodule {
    config._module.strict = true;
    options =
      planOptions
      // {
        resolverEnabled = lib.mkOption {type = lib.types.bool;};
      };
  };
}
