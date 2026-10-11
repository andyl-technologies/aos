##! Shared declarative diagnostics for package and system module evaluation.
{lib, ...}: {
  options = {
    assertions = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {
        options = {
          assertion = lib.mkOption {
            type = lib.types.bool;
            description = "Predicate required before deployment.";
          };
          message = lib.mkOption {
            type = lib.types.str;
            description = "Explanation of the rejected configuration.";
          };
        };
      });
      default = [];
      internal = true;
      description = "Configuration invariants checked before constructing a deployment graph.";
    };
    warnings = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      internal = true;
      description = "Non-fatal diagnostics reported while constructing a deployment graph.";
    };
  };
}
