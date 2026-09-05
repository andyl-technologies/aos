##! Owns the qualification catalog, export boundary and cross-feature invariants.
{
  config,
  lib,
  ...
}: let
  cfg = config.qualification;
  types = import ./_types.nix {inherit lib;};
  named = field: values: lib.mapAttrsToList (name: value: value // {${field} = name;}) values;
  failures = builtins.filter (check: !check.assertion) cfg.assertions;
  # Submodule evaluation retains private module metadata. The signed process
  # contract contains only option values, independent of evaluator internals.
  data = value:
    if builtins.isAttrs value
    then builtins.mapAttrs (_: data) (builtins.removeAttrs value ["_module"])
    else if builtins.isList value
    then map data value
    else value;
in {
  options.qualification = {
    requirements = lib.mkOption {
      type = lib.types.attrsOf types.requirement;
      default = {};
      description = "Claim requirements composed by feature modules.";
    };
    targets = lib.mkOption {
      type = lib.types.attrsOf types.target;
      default = {};
      description = "Reference execution configurations.";
    };
    assertions = lib.mkOption {
      type = lib.types.listOf (types.closed {
        assertion = types.option lib.types.bool "Condition required for a valid policy.";
        message = types.text "Diagnostic for a violated policy invariant.";
      });
      default = [];
      description = "Qualification policy invariants evaluated before export.";
    };
    export = lib.mkOption {
      type = lib.types.attrs;
      readOnly = true;
      description = "Canonical offline qualification contract derived from the module fixed point.";
    };
  };
  config = {
    _module.strict = true;
    qualification.export =
      if failures != []
      then throw ("Invalid qualification policy: " + lib.concatStringsSep "; " (map (check: check.message) failures))
      else
        data {
          schema_version = "aos.release.qualification-contract/v2";
          inherit (cfg) id promises exclusions thresholds;
          targets = named "id" (builtins.mapAttrs (_: target:
            target
            // {
              environment = types.environments.export target.environment;
            })
          cfg.targets);
          requirements = named "id" cfg.requirements;
          package_rules = named "name" cfg.packageRules;
          claims = named "id" cfg.claims;
        };
  };
}
