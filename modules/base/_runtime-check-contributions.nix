##! Package-authored runtime qualification contributions.
{lib, ...}: let
  types = lib.abilities.types;
  contributionMap = import ../_package-contribution-map.nix {inherit lib;};
  runtimeCheck = types.record {
    fields = {
      name = types.localKey;
      description = types.string {
        maxLength = 4096;
        syntax = null;
      };
      script = types.string {
        maxLength = types.limits.maxStringLength;
        syntax = null;
      };
    };
  };
  runtimeCheckGroup = types.record {
    fields = {
      description = types.string {
        maxLength = 4096;
        syntax = null;
      };
      checks = types.list {
        element = runtimeCheck;
        maxItems = 256;
      };
    };
  };
in {
  options.aos.contributions.runtimeChecks = lib.mkOption {
    type = contributionMap runtimeCheckGroup;
    default = {};
    contributable = true;
    description = "Package-owned runtime qualification groups consumed by the system test plan.";
  };
}
