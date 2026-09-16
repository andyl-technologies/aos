##! Package-authored privileged wrapper contributions.
{lib, ...}: let
  types = lib.abilities.types;
  contributionMap = import ../_package-contribution-map.nix {inherit lib;};
  wrapper = types.record {
    fields = {
      source = types.artifactPathReference;
      owner = types.deferredResult types.principalName;
      group = types.deferredResult types.groupName;
      mode = types.fileMode;
      maximumSizeBytes = types.integer {
        minimum = 1;
        maximum = types.limits.maxSafeInteger;
      };
    };
  };
in {
  options.aos.contributions.wrappers = lib.mkOption {
    type = contributionMap wrapper;
    default = {};
    contributable = true;
    description = "Package-owned privileged executable declarations consumed by the wrapper materializer.";
  };
}
