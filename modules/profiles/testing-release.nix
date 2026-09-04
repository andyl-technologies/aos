##! modules/profiles/testing-release.nix — Experimental public release profile
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.profiles.testingRelease;
in {
  options.aos.profiles.testingRelease.enable = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = "Build a public experimental image tied only to andyl/testing edge.";
  };

  config = lib.mkIf cfg.enable {
    aos.release = {
      enabled = true;
      tier = "testing";
      registry = "andyl/testing";
      rootEpoch = 1;
      clientName = "andyl-testing";
      url = "https://aos.andyl.org/andyl/testing/";
      channel = "edge";
      warning = ''
        ANDYL OS TESTING

        This is an experimental AOS testing image. It is not supported for
        production workloads or important data. This system follows the
        andyl/testing edge channel. Updates may contain breaking changes,
        require reinstallation, or replace the testing trust root. Keep
        important data and recovery material backed up elsewhere.

      '';
    };

    aos.image = {
      enable = true;
      allowTestArtifacts = false;
    };
  };
}
