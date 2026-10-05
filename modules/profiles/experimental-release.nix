##! modules/profiles/experimental-release.nix — Experimental public release profile
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.profiles.experimentalRelease;
in {
  options.aos.profiles.experimentalRelease.enable = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = "Build a public experimental image tied only to andyl/experimental.";
  };

  config = lib.mkIf cfg.enable {
    aos.system.version = "2026.10.0-dev.20261002.1";

    aos.release = {
      enabled = true;
      tier = "testing";
      registry = "andyl/experimental";
      rootEpoch = 1;
      clientName = "andyl-experimental";
      # Shared-root ownership requires operator authorization in addition to
      # authenticated membership in the registry provenance signer roster.
      rootOwnerSigners = ["andyl-experimental-provenance-v1"];
      channel = lib.mkDefault "edge";
      warning = ''
        ANDYL OS EXPERIMENTAL

        This is an experimental AOS image. It is not supported for
        production workloads or important data. This system follows the
        ${config.aos.release.registry} ${config.aos.release.channel} channel. Updates may contain breaking changes,
        require reinstallation, or replace the experimental trust root. Keep
        important data and recovery material backed up elsewhere.

      '';
    };

    aos.image = {
      enable = true;
      allowTestArtifacts = false;
    };
  };
}
