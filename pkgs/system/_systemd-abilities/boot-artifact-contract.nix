##! Authenticated systemd boot-artifact contract construction.
{
  abilitySelection ? null,
  config,
  lib,
  pkgs,
  ...
}: let
  selected =
    config.aos.abilities.environment
    != null
    && abilitySelection != null
    && abilitySelection.isImplementationSelected "image-health-observation";
  healthExecutable = config.aos.apm.healthScript;
  contract = pkgs.mkDerivation {
    name = "aos-systemd-boot-artifact-contract";
    src = null;
    buildDeps = [pkgs.coreutils];
    phases = [
      {
        name = "build-contract";
        script = ''
          mkdir -p "$out/libexec"
          install -m 0555 ${healthExecutable} "$out/libexec/health"
          printf '%s\n' \
            "{\"health-executable\":\"$out/libexec/health\",\"schema\":\"aos.systemd.boot-artifact-contract/v1\"}" \
            > "$out/contract.json"
        '';
      }
    ];
  };
in {
  config = lib.mkIf (selected && healthExecutable != null) {
    aos.config._artifactSources.boot-artifact-contract = contract;
  };
}
