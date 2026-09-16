##! Concrete artifact backend selection for Linux image compositions.
{
  config,
  lib,
  pkgs,
  ...
}: {
  environment.systemPackages = [pkgs.aos-oci-backend];

  aos.abilities.bindings = lib.mkIf (
    config.aos.abilities.environment != null
    && config.aos.abilities.environment.stage == "host"
  ) {
    "artifact-backend:oci" = {
      request = "system:artifact-backend";
      implementation = "aos-oci-backend:artifact-backend";
      providerInstance = "aos-oci-backend:artifact-backend-provider";
      slot = "artifact-backend";
    };
  };
}
