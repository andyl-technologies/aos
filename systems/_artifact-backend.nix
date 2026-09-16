##! Concrete artifact backend selection for Linux image compositions.
{
  pkgs,
  ...
}: {
  environment.systemPackages = [pkgs.aos-oci-backend];

  aos.abilities.bindings."artifact-backend:oci" = {
    request = "aos-oci-backend:artifact-backend";
    implementation = "aos-oci-backend:artifact-backend";
    providerInstance = "aos-oci-backend:artifact-backend-provider";
    slot = "artifact-backend";
  };
}
