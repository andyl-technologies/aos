##! Exact system-manager selection shared by current system variants.
{pkgs, ...}: {
  environment.systemPackages = [pkgs.systemd];

  aos.abilities.bindings."system-manager:systemd" = {
    request = "system:manager";
    implementation = "systemd:system-manager";
    providerInstance = "systemd:system-manager-provider";
    slot = "system-manager";
  };
}
